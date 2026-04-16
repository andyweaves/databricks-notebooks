"""
Amiga Bricks - Databricks App

Serves an EmulatorJS-based Amiga emulator (PUAE core) via FastAPI.
Place your Kickstart ROM in static/roms/ and ADF game files in static/games/.

Multi-disk games are auto-detected by naming convention:
    Game Name_Disk 1.adf, Game Name_Disk 2.adf  (numeric)
    Game Name_Disk1.adf, Game Name_d1.adf
    Game Name (Disk 1).adf, Game Name (Disk 2).adf
    Game Name A.adf, Game Name B.adf             (alpha A-F)
    Game Name_Disk A.adf, Game Name (Disk B).adf  (alpha A-Z with prefix)
    Game Name savedisk.adf                        (save disk, excluded from M3U)

Environment variables:
    EMULATORJS_SOURCE  "local" (default) to serve vendored v4.2.3 assets,
                       or "cdn" to load from https://cdn.emulatorjs.org.
    UVICORN_HOST       Listen address. Defaults to 127.0.0.1 (localhost).
                       Set to 0.0.0.0 for Databricks Apps (done in app.yaml).
    PORT               Listen port. Defaults to 8000.
"""

import io
import os
import re
import zipfile
from pathlib import Path
from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI(title="Amiga Bricks")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to every response.

    - COOP/COEP enable SharedArrayBuffer so EmulatorJS can use the
      threaded WASM core instead of the legacy fallback.
    - CSP (local mode only) restricts script sources to 'self' while
      allowing connect-src to the CDN for the harmless version check
      that EmulatorJS runs on localhost.
    """

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        if EMULATORJS_SOURCE == "local":
            response.headers["Content-Security-Policy"] = "; ".join([
                "default-src 'self' 'unsafe-inline' 'unsafe-eval' blob: data:",
                "connect-src 'self' blob: data: https://cdn.emulatorjs.org",
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:",
                "style-src 'self' 'unsafe-inline'",
                "img-src 'self' blob: data:",
                "media-src 'self' blob:",
                "worker-src 'self' blob:",
            ])
        return response


app.add_middleware(SecurityHeadersMiddleware)

STATIC_DIR = Path(__file__).parent / "static"
ROMS_DIR = STATIC_DIR / "roms"
GAMES_DIR = STATIC_DIR / "games"

EMULATORJS_SOURCE = os.environ.get("EMULATORJS_SOURCE", "local").lower()
EMULATORJS_CDN_URL = "https://cdn.emulatorjs.org/stable/data/"
EMULATORJS_LOCAL_PATH = "/static/emulatorjs/"

GAME_EXTENSIONS = {".adf", ".adz", ".dms", ".zip"}
ROM_EXTENSIONS = {".rom", ".bin"}

# Optional trailing scene/release tags like [cr QTX], [a], [!], [t+3]
_TRAILING_TAGS = r"(?:\[[^\]]*\])*"

# Matches disk number/letter patterns in filenames.
# Numeric:  "_Disk 1", "_Disk1", "_d1", " (Disk 1)", "(Disk 3 of 3)"
# Alpha:    "_Disk A", "(Disk B)", "_A", " A" (single uppercase A-F only)
# Trailing [tags] are allowed after the disk pattern.
_DISK_NUM_PATTERN = re.compile(
    r"(?:"
    r"[_ ]?\(Disk\s*(\d+)(?:\s*of\s*\d+)?\)"  # (Disk 1), (Disk1), (Disk 3 of 3)
    r"|[_ ]Disk\s*(\d+)"                       # _Disk 1, _Disk1
    r"|[_ ][dD](\d+)"                           # _d1, _D1
    r")" + _TRAILING_TAGS + r"$"
)
_DISK_ALPHA_PATTERN = re.compile(
    r"(?:"
    r"[_ ]?\(Disk\s*([A-Za-z])(?:\s*of\s*[A-Za-z])?\)"  # (Disk A), (Disk A of D)
    r"|[_ ]Disk\s*([A-Za-z])"                             # _Disk A, _Disk a
    r"|[_ ]([A-F])"                                        # _A,  A (uppercase A-F only)
    r")" + _TRAILING_TAGS + r"$"
)

# Matches save disk filenames: "Game savedisk", "Game save_disk", "Game Save Disk"
_SAVE_DISK_PATTERN = re.compile(
    r"[_ ]save[_ ]?disk" + _TRAILING_TAGS + r"$", re.IGNORECASE
)


def _is_valid_game(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in GAME_EXTENSIONS


def _is_valid_rom(path: Path) -> bool:
    return path.is_file() and (
        path.suffix.lower() in ROM_EXTENSIONS or "kick" in path.name.lower()
    )


SAVE_DISK_SENTINEL = -1


def _parse_disk_info(stem: str) -> tuple[str, int | None]:
    """Extract the base game name and disk number from a filename stem.

    Returns (base_name, disk_number) where disk_number is:
      - a positive int for numbered/lettered disks (A-D -> 1-4)
      - SAVE_DISK_SENTINEL (-1) for save disks
      - None for single-disk games
    """
    m = _SAVE_DISK_PATTERN.search(stem)
    if m:
        return stem[: m.start()].strip(), SAVE_DISK_SENTINEL

    m = _DISK_NUM_PATTERN.search(stem)
    if m:
        disk_num = int(next(g for g in m.groups() if g is not None))
        return stem[: m.start()].strip(), disk_num

    m = _DISK_ALPHA_PATTERN.search(stem)
    if m:
        letter = next(g for g in m.groups() if g is not None).upper()
        disk_num = ord(letter) - ord("A") + 1
        return stem[: m.start()].strip(), disk_num

    return stem, None


def _group_games() -> list[dict]:
    """Scan the games directory and return a list of game entries.

    Single-disk games:  {"name": "...", "filename": "...",
                         "disks": null, "has_save_disk": false}
    Multi-disk games:   {"name": "...", "slug": "...",
                         "disks": [{"filename": "...", "disk": 1}, ...],
                         "has_save_disk": true/false}

    Save disks (detected by name) are excluded from the disks list.
    A #SAVEDISK directive is added to the M3U instead.
    """
    if not GAMES_DIR.exists():
        return []

    # Gather all valid game files and parse disk info
    entries: list[tuple[str, int | None, Path]] = []
    for f in sorted(GAMES_DIR.iterdir()):
        if _is_valid_game(f):
            base, num = _parse_disk_info(f.stem)
            entries.append((base, num, f))

    # Group by base name
    groups: dict[str, list[tuple[int | None, Path]]] = {}
    for base, num, path in entries:
        groups.setdefault(base, []).append((num, path))

    games = []
    for base, disks in groups.items():
        # Separate save disks from regular disks
        regular = [(n, p) for n, p in disks if n != SAVE_DISK_SENTINEL]
        has_save_disk = len(regular) < len(disks)

        has_numbers = any(n is not None for n in (d[0] for d in regular))
        if has_numbers and len(regular) > 1:
            # Multi-disk game — sort by disk number
            sorted_disks = sorted(regular, key=lambda d: d[0] or 0)
            slug = re.sub(r"[^a-z0-9]+", "-", base.lower()).strip("-")
            games.append({
                "name": base,
                "slug": slug,
                "filename": None,
                "disks": [
                    {"filename": p.name, "disk": n}
                    for n, p in sorted_disks
                ],
                "has_save_disk": has_save_disk,
            })
        else:
            # Single-disk game(s) — each file is its own entry
            for _, path in regular:
                games.append({
                    "name": path.stem,
                    "filename": path.name,
                    "slug": None,
                    "disks": None,
                    "has_save_disk": has_save_disk,
                })

    return sorted(games, key=lambda g: g["name"].lower())


@app.get("/")
async def index():
    """Serve the emulator HTML page."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/api/config")
async def config():
    """Return runtime configuration for the frontend."""
    return {
        "emulatorjs_source": EMULATORJS_SOURCE,
        "emulatorjs_path": (
            EMULATORJS_CDN_URL if EMULATORJS_SOURCE == "cdn"
            else EMULATORJS_LOCAL_PATH
        ),
    }


@app.get("/api/games")
async def list_games():
    """List available game files, with multi-disk games grouped."""
    return {"games": _group_games()}


@app.head("/api/games/{slug}/bundle")
@app.get("/api/games/{slug}/bundle")
async def game_bundle(slug: str):
    """Generate a ZIP containing an M3U playlist and ADF files for a multi-disk game."""
    games = _group_games()
    game = next((g for g in games if g.get("slug") == slug), None)
    if game is None or game["disks"] is None:
        return JSONResponse({"error": "Game not found"}, status_code=404)

    m3u_name = f"{game['name']} (MD).m3u"
    m3u_lines = [d["filename"] for d in game["disks"]]
    if game.get("has_save_disk"):
        m3u_lines.append("#SAVEDISK:SaveDisk")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(m3u_name, "\n".join(m3u_lines) + "\n")
        for disk in game["disks"]:
            disk_path = GAMES_DIR / disk["filename"]
            zf.write(disk_path, disk["filename"])
    buf.seek(0)

    safe_name = re.sub(r"[^a-zA-Z0-9_ -]", "", game["name"])
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'inline; filename="{safe_name}.zip"'},
    )


@app.head("/api/games/{slug}/playlist.m3u")
@app.get("/api/games/{slug}/playlist.m3u")
async def game_playlist(slug: str):
    """Serve a plain M3U playlist that references ADFs at their static paths."""
    games = _group_games()
    game = next((g for g in games if g.get("slug") == slug), None)
    if game is None or game["disks"] is None:
        return JSONResponse({"error": "Game not found"}, status_code=404)

    m3u_lines = [f"/static/games/{d['filename']}" for d in game["disks"]]
    if game.get("has_save_disk"):
        m3u_lines.append("#SAVEDISK:SaveDisk")

    return Response(
        content="\n".join(m3u_lines) + "\n",
        media_type="audio/x-mpegurl",
        headers={"Content-Disposition": f'inline; filename="{game["name"]} (MD).m3u"'},
    )


@app.get("/api/roms")
async def list_roms():
    """List available Kickstart ROM files."""
    roms = []
    if ROMS_DIR.exists():
        for f in sorted(ROMS_DIR.iterdir()):
            if _is_valid_rom(f):
                roms.append({"name": f.stem, "filename": f.name})
    return {"roms": roms}


# Mount only the specific subdirectories needed, so READMEs and other
# non-asset files in static/ are not served.
app.mount("/static/roms", StaticFiles(directory=str(ROMS_DIR)), name="roms")
app.mount("/static/games", StaticFiles(directory=str(GAMES_DIR)), name="games")
# index.html and other top-level static assets (CSS/JS if added later)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("UVICORN_HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=port)
