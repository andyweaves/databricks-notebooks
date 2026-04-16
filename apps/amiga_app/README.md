# Amiga Bricks — Databricks App

A web-based Commodore Amiga emulator that runs in the browser, powered by
[EmulatorJS](https://emulatorjs.org/) (PUAE core) and served via FastAPI as a
Databricks App. Supports single-disk and multi-disk games with automatic disk
grouping.

## Prerequisites

You need two things that are **not included** in this repository (they are
copyrighted):

1. **Kickstart ROM** — place any `.rom` or `.bin` file in `static/roms/`
   - The app auto-discovers ROMs; no specific filename required.
   - Kickstart 1.3 (256 KB) is recommended for most classic games.
   - Purchase legally from [Amiga Forever](https://www.amigaforever.com/)
     (the Plus Edition includes all ROMs as unencoded files).

2. **Game disk images** — place ADF files in `static/games/`
   - Supported formats: `.adf`, `.adz`, `.dms`, `.zip`
   - If multiple games are present a dropdown selector is shown.

## Quick start (local)

```bash
pip install -r requirements.txt
python app.py
```

Open <http://localhost:8000>. The app listens on `127.0.0.1` by default when
run locally.

## Multi-disk games

Multi-disk games are auto-detected by naming convention and grouped in the
UI. The app generates a ZIP bundle at runtime containing an M3U playlist
(with the `(MD)` multi-drive flag) and the ADF files. PUAE loads each disk
into a separate virtual floppy drive (DF0:–DF3:), so games that support
multi-drive work seamlessly without manual disk swapping.

### Supported naming patterns

| Pattern | Example |
|---|---|
| `_Disk N` / `_DiskN` | `Monkey Island_Disk 1.adf` |
| `(Disk N)` / `(Disk N of M)` | `Game (Disk 2 of 3).adf` |
| `_dN` / `_DN` | `Monkey Island_d1.adf` |
| `_Disk A` / `(Disk A)` | `Monkey Island_Disk A.adf` |
| Trailing letter A–F | `Monkey Island A.adf` |
| Scene tags after disk pattern | `Game (Disk 1)[cr FLT].adf` |

Scene/release tags in square brackets (`[cr FLT]`, `[!]`, `[a]`, etc.)
are allowed after the disk pattern and are stripped during grouping.

### Save disks

Files matching `savedisk`, `save_disk`, or `Save Disk` in the name are
detected as save disks. They are excluded from the disk list and a
`#SAVEDISK:SaveDisk` directive is added to the M3U so the PUAE core
auto-creates a writable save image.

### How multi-drive works (currently not functional)

The Amiga supported up to 4 floppy drives (DF0:–DF3:). The M3U filename
includes `(MD)` to signal multi-drive support to the PUAE core. In theory,
this loads each disk into a separate drive at startup so games can read
from multiple drives without prompting for a swap.

**However, multi-drive does not currently work in the EmulatorJS PUAE WASM
build** — the core registers the disks but does not apply the drive
configurations. The `(MD)` flag and M3U infrastructure are in place so
that if a future WASM core build fixes this, it will work automatically.
See [Limitations](#limitations) for details.

### ADF naming conventions (scene tags)

If downloading ADF files from preservation archives, look for the cleanest
version:

| Tag | Meaning | Recommended? |
|---|---|---|
| `[!]` | Verified good dump | Yes — best choice |
| `[cr FLT]` | Cracked by (group) — copy protection removed | Yes — needed for emulation |
| `[f ...]` | Fixed (bug fix applied) | Often helpful |
| `[t +N]` | Trained (cheats added) | No |
| `[h]` / `[h HD]` | Hacked / hard drive version | No |
| `[b]` / `[m baddump]` | Bad dump / corrupt | No |
| `(DE)`, `(IT)` | Language (German, Italian) | Only if wanted |

Use disks from the **same group/release** (e.g. all `[cr FLT]`) so they
are compatible with each other.

## Configuration

All settings are controlled via environment variables:

| Variable | Default | Description |
|---|---|---|
| `EMULATORJS_SOURCE` | `local` | `local` to serve vendored v4.2.3 assets from `static/emulatorjs/`, or `cdn` to load from `https://cdn.emulatorjs.org`. |
| `UVICORN_HOST` | `127.0.0.1` | Listen address. Use `0.0.0.0` to accept connections from all interfaces (set automatically by `app.yaml` for Databricks Apps). |
| `PORT` | `8000` | Listen port. |

### EmulatorJS source: local vs CDN

**Local (default, recommended)** — EmulatorJS v4.2.3 is vendored in
`static/emulatorjs/`. No external network requests are made at runtime
except for a harmless version-check to `cdn.emulatorjs.org`. A
Content-Security-Policy header restricts script sources to `'self'`.

```bash
# Explicit, but this is the default:
EMULATORJS_SOURCE=local python app.py
```

**CDN** — EmulatorJS is loaded from `https://cdn.emulatorjs.org/stable/data/`
at page load. Smaller deployment size but introduces a runtime dependency on a
third-party CDN. If the CDN is compromised, malicious JavaScript would execute
in the user's browser.

```bash
EMULATORJS_SOURCE=cdn python app.py
```

### Security headers

The app sets the following response headers via middleware:

- **`Cross-Origin-Opener-Policy: same-origin`** and
  **`Cross-Origin-Embedder-Policy: require-corp`** — enable
  `SharedArrayBuffer`, which lets EmulatorJS use the threaded WASM core
  instead of the legacy (non-threaded) fallback.
- **`Content-Security-Policy`** (local mode only) — restricts script
  sources to `'self'` while allowing `connect-src` to the CDN for the
  version check.

### Host binding

When run directly with `python app.py`, the server defaults to `127.0.0.1`
(localhost only). Override with `UVICORN_HOST`:

```bash
# Accept connections from all interfaces (e.g. for Docker or LAN access):
UVICORN_HOST=0.0.0.0 python app.py
```

When deployed as a Databricks App, `databricks.yml` sets
`UVICORN_HOST=0.0.0.0` automatically.

## Deploying to Databricks Apps

Deployment uses
[Databricks Asset Bundles (DABs)](https://docs.databricks.com/aws/en/dev-tools/bundles/),
which manages the app as infrastructure-as-code with environment targets,
permissions, and CI/CD integration.

The app configuration (command, environment variables) is defined in
`databricks.yml` — no separate `app.yaml` is needed.

```yaml
bundle:
  name: amiga_bricks

resources:
  apps:
    amiga_bricks:
      name: 'amiga-bricks'
      description: 'Amiga Bricks — Web-based Amiga emulator powered by EmulatorJS and PUAE'
      source_code_path: .
      config:
        command:
          - 'python'
          - 'app.py'
        env:
          - name: 'UVICORN_HOST'
            value: '0.0.0.0'
      permissions:
        - level: CAN_USE
          group_name: users

targets:
  dev:
    mode: development
    default: true
  prod:
    mode: production
```

To use the CDN instead of local EmulatorJS assets, add an environment
variable to the `config.env` section:

```yaml
        env:
          - name: 'UVICORN_HOST'
            value: '0.0.0.0'
          - name: 'EMULATORJS_SOURCE'
            value: 'cdn'
```

**Deploy with the Databricks CLI (v0.218.0+):**

```bash
# Validate the bundle configuration
databricks bundle validate --profile <your-profile>

# Deploy to the default (dev) target
databricks bundle deploy --profile <your-profile>

# Run the app
databricks bundle run amiga_bricks --profile <your-profile>

# Deploy to production
databricks bundle deploy -t prod --profile <your-profile>
databricks bundle run amiga_bricks -t prod --profile <your-profile>
```

**Note:** ROM and game files in `static/roms/` and `static/games/` are
uploaded as part of the bundle. Ensure you have the files in place before
deploying. These files are gitignored so they won't be committed to version
control.

**Customising targets** — add `workspace.host` to each target to deploy to
specific workspaces, or add `run_as` / `permissions` blocks for production
access control. See the
[DABs documentation](https://docs.databricks.com/aws/en/dev-tools/bundles/)
for the full reference.

## API endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Serve the emulator HTML page |
| `GET /api/health` | Health check |
| `GET /api/config` | Runtime configuration (EmulatorJS source/path) |
| `GET /api/roms` | List discovered ROM files |
| `GET /api/games` | List games with multi-disk grouping |
| `GET /api/games/{slug}/bundle` | Generate ZIP + M3U for a multi-disk game |

## Project structure

```
amiga_app/
├── app.py                  # FastAPI backend + security middleware
├── databricks.yml          # DABs bundle configuration (includes app config)
├── requirements.txt        # Python dependencies
├── static/
│   ├── index.html          # Emulator frontend (single page)
│   ├── favicon.svg         # Rainbow checkmark tab icon
│   ├── emulatorjs/         # Vendored EmulatorJS v4.2.3 (patched)
│   │   ├── loader.js
│   │   ├── emulator.min.js
│   │   ├── emulator.min.css
│   │   ├── version.json
│   │   ├── compression/    # Decompression utilities
│   │   │   ├── extract7z.js
│   │   │   ├── extractzip.js
│   │   │   ├── libunrar.js
│   │   │   └── libunrar.wasm
│   │   ├── localization/   # Browser locale translations
│   │   │   └── en-GB.json
│   │   └── cores/
│   │       ├── puae-wasm.data
│   │       └── reports/puae.json
│   ├── roms/               # Kickstart ROM files (git-ignored)
│   └── games/              # ADF game images (git-ignored)
└── .gitignore
```

## Limitations

- **Multi-disk games do not support disk swapping.** The PUAE WASM core
  binary (EmulatorJS v4.2.3) has a bug where the `set_current_disk`
  function crashes with `RuntimeError: unreachable` when the core's disk
  control callbacks are invoked. This means games that require swapping
  floppy disks during gameplay cannot progress past the swap point.
  This is a [known issue](https://github.com/rommapp/romm/issues/2696)
  affecting all EmulatorJS deployments using the PUAE core. Fixing it
  would require rebuilding the PUAE WASM core from the
  [EmulatorJS/libretro-uae](https://github.com/EmulatorJS/libretro-uae)
  source. The EmulatorJS disk selection menu is present but displays a
  warning message when used.

- **Multi-drive (loading disks into DF0:–DF3: simultaneously) does not
  work in this WASM build.** Although the M3U playlist includes the
  `(MD)` multi-drive flag and the core registers all disks, the PUAE
  WASM core does not apply the additional drive configurations. Only
  DF0: is loaded. Games that load all their data from Disk A will work
  fine; games that need data from other disks will not.

- **Single-disk games work without issues.** Games that fit on a single
  ADF file work perfectly.

- **IPF files are not supported.** They require the proprietary
  `capsimg.so` library which cannot be compiled into the WASM core.

- **Maximum 4 disks per game** in the multi-drive configuration (the
  Amiga had 4 floppy drives). Not currently relevant since multi-drive
  does not work in this WASM build.

## EmulatorJS patches

The vendored `emulator.min.js` includes patches for bugs in v4.2.3 that
affect multi-disk games:

1. **`allSettings` guard** — `setupDisksMenu()` runs before
   `setupSettingsMenu()` initializes `this.allSettings`, so
   `menuOptionChanged("disk", ...)` crashed with
   `Cannot set properties of undefined`. Fixed by adding
   `this.allSettings=this.allSettings||{}`.

2. **`setCurrentDisk` guard** — `setupDisksMenu()` called
   `handleSpecialOptions` which invoked `setCurrentDisk()` on the WASM
   core before its disk subsystem was ready, causing
   `RuntimeError: unreachable`. Fixed by gating the call with
   `if(this.started)`.

3. **Disk swap no-op** — `handleSpecialOptions` for `"disk"` is replaced
   with a console warning. The PUAE WASM core's disk control callbacks
   crash when invoked via `set_current_disk`, even though the RetroArch
   wrapper (`retroarch.c:6296`) correctly handles eject/insert. The crash
   is in the PUAE core binary itself and cannot be fixed from JavaScript.

4. **Disk function logging** — `getDiskCount`, `getCurrentDisk`, and
   `setCurrentDisk` are wrapped to log `[DISK]` messages to the console
   for debugging.

## Security considerations

- **Local mode** is the default because it eliminates supply-chain risk from
  the EmulatorJS CDN. The vendored assets are pinned to a known version
  (v4.2.3) and a Content-Security-Policy blocks external script loading.
- **CDN mode** loads JavaScript from a third party at runtime. If the CDN is
  compromised, the injected code runs in the browser with full access to the
  page origin (cookies, localStorage, API endpoints). Only use this in
  trusted environments or when the deployment size matters.
- ROM and game files are copyrighted and must not be committed to version
  control. The `.gitignore` excludes them.

## Updating EmulatorJS

To update the vendored EmulatorJS assets:

1. Download the new release files from the
   [EmulatorJS releases page](https://github.com/EmulatorJS/EmulatorJS/releases)
   or the CDN (`https://cdn.emulatorjs.org/stable/data/`).
2. Replace the contents of `static/emulatorjs/`, including `compression/`.
3. Re-apply the patches documented above (check if they are still needed in
   the new version).
4. Review the [changelog](https://emulatorjs.org/docs/changelog/) for
   breaking changes.
5. Test locally before deploying.
