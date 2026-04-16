# Amiga Game Files

Place your Amiga disk image files here.

## Supported formats

- `.adf` — Amiga Disk File (most common, recommended)
- `.adz` — Compressed ADF
- `.dms` — Disk Masher System
- `.zip` — ZIP archive containing any of the above

Note: `.ipf` files are **not supported** — they require the proprietary
`capsimg.so` library which cannot be compiled into the WASM core.

## Multi-disk games

Multi-disk games are auto-detected by filename and grouped in the UI.
Name your files using one of these conventions:

**Numeric:**

    Game Name_Disk 1.adf
    Game Name_Disk 2.adf
    Game Name (Disk 1).adf
    Game Name_d1.adf

**Alpha (A-F without prefix, A-Z with "Disk" prefix):**

    Game Name A.adf
    Game Name B.adf
    Game Name_Disk A.adf
    Game Name (Disk B).adf

The app generates an M3U playlist inside a ZIP bundle at runtime and passes
it to the PUAE core. Disk swapping is handled via the EmulatorJS menu during
gameplay.

## Save disks

Some games require a dedicated save disk. If you have one, name it:

    Game Name savedisk.adf
    Game Name save_disk.adf
    Game Name_SaveDisk.adf

Save disks are detected automatically and excluded from the regular disk
list. A `#SAVEDISK:SaveDisk` directive is added to the M3U playlist so
the PUAE core generates a writable save image in its save directory.

## Amiga Forever games

Games bundled with Amiga Forever are typically in RP9 format. RP9 files are
ZIP archives — rename `.rp9` to `.zip`, extract, and copy the `.adf` files
into this directory.

## Where to find ADF files

If you own the original game, you can create ADF images from physical disks
using tools like:

- **Greaseweazle** or **KryoFlux** (hardware disk readers)
- **TransADF** on a real Amiga with a network connection

Some games are also available as legal freeware or from rights holders.
