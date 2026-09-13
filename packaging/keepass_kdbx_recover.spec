# PyInstaller spec for the keepass-kdbx-recover GUI (Windows standalone build).
#
# Build from the repository root:
#     pyinstaller packaging/keepass_kdbx_recover.spec --noconfirm --clean
#
# Produces dist/keepass-kdbx-recover-gui/ (a one-directory bundle - fewer antivirus false
# positives than --onefile, and it starts faster). To ship a single file instead,
# see the commented --onefile EXE variant below.
#
# Notes:
# - console=False makes it a windowed GUI (no console window).
# - collect_all pulls the data files, binaries, and hidden submodules of the
#   crypto/parsing dependencies that PyInstaller's static analysis misses.
# - freeze_support() lives in the entry script so multiprocessing works when frozen.

import os

from PyInstaller.utils.hooks import collect_all

# Resolve paths relative to THIS spec file, so the build works from any working
# directory (SPECPATH is injected by PyInstaller and is the spec's directory).
ENTRY = os.path.join(SPECPATH, "keepass_kdbx_recover_gui.py")
SRC = os.path.join(SPECPATH, "..", "src")

datas = []
binaries = []
hiddenimports = []

for package in ("pykeepass", "construct", "argon2", "argon2_cffi_bindings", "Cryptodome"):
    try:
        pkg_datas, pkg_binaries, pkg_hidden = collect_all(package)
    except Exception:
        continue
    datas += pkg_datas
    binaries += pkg_binaries
    hiddenimports += pkg_hidden

a = Analysis(
    [ENTRY],
    pathex=[SRC],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

# Named keepass-kdbx-recover-gui (not keepass-kdbx-recover) so the GUI executable is not confused
# with the keepass-kdbx-recover CLI command installed via pip.
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="keepass-kdbx-recover-gui",
    debug=False,
    strip=False,
    upx=False,
    console=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="keepass-kdbx-recover-gui",
)

# --onefile alternative (single keepass-kdbx-recover-gui.exe; slower start, more AV noise):
#   exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="keepass-kdbx-recover-gui",
#             debug=False, strip=False, upx=False, console=False, onefile=True)
