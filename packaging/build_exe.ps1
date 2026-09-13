# Build the standalone Windows executable for the keepass-kdbx-recover GUI.
#
# Usage (from the repository root, in an activated venv or with the venv python):
#     ./packaging/build_exe.ps1
#
# Output: dist/keepass-kdbx-recover-gui/keepass-kdbx-recover-gui.exe (a one-directory bundle).

$ErrorActionPreference = "Stop"

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m PyInstaller packaging/keepass_kdbx_recover.spec --noconfirm --clean

Write-Host ""
Write-Host "Build complete: dist/keepass-kdbx-recover-gui/keepass-kdbx-recover-gui.exe"
Write-Host "Zip the dist/keepass-kdbx-recover-gui/ folder to distribute it."
