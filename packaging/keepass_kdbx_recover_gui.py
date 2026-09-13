"""Frozen-executable entry point for the keepass-kdbx-recover GUI.

PyInstaller bundles this script. ``freeze_support`` MUST run before anything else
so the multiprocessing worker processes spawned by the recovery engine work in the
frozen executable on Windows.
"""

import multiprocessing

from keepass_kdbx_recover.gui.app import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
