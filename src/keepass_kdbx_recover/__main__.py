"""Entry point for `python -m keepass_kdbx_recover`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
