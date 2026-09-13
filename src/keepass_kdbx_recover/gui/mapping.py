"""Pure mapping between the GUI form values and a Config (no Tk import).

Keeping this Tk-free means it can be imported and unit-tested on a headless
machine, and the form dict is a plain snapshot of the Tk variables.
"""

from ..config import Config, default


def _as_int(value: object, fallback: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return fallback


def _as_float(value: object, fallback: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return fallback


def _split_pieces(text: str) -> list[str]:
    return [piece.strip() for piece in text.split(",") if piece.strip()]


def form_to_config(values: dict) -> Config:
    """Build a Config from the GUI form snapshot (defensive coercion)."""
    cfg = default()
    cfg.database.path = values.get("db_path", "")
    cfg.database.keyfile = values.get("keyfile", "")

    cfg.recovery.workers = _as_int(values.get("workers", 0), 0)
    cfg.recovery.progress_interval = _as_float(values.get("progress_interval", 2.0), 2.0)

    cfg.mask.enabled = bool(values.get("mask_enabled", False))
    cfg.mask.pattern = values.get("mask_pattern", "")

    cfg.fragments.enabled = bool(values.get("fragments_enabled", False))
    cfg.fragments.pieces = _split_pieces(values.get("fragments_pieces", ""))
    cfg.fragments.permutations = bool(values.get("fragments_permutations", True))
    cfg.fragments.case_variants = bool(values.get("fragments_case_variants", False))
    cfg.fragments.fixed_prefix = values.get("fragments_fixed_prefix", "")
    cfg.fragments.min_fragments = _as_int(values.get("fragments_min_fragments", 1), 1)

    cfg.wordlist.enabled = bool(values.get("wordlist_enabled", False))
    cfg.wordlist.path = values.get("wordlist_path", "")

    cfg.export.enabled = bool(values.get("export_enabled", False))
    cfg.export.path = values.get("export_path", "candidates.txt")
    return cfg


def config_to_form(cfg: Config) -> dict:
    """Produce the full GUI form snapshot from a Config."""
    return {
        "db_path": cfg.database.path,
        "keyfile": cfg.database.keyfile,
        "workers": cfg.recovery.workers,
        "progress_interval": cfg.recovery.progress_interval,
        "mask_enabled": cfg.mask.enabled,
        "mask_pattern": cfg.mask.pattern,
        "fragments_enabled": cfg.fragments.enabled,
        "fragments_pieces": ", ".join(cfg.fragments.pieces),
        "fragments_permutations": cfg.fragments.permutations,
        "fragments_case_variants": cfg.fragments.case_variants,
        "fragments_fixed_prefix": cfg.fragments.fixed_prefix,
        "fragments_min_fragments": cfg.fragments.min_fragments,
        "wordlist_enabled": cfg.wordlist.enabled,
        "wordlist_path": cfg.wordlist.path,
        "export_enabled": cfg.export.enabled,
        "export_path": cfg.export.path,
    }
