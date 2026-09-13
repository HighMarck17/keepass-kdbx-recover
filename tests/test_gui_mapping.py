"""Tests for the pure GUI form <-> Config mapping (headless, no Tk)."""

from keepass_kdbx_recover.config import default
from keepass_kdbx_recover.gui.mapping import config_to_form, form_to_config

CANONICAL = {
    "db_path": "my.kdbx",
    "keyfile": "",
    "workers": 4,
    "progress_interval": 1.5,
    "mask_enabled": False,
    "mask_pattern": "Summer?d",
    "fragments_enabled": True,
    "fragments_pieces": "a, b, c",
    "fragments_permutations": True,
    "fragments_case_variants": False,
    "fragments_fixed_prefix": "a",
    "fragments_min_fragments": 2,
    "wordlist_enabled": False,
    "wordlist_path": "",
    "export_enabled": False,
    "export_path": "candidates.txt",
}


def test_form_to_config_maps_all_fields():
    cfg = form_to_config(CANONICAL)
    assert cfg.database.path == "my.kdbx"
    assert cfg.recovery.workers == 4
    assert cfg.recovery.progress_interval == 1.5
    assert cfg.fragments.enabled is True
    assert cfg.fragments.pieces == ["a", "b", "c"]
    assert cfg.fragments.fixed_prefix == "a"
    assert cfg.fragments.min_fragments == 2


def test_pieces_string_splits_and_drops_empties():
    cfg = form_to_config({**CANONICAL, "fragments_pieces": "a, ,b,"})
    assert cfg.fragments.pieces == ["a", "b"]


def test_numeric_fields_coerce_with_fallback():
    cfg = form_to_config({
        **CANONICAL,
        "workers": "",
        "progress_interval": "",
        "fragments_min_fragments": "not-a-number",
    })
    assert cfg.recovery.workers == 0
    assert cfg.recovery.progress_interval == 2.0
    assert cfg.fragments.min_fragments == 1


def test_config_to_form_round_trips_from_canonical_values():
    assert config_to_form(form_to_config(CANONICAL)) == CANONICAL


def test_form_to_config_round_trips_from_default_config():
    assert form_to_config(config_to_form(default())) == default()


def test_config_to_form_joins_pieces_with_comma_space():
    cfg = default()
    cfg.fragments.pieces = ["one", "two"]
    assert config_to_form(cfg)["fragments_pieces"] == "one, two"
