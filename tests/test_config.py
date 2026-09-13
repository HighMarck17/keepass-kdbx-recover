"""Tests for configuration loading, validation, and saving."""

from keepass_kdbx_recover.config import (
    Config,
    check_paths,
    default,
    load,
    save,
    validate,
)

VALID_TOML = """
[database]
path = "db.kdbx"
keyfile = ""

[recovery]
workers = 4
progress_interval = 1.5

[mask]
enabled = false
pattern = "Summer?d?d"

[fragments]
enabled = true
pieces = ["a", "b"]
permutations = true
case_variants = false
fixed_prefix = "a"
min_fragments = 2

[wordlist]
enabled = false
path = ""

[export]
enabled = false
path = "out.txt"
"""


def write(tmp_path, text, name="config.toml"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_default_has_a_mode_enabled():
    cfg = default()
    assert isinstance(cfg, Config)
    assert cfg.fragments.enabled is True
    assert validate(cfg) == []


def test_default_min_fragments_is_one_so_single_pieces_are_tried():
    # A recovery tool must, by default, also try each single remembered piece.
    assert default().fragments.min_fragments == 1


def test_load_reads_all_sections(tmp_path):
    cfg = load(write(tmp_path, VALID_TOML))
    assert cfg.database.path == "db.kdbx"
    assert cfg.recovery.workers == 4
    assert cfg.recovery.progress_interval == 1.5
    assert cfg.fragments.pieces == ["a", "b"]
    assert cfg.fragments.min_fragments == 2
    assert cfg.export.path == "out.txt"


def test_load_tolerates_missing_sections(tmp_path):
    cfg = load(write(tmp_path, "[database]\npath = 'x.kdbx'\n"))
    assert cfg.database.path == "x.kdbx"
    # Missing sections fall back to defaults.
    assert cfg.fragments.enabled is default().fragments.enabled


def test_validate_requires_at_least_one_mode(tmp_path):
    cfg = default()
    cfg.fragments.enabled = False
    errors = validate(cfg)
    assert any("mode" in e.lower() for e in errors)


def test_validate_rejects_empty_fragments(tmp_path):
    cfg = default()
    cfg.fragments.pieces = []
    assert any("fragment" in e.lower() for e in validate(cfg))


def test_validate_rejects_empty_mask_pattern():
    cfg = default()
    cfg.mask.enabled = True
    cfg.mask.pattern = ""
    assert any("mask" in e.lower() for e in validate(cfg))


def test_validate_rejects_bad_numbers():
    cfg = default()
    cfg.recovery.workers = -1
    cfg.recovery.progress_interval = 0
    cfg.fragments.min_fragments = 0
    errors = validate(cfg)
    assert len(errors) >= 3


def test_validate_rejects_non_string_pieces():
    cfg = default()
    cfg.fragments.pieces = ["a", 1]  # type: ignore[list-item]
    assert any("piece" in e.lower() for e in validate(cfg))


def test_save_then_load_round_trips(tmp_path):
    cfg = load(write(tmp_path, VALID_TOML))
    out = tmp_path / "written.toml"
    save(cfg, out)
    reloaded = load(out)
    assert reloaded == cfg


def test_saved_file_contains_guidance_comments(tmp_path):
    out = tmp_path / "written.toml"
    save(default(), out)
    text = out.read_text(encoding="utf-8")
    assert "?l" in text  # mask placeholder guidance is present
    assert "#" in text


def test_check_paths_flags_missing_database(tmp_path):
    cfg = default()
    cfg.database.path = str(tmp_path / "nope.kdbx")
    assert any("database" in e.lower() for e in check_paths(cfg))


def test_check_paths_skips_database_when_export_only(tmp_path):
    cfg = default()
    cfg.database.path = str(tmp_path / "nope.kdbx")
    cfg.export.enabled = True
    assert check_paths(cfg) == []


def test_check_paths_flags_missing_wordlist(tmp_path):
    cfg = default()
    cfg.database.path = str(write(tmp_path, "x", "db.kdbx"))
    cfg.wordlist.enabled = True
    cfg.wordlist.path = str(tmp_path / "missing.txt")
    assert any("wordlist" in e.lower() for e in check_paths(cfg))


def test_check_paths_flags_missing_keyfile(tmp_path):
    cfg = default()
    cfg.database.path = str(write(tmp_path, "x", "db.kdbx"))
    cfg.database.keyfile = str(tmp_path / "missing.key")
    assert any("keyfile" in e.lower() for e in check_paths(cfg))


# --- type guards: wrong-typed TOML must yield clean errors, never crash ---


def test_validate_rejects_non_integer_workers():
    cfg = default()
    cfg.recovery.workers = "auto"  # type: ignore[assignment]
    assert any("workers" in e.lower() for e in validate(cfg))


def test_validate_rejects_non_numeric_progress_interval():
    cfg = default()
    cfg.recovery.progress_interval = "fast"  # type: ignore[assignment]
    assert any("progress_interval" in e.lower() for e in validate(cfg))


def test_validate_rejects_non_integer_min_fragments():
    cfg = default()
    cfg.fragments.min_fragments = "3"  # type: ignore[assignment]
    assert any("min_fragments" in e.lower() for e in validate(cfg))


def test_validate_rejects_non_string_mask_pattern():
    cfg = default()
    cfg.mask.enabled = True
    cfg.mask.pattern = 123  # type: ignore[assignment]
    assert any("pattern" in e.lower() for e in validate(cfg))


def test_validate_rejects_pieces_that_are_not_a_list():
    cfg = default()
    cfg.fragments.pieces = "abc"  # type: ignore[assignment]  # a bare string, not a list
    assert any("list" in e.lower() or "piece" in e.lower() for e in validate(cfg))


def test_save_preserves_user_comments_and_unknown_keys(tmp_path):
    p = tmp_path / "config.toml"
    save(default(), p)
    text = p.read_text(encoding="utf-8")
    text = text.replace("[database]", "# MY CUSTOM NOTE\n[database]")
    text += "\n[custom]\nmy_key = 42\n"
    p.write_text(text, encoding="utf-8")

    cfg = load(p)
    cfg.database.path = "changed.kdbx"
    save(cfg, p)

    out = p.read_text(encoding="utf-8")
    assert "# MY CUSTOM NOTE" in out
    assert "my_key" in out
    assert 'path = "changed.kdbx"' in out
