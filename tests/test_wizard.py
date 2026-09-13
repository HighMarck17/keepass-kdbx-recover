"""Tests for the guided helper (wizard)."""

from keepass_kdbx_recover.config import Config, validate
from keepass_kdbx_recover.wizard import config_from_answers, run_wizard, suggest_command


def test_config_from_answers_builds_fragment_config():
    cfg = config_from_answers({
        "db": "my.kdbx",
        "keyfile": "",
        "mode": "fragments",
        "pieces": ["sun", "flower", "42"],
        "permutations": True,
        "case_variants": True,
        "fixed_prefix": "sun",
        "min_fragments": 2,
    })
    assert isinstance(cfg, Config)
    assert cfg.database.path == "my.kdbx"
    assert cfg.fragments.enabled is True
    assert cfg.mask.enabled is False
    assert cfg.fragments.pieces == ["sun", "flower", "42"]
    assert cfg.fragments.fixed_prefix == "sun"


def test_config_from_answers_builds_mask_config():
    cfg = config_from_answers({
        "db": "my.kdbx",
        "mode": "mask",
        "pattern": "Summer?d?d",
    })
    assert cfg.mask.enabled is True
    assert cfg.fragments.enabled is False
    assert cfg.mask.pattern == "Summer?d?d"


def test_suggest_command_points_at_config():
    assert suggest_command("myconf.toml") == "keepass-kdbx-recover run --config myconf.toml"


def test_run_wizard_writes_valid_config(tmp_path):
    answers = iter([
        str(tmp_path / "db.kdbx"),  # database path
        "",                          # keyfile (none)
        "1",                         # mode: fragments
        "sun,flower,42",             # pieces
        "y",                         # permutations
        "n",                         # case variants
        "sun",                       # fixed prefix
        "2",                         # min fragments
    ])
    out_lines = []
    cfg_path = tmp_path / "config.toml"
    run_wizard(str(cfg_path), in_=lambda _prompt: next(answers), out=out_lines.append)
    assert cfg_path.is_file()
    from keepass_kdbx_recover.config import load
    cfg = load(cfg_path)
    assert cfg.fragments.pieces == ["sun", "flower", "42"]
    assert validate(cfg) == []
    # The wizard tells the user the exact command to run.
    assert any("keepass-kdbx-recover run" in line for line in out_lines)


def test_run_wizard_does_not_offer_to_run_an_invalid_config(tmp_path):
    answers = iter([
        str(tmp_path / "db.kdbx"),  # database path
        "",                          # keyfile
        "2",                         # mode: mask
        "",                          # empty pattern -> invalid config
    ])
    out_lines = []
    run_wizard(str(tmp_path / "config.toml"), in_=lambda _p: next(answers),
               out=out_lines.append)
    text = "\n".join(out_lines).lower()
    # It must warn instead of presenting the config as ready to run.
    assert "empty" in text or "problem" in text or "incomplete" in text
    assert not any("keepass-kdbx-recover run" in line for line in out_lines)


def test_run_wizard_handles_non_numeric_min_fragments(tmp_path):
    answers = iter([
        str(tmp_path / "db.kdbx"), "", "1",  # fragments mode
        "a,b,c",                              # pieces
        "y", "n", "",                         # permutations, case variants, fixed prefix
        "not-a-number",                       # min fragments (must not crash)
    ])
    cfg = run_wizard(str(tmp_path / "config.toml"), in_=lambda _p: next(answers),
                     out=lambda _line: None)
    assert cfg.fragments.min_fragments >= 1
