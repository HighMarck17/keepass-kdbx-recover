"""Tests for CLI parsing, override precedence, and subcommand routing."""

from keepass_kdbx_recover.candidates import build_candidates
from keepass_kdbx_recover.cli import (
    build_parser,
    load_config_with_overrides,
    main,
    normalize_argv,
)
from keepass_kdbx_recover.config import default, save


def parse(argv):
    return build_parser().parse_args(argv)


def test_normalize_argv_defaults_to_run():
    assert normalize_argv([]) == ["run"]
    assert normalize_argv(["--db", "x.kdbx"]) == ["run", "--db", "x.kdbx"]
    assert normalize_argv(["inspect", "x.kdbx"]) == ["inspect", "x.kdbx"]


def test_normalize_argv_preserves_help_and_version():
    assert normalize_argv(["-h"]) == ["-h"]
    assert normalize_argv(["--help"]) == ["--help"]
    assert normalize_argv(["--version"]) == ["--version"]


def test_export_with_missing_wordlist_is_a_clean_config_error(tmp_path):
    out = tmp_path / "o.txt"
    code = main(["export", "--wordlist", str(tmp_path / "missing.txt"), "--out", str(out)])
    assert code == 2  # clean config error, not a FileNotFoundError traceback


def test_parser_routes_subcommands():
    assert parse(["run"]).command == "run"
    assert parse(["inspect", "a.kdbx"]).command == "inspect"
    assert parse(["export", "--out", "o.txt"]).command == "export"
    assert parse(["wizard"]).command == "wizard"


def test_overrides_replace_config_values(tmp_path):
    cfgpath = tmp_path / "config.toml"
    save(default(), cfgpath)
    args = parse(["run", "--config", str(cfgpath), "--db", "over.kdbx", "--workers", "3"])
    cfg = load_config_with_overrides(args)
    assert cfg.database.path == "over.kdbx"
    assert cfg.recovery.workers == 3


def test_mask_flag_enables_only_mask(tmp_path):
    cfgpath = tmp_path / "config.toml"
    save(default(), cfgpath)  # default has fragments enabled
    args = parse(["run", "--config", str(cfgpath), "--mask", "Summer?d?d"])
    cfg = load_config_with_overrides(args)
    assert cfg.mask.enabled is True
    assert cfg.mask.pattern == "Summer?d?d"
    assert cfg.fragments.enabled is False


def test_fragments_flag_splits_pieces(tmp_path):
    args = parse(["run", "--fragments", "a,b,c"])
    cfg = load_config_with_overrides(args)
    assert cfg.fragments.enabled is True
    assert cfg.fragments.pieces == ["a", "b", "c"]
    assert cfg.mask.enabled is False


def test_fragments_flag_tries_each_single_fragment():
    # Regression: a password equal to one remembered fragment must be generated.
    args = parse(["run", "--fragments", "wrong,secret,other"])
    cfg = load_config_with_overrides(args)
    assert "secret" in set(build_candidates(cfg))


def test_min_fragments_flag_overrides():
    args = parse(["run", "--fragments", "a,b,c", "--min-fragments", "2"])
    cfg = load_config_with_overrides(args)
    assert cfg.fragments.min_fragments == 2


def test_permute_flag_can_be_disabled():
    args = parse(["run", "--fragments", "a,b", "--no-permute"])
    cfg = load_config_with_overrides(args)
    assert cfg.fragments.permutations is False


def test_case_variants_flag_enables():
    args = parse(["run", "--fragments", "a,b", "--case-variants"])
    cfg = load_config_with_overrides(args)
    assert cfg.fragments.case_variants is True


def test_run_reports_error_and_exit_code_when_no_database(tmp_path, capsys):
    # No config file -> defaults (fragments on, but no database path).
    code = main(["run", "--config", str(tmp_path / "missing.toml")])
    assert code == 2
    assert "database" in capsys.readouterr().out.lower()


def test_inspect_prints_kdf(kdbx_db, capsys):
    db_path, _ = kdbx_db
    code = main(["inspect", db_path])
    out = capsys.readouterr().out
    assert code == 0
    assert "Argon2" in out
    assert "4.0" in out


def test_export_writes_candidates_and_prints_advice(kdbx_db, tmp_path, capsys):
    db_path, _ = kdbx_db
    out = tmp_path / "cand.txt"
    code = main(["export", "--db", db_path, "--mask", "?d", "--out", str(out)])
    text = capsys.readouterr().out.lower()
    assert code == 0
    assert out.read_text(encoding="utf-8").splitlines() == [str(d) for d in range(10)]
    # Argon2 database -> the advice must warn that a GPU gives little advantage.
    assert "little" in text or "memory-hard" in text
