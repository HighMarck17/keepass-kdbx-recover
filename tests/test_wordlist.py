"""Tests for the external wordlist source."""

from keepass_kdbx_recover.wordlist import gen_from_wordlist


def test_reads_lines_and_strips_newlines(tmp_path):
    p = tmp_path / "words.txt"
    p.write_bytes(b"alpha\r\nbeta\ngamma")
    assert list(gen_from_wordlist(p)) == ["alpha", "beta", "gamma"]


def test_ignores_undecodable_bytes(tmp_path):
    p = tmp_path / "words.txt"
    p.write_bytes(b"good\n\xff\xfe\ntail")
    # Bad bytes are skipped (errors ignored), lines still stream.
    result = list(gen_from_wordlist(p))
    assert result[0] == "good"
    assert result[-1] == "tail"


def test_does_not_deduplicate(tmp_path):
    # Wordlists can be huge; the source streams every line, dedup is not its job.
    p = tmp_path / "words.txt"
    p.write_text("dup\ndup\n", encoding="utf-8")
    assert list(gen_from_wordlist(p)) == ["dup", "dup"]
