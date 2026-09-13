"""Tests for candidate composition, dedup policy, counting, and export."""

from keepass_kdbx_recover.candidates import build_candidates, count_total, export_candidates
from keepass_kdbx_recover.config import default


def cfg_mask_only(pattern="?d"):
    c = default()
    c.fragments.enabled = False
    c.mask.enabled = True
    c.mask.pattern = pattern
    return c


def cfg_fragments_only(pieces, permutations=True, min_fragments=None, fixed_prefix=""):
    c = default()
    c.fragments.enabled = True
    c.mask.enabled = False
    c.fragments.pieces = pieces
    c.fragments.permutations = permutations
    c.fragments.case_variants = False
    c.fragments.fixed_prefix = fixed_prefix
    c.fragments.min_fragments = min_fragments if min_fragments is not None else len(pieces)
    return c


def test_mask_only_yields_full_product():
    assert list(build_candidates(cfg_mask_only("?d"))) == [str(d) for d in range(10)]


def test_fragments_only_deduplicates():
    c = cfg_fragments_only(["1", "1"], permutations=True, min_fragments=2)
    assert list(build_candidates(c)) == ["11"]


def test_wordlist_only_keeps_duplicates(tmp_path):
    p = tmp_path / "w.txt"
    p.write_text("dup\ndup\nother\n", encoding="utf-8")
    c = default()
    c.fragments.enabled = False
    c.wordlist.enabled = True
    c.wordlist.path = str(p)
    assert list(build_candidates(c)) == ["dup", "dup", "other"]


def test_multiple_sources_are_ordered_mask_then_fragments():
    c = cfg_fragments_only(["x"], permutations=False, min_fragments=1)
    c.mask.enabled = True
    c.mask.pattern = "?d"
    result = list(build_candidates(c))
    assert result == [str(d) for d in range(10)] + ["x"]


def test_count_total_known_for_single_mode():
    assert count_total(cfg_mask_only("?d")) == 10
    assert count_total(cfg_fragments_only(["a", "b"], min_fragments=2)) == 2


def test_count_total_unknown_for_multiple_or_wordlist():
    c = cfg_fragments_only(["a", "b"], min_fragments=2)
    c.mask.enabled = True
    assert count_total(c) is None

    w = default()
    w.wordlist.enabled = True
    assert count_total(w) is None


def test_count_total_returns_none_for_huge_fragment_space():
    # A large permuted fragment space must not be materialized just to count it.
    c = cfg_fragments_only([str(i) for i in range(9)], permutations=True, min_fragments=1)
    assert count_total(c) is None


def test_export_writes_one_per_line_and_returns_count(tmp_path):
    out = tmp_path / "candidates.txt"
    count = export_candidates(cfg_mask_only("?d"), out)
    assert count == 10
    assert out.read_text(encoding="utf-8").splitlines() == [str(d) for d in range(10)]
