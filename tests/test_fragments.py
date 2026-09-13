"""Tests for the fragment (remembered pieces) candidate generator."""

from keepass_kdbx_recover.fragments import case_variants, count_fragments, gen_from_fragments


def gen(*args, **kwargs):
    return list(gen_from_fragments(*args, **kwargs))


def test_case_variants_are_unique():
    assert set(case_variants("ab")) == {"ab", "AB", "Ab"}
    assert set(case_variants("Ab")) == {"Ab", "ab", "AB"}
    # A pure-digit fragment has no case: only itself.
    assert set(case_variants("12")) == {"12"}


def test_case_variants_have_deterministic_first_seen_order():
    # Deterministic order (not set-hash order) keeps candidate streams reproducible.
    assert case_variants("ab") == ["ab", "AB", "Ab"]
    assert case_variants("12") == ["12"]


def test_permutations_vs_combinations_full_length():
    assert set(gen(["a", "b"], True, False, 2)) == {"ab", "ba"}
    assert set(gen(["a", "b"], False, False, 2)) == {"ab"}


def test_subsets_from_min_len_to_all_combinations():
    result = set(gen(["a", "b", "c"], False, False, 1))
    assert result == {"a", "b", "c", "ab", "ac", "bc", "abc"}


def test_subsets_from_min_len_to_all_permutations():
    result = set(gen(["a", "b", "c"], True, False, 2))
    # length-2 orderings + all length-3 orderings
    assert result == {"ab", "ba", "ac", "ca", "bc", "cb",
                      "abc", "acb", "bac", "bca", "cab", "cba"}


def test_min_len_is_clamped_into_range():
    # min_len larger than the number of pieces clamps to using all pieces.
    assert set(gen(["a", "b"], True, False, 5)) == {"ab", "ba"}
    # min_len below 1 clamps to 1.
    assert "a" in set(gen(["a", "b"], True, False, 0))


def test_fixed_prefix_is_always_first():
    result = set(gen(["x", "a", "b"], True, False, 1, fixed_prefix="x"))
    assert result == {"x", "xa", "xb", "xab", "xba"}
    assert all(c.startswith("x") for c in result)


def test_fixed_prefix_combinations_keep_original_order():
    result = set(gen(["x", "a", "b"], False, False, 1, fixed_prefix="x"))
    assert result == {"x", "xa", "xb", "xab"}


def test_fixed_prefix_not_in_fragments_is_ignored():
    result = set(gen(["a", "b"], True, False, 2, fixed_prefix="zzz"))
    assert result == {"ab", "ba"}


def test_case_variants_expand_each_piece():
    result = set(gen(["ab"], False, True, 1))
    assert result == {"ab", "AB", "Ab"}


def test_count_fragments_counts_unique_candidates():
    # Duplicate pieces collapse to a single unique candidate.
    assert count_fragments(["1", "1"], True, False, 2) == 1
    assert count_fragments(["a", "b", "c"], False, False, 1) == 7
