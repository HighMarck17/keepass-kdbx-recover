"""Tests for the hashcat-style mask candidate generator."""

import string

from keepass_kdbx_recover.mask import (
    count_mask,
    find_unknown_placeholders,
    gen_from_mask,
    parse_pattern,
)


def test_parse_pattern_splits_placeholders_and_literals():
    tokens = parse_pattern("a?d")
    assert tokens == [["a"], list(string.digits)]


def test_parse_pattern_keeps_unknown_placeholder_as_literals():
    # "?z" is not a known class: "?" and "z" are two separate literals.
    tokens = parse_pattern("?z")
    assert tokens == [["?"], ["z"]]


def test_parse_pattern_all_classes():
    assert parse_pattern("?l") == [list(string.ascii_lowercase)]
    assert parse_pattern("?u") == [list(string.ascii_uppercase)]
    assert parse_pattern("?d") == [list(string.digits)]
    assert parse_pattern("?s") == [list("!@#$%^&*_-")]
    assert parse_pattern("?a") == [list(string.ascii_letters + string.digits + "!@#$%^&*_-")]


def test_count_mask_is_product_of_token_sizes():
    assert count_mask("?d") == 10
    assert count_mask("?l?d") == 26 * 10
    assert count_mask("Summer?d?d") == 100


def test_gen_from_mask_enumerates_full_product_with_literals():
    assert list(gen_from_mask("a?d")) == [f"a{d}" for d in string.digits]


def test_gen_from_mask_count_matches_count_mask():
    pattern = "?l?d"
    generated = list(gen_from_mask(pattern))
    assert len(generated) == count_mask(pattern)
    assert len(set(generated)) == len(generated)  # products are unique


def test_double_question_mark_is_a_literal_question_mark():
    assert parse_pattern("??d") == [["?"], ["d"]]
    assert list(gen_from_mask("a???d")) == [f"a?{d}" for d in string.digits]


def test_find_unknown_placeholders():
    assert find_unknown_placeholders("Summer?d?d") == []
    assert find_unknown_placeholders("a??b") == []
    assert find_unknown_placeholders("?z?d") == ["?z"]
    assert find_unknown_placeholders("end?") == ["?"]
