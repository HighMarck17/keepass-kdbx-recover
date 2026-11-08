"""Hashcat-style mask candidate generator.

A mask is a string mixing literal characters with placeholders (see charsets).
Every placeholder expands to its character class; literals are kept verbatim,
and "??" stands for a literal question mark.
Example: "Summer?d?d" expands to Summer00 .. Summer99 (100 candidates).
"""

import itertools
from collections.abc import Iterator

from .charsets import CHARSETS


def parse_pattern(pattern: str) -> list[list[str]]:
    """Split a mask into a list of position choices.

    Each element is the list of characters allowed at that position: a single
    literal character, or the full character class of a placeholder.
    """
    tokens: list[list[str]] = []
    i = 0
    while i < len(pattern):
        pair = pattern[i : i + 2]
        if pair in CHARSETS:
            tokens.append(list(CHARSETS[pair]))
            i += 2
        elif pair == "??":
            tokens.append(["?"])
            i += 2
        else:
            tokens.append([pattern[i]])
            i += 1
    return tokens


def find_unknown_placeholders(pattern: str) -> list[str]:
    """Return the "?x" sequences that are neither a known class nor "??".

    A "?" at the very end is returned on its own. parse_pattern keeps these as
    literals; config validation uses this to report them as likely typos.
    """
    unknown: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern[i] == "?":
            pair = pattern[i : i + 2]
            if pair not in CHARSETS and pair != "??":
                unknown.append(pair)
            i += 2
        else:
            i += 1
    return unknown


def count_mask(pattern: str) -> int:
    """Number of candidates the mask expands to (product of position sizes)."""
    total = 1
    for token in parse_pattern(pattern):
        total *= len(token)
    return total


def gen_from_mask(pattern: str) -> Iterator[str]:
    """Yield every candidate of the mask, in odometer order. Constant memory."""
    for combo in itertools.product(*parse_pattern(pattern)):
        yield "".join(combo)
