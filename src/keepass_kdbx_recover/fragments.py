"""Fragment candidate generator.

Use this when you remember PIECES of the password but not the exact order:
it recombines the pieces into candidates. Options:
    permute        try all orderings (else keep the original order)
    case_var       also try lower / UPPER / Capitalized variants of each piece
    min_len        use subsets from this many pieces up to all of them
    fixed_prefix   a piece that is always placed first (e.g. a base word)
"""

import itertools
from collections.abc import Iterator


def case_variants(word: str) -> list[str]:
    """Return the unique case variants of a word (self, lower, upper, capitalized).

    First-seen order is preserved so candidate streams stay deterministic across
    processes (a plain set would order by hash and vary between runs).
    """
    variants: list[str] = []
    for variant in (word, word.lower(), word.upper(), word.capitalize()):
        if variant not in variants:
            variants.append(variant)
    return variants


def gen_from_fragments(
    fragments: list[str],
    permute: bool,
    case_var: bool,
    min_len: int,
    fixed_prefix: str | None = None,
) -> Iterator[str]:
    """Yield candidates built from the remembered fragments.

    Each yielded value concatenates a chosen subset of the pieces. Subsets range
    from ``min_len`` pieces up to all of them. When ``permute`` is true every
    ordering of a subset is tried; otherwise the original order is kept. When
    ``case_var`` is true each piece additionally expands to its case variants.
    """
    frag_pool = [case_variants(f) if case_var else [f] for f in fragments]
    n = len(fragments)
    min_len = max(1, min(min_len, n))

    fixed_index: int | None = None
    if fixed_prefix is not None:
        try:
            fixed_index = fragments.index(fixed_prefix)
        except ValueError:
            fixed_index = None

    if fixed_index is not None:
        remaining = [i for i in range(n) if i != fixed_index]
        for total_len in range(min_len, n + 1):
            if total_len == 1:
                yield from frag_pool[fixed_index]
                continue
            pick = total_len - 1
            orders = (
                itertools.permutations(remaining, pick)
                if permute
                else itertools.combinations(remaining, pick)
            )
            for order in orders:
                full_order = (fixed_index, *order)
                for combo in itertools.product(*(frag_pool[i] for i in full_order)):
                    yield "".join(combo)
        return

    for r in range(min_len, n + 1):
        orders = (
            itertools.permutations(range(n), r)
            if permute
            else itertools.combinations(range(n), r)
        )
        for order in orders:
            for combo in itertools.product(*(frag_pool[i] for i in order)):
                yield "".join(combo)


def count_fragments(
    fragments: list[str],
    permute: bool,
    case_var: bool,
    min_len: int,
    fixed_prefix: str | None = None,
) -> int:
    """Number of UNIQUE candidates (after dedup), so progress percentages stay
    accurate even when the fragment list contains repeated pieces."""
    return len(set(gen_from_fragments(fragments, permute, case_var, min_len, fixed_prefix)))
