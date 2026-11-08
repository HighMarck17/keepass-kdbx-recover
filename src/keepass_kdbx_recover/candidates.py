"""Candidate composition.

Combines the enabled sources (mask, fragments, wordlist) into a single stream of
password candidates, using constant memory. Dedup policy:
    - mask products are already unique -> not deduplicated
    - fragments are a small set -> deduplicated so the reported total is accurate
    - wordlists can be huge -> streamed as-is, not deduplicated
"""

import math
import threading
from collections.abc import Callable, Iterator
from os import PathLike

from .config import Config
from .fragments import count_fragments, gen_from_fragments
from .mask import count_mask, gen_from_mask
from .wordlist import gen_from_wordlist

PathArg = str | PathLike[str]

# Above this many candidates, do not materialize the fragment space just to show
# an exact total; report it as unknown (streaming) instead.
_COUNT_CAP = 500_000


def _fragment_prefix(cfg: Config) -> str | None:
    return cfg.fragments.fixed_prefix or None


def build_candidates(cfg: Config) -> Iterator[str]:
    """Yield every candidate for the enabled modes, in mask/fragments/wordlist order."""
    if cfg.mask.enabled:
        yield from gen_from_mask(cfg.mask.pattern)

    if cfg.fragments.enabled:
        seen: set[str] = set()
        for candidate in gen_from_fragments(
            cfg.fragments.pieces,
            cfg.fragments.permutations,
            cfg.fragments.case_variants,
            cfg.fragments.min_fragments,
            fixed_prefix=_fragment_prefix(cfg),
        ):
            if candidate not in seen:
                seen.add(candidate)
                yield candidate

    if cfg.wordlist.enabled:
        yield from gen_from_wordlist(cfg.wordlist.path)


def _fragment_upper_bound(cfg: Config) -> int:
    """Cheap analytic upper bound on the number of fragment candidates (before
    dedup), computed without generating anything."""
    pieces = cfg.fragments.pieces
    n = len(pieces)
    if n == 0:
        return 0
    min_len = max(1, min(cfg.fragments.min_fragments, n))
    permute = cfg.fragments.permutations
    factor = 4 if cfg.fragments.case_variants else 1  # <=4 case variants per piece
    has_fixed = bool(cfg.fragments.fixed_prefix) and cfg.fragments.fixed_prefix in pieces

    total = 0
    if has_fixed:
        for length in range(min_len, n + 1):
            orders = 1 if length == 1 else (
                math.perm(n - 1, length - 1) if permute else math.comb(n - 1, length - 1)
            )
            total += orders * (factor ** length)
    else:
        for r in range(min_len, n + 1):
            orders = math.perm(n, r) if permute else math.comb(n, r)
            total += orders * (factor ** r)
    return total


def count_total(cfg: Config) -> int | None:
    """Exact number of candidates, or None when it cannot be known cheaply.

    The total is known only when exactly one non-wordlist mode is active; with a
    wordlist or several modes at once it is a streaming, unknown-length source.
    For fragments, the exact (deduplicated) count is computed only when the space
    is small enough to enumerate; a huge space is reported as unknown.
    """
    only_mask = cfg.mask.enabled and not cfg.fragments.enabled and not cfg.wordlist.enabled
    only_frag = cfg.fragments.enabled and not cfg.mask.enabled and not cfg.wordlist.enabled
    if only_mask:
        return count_mask(cfg.mask.pattern)
    if only_frag:
        if _fragment_upper_bound(cfg) > _COUNT_CAP:
            return None
        return count_fragments(
            cfg.fragments.pieces,
            cfg.fragments.permutations,
            cfg.fragments.case_variants,
            cfg.fragments.min_fragments,
            fixed_prefix=_fragment_prefix(cfg),
        )
    return None


def export_candidates(
    cfg: Config,
    path: PathArg,
    on_progress: Callable[[int], None] | None = None,
    progress_every: int = 500_000,
    cancel: threading.Event | None = None,
) -> int:
    """Write all candidates to a file (one per line) for use as a hashcat wordlist.

    Returns the number of candidates written. ``on_progress`` (if given) is called
    with the running count every ``progress_every`` lines. Setting ``cancel`` stops
    the export early and leaves a partial file.
    """
    written = 0
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for candidate in build_candidates(cfg):
            if cancel is not None and cancel.is_set():
                break
            handle.write(candidate + "\n")
            written += 1
            if on_progress and written % progress_every == 0:
                on_progress(written)
    return written
