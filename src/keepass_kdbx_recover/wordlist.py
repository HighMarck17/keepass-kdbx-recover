"""External wordlist source.

Streams one candidate per line from a text file. Undecodable bytes are ignored
so a mixed-encoding list still loads. Wordlists can be very large, so this source
does NOT deduplicate - it yields every line as-is, using constant memory.
"""

from collections.abc import Iterator
from os import PathLike


def gen_from_wordlist(path: str | PathLike[str]) -> Iterator[str]:
    """Yield each line of the wordlist with trailing CR/LF removed."""
    with open(path, encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            yield line.rstrip("\r\n")
