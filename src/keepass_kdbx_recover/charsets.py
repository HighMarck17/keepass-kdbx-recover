"""Character classes used by the hashcat-style mask generator.

Placeholders (hashcat convention):
    ?l  lowercase letters   a-z
    ?u  uppercase letters   A-Z
    ?d  digits              0-9
    ?s  common symbols      !@#$%^&*_-
    ?a  any of the above    letters + digits + symbols
    ??  a literal question mark
"""

import string

SYMBOLS = "!@#$%^&*_-"

CHARSETS: dict[str, str] = {
    "?l": string.ascii_lowercase,
    "?u": string.ascii_uppercase,
    "?d": string.digits,
    "?s": SYMBOLS,
    "?a": string.ascii_letters + string.digits + SYMBOLS,
}
