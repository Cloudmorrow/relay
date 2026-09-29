"""What a cloud may be called.

A name is what a person typed, folded (Unicode NFKC, trimmed, lower case),
and then 5 to 40 of `a-z 0-9 -`, starting and ending with a letter or
digit, with no `--` (which also rules out `xn--` look-alikes of other
names), and not reserved: the list in config.py, the labels the zone's own
names use, and `reserved` in the config. The website asks the admin API
before it offers a name, so these sentences are what a person reads.
"""

from __future__ import annotations

import re
import unicodedata

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{3,38}[a-z0-9]$")
MIN, MAX = 5, 40


def normalise_name(value: str) -> str:
    """What a person typed, as the name it would become: compatibility
    forms folded (a full-width "Ｌ" is an "l"), outer space dropped, lower
    case. Nothing else is changed; the rules below then accept or refuse.
    """
    return unicodedata.normalize("NFKC", value or "").strip().lower()


def name_problem(name: str, reserved: frozenset[str]) -> str | None:
    if not MIN <= len(name) <= MAX:
        return f"A name is {MIN} to {MAX} characters long."
    if not NAME_RE.match(name):
        return "A name is made of a-z, 0-9 and hyphens, and starts and ends with a letter or digit."
    if "--" in name:
        return "A name cannot have two hyphens in a row."
    if name in reserved:
        return f"The name {name} is reserved."
    return None
