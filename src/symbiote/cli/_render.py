"""Safe terminal rendering of human-readable CLI output.

Names, messages and paths in a scan come from the scanned repository. Rich markup in them (``[link=…]``,
``[conceal]``) or raw terminal control sequences could hide or spoof what an operator reads. Every human line is
escaped as a whole; only the CLI's own style tags are re-enabled.
"""

from __future__ import annotations

import re

from rich.markup import escape

_STYLE_TAGS = re.compile(r"\\\[(/?(?:red|green|yellow|cyan|white|bold|dim|magenta|blue)(?: [a-z]+)?)\]")
_CONTROL = re.compile("[\\x00-\\x08\\x0b-\\x1f\\x7f-\\x9f\\u202a-\\u202e\\u2066-\\u2069]")


def safe_markup(text: str) -> str:
    """Escape all markup, strip control and bidi characters, then re-enable the whitelisted style tags."""
    cleaned = _CONTROL.sub("", text)
    return _STYLE_TAGS.sub(lambda m: f"[{m.group(1)}]", escape(cleaned))


__all__ = ["escape", "safe_markup"]
