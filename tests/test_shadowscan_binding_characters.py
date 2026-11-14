"""Report-carried repository and commit bindings carry no text that disguises itself."""

from __future__ import annotations

import pytest

from nexus_symbiote.scanners.shadowscan import _clean_binding


@pytest.mark.parametrize(
    "value",
    [
        "git\x9b31mhub.example",  # C1 control: CSI
        "a\u202eb",  # right-to-left override
        "a\u200bb",  # zero-width space
        "a\u2028b",  # line separator
        "a\ufeffb",  # byte-order mark inside the text
        "a\x1bb",  # C0 control: ESC
        "a\x7fb",  # DEL
        "a\tb",  # tab
    ],
)
def test_bindings_with_control_or_format_characters_are_not_recorded(value: str) -> None:
    assert _clean_binding(value) is None


@pytest.mark.parametrize("value", ["github.com/org/repo", "deadbeef", "räpö/repo"])
def test_plain_bindings_are_recorded_as_written(value: str) -> None:
    assert _clean_binding(value) == value
