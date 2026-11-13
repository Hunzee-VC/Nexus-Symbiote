"""Package source origins are found in time linear in a setting's length, with the same
results as the regular expression they replace."""

from __future__ import annotations

import re
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from nexus_symbiote.scanners.mcp import MCPScanner, _locators, _origin_label
from tests.support import scaling_ratio

LOCATOR = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s,;\"']+")
PIECES = st.sampled_from(
    [*"aZ9+.-:/@#?%$\\ ,;\"'\t\n", "\u00a0", "\u3000", "\u2028", "\x1c", "://", "a://", "1://"]
)


@given(st.lists(PIECES, max_size=40).map("".join))
def test_locators_are_the_matches_of_the_expression(value):
    assert _locators(value) == LOCATOR.findall(value)


@given(st.text(max_size=60))
def test_locators_agree_on_any_text(value):
    assert _locators(value) == LOCATOR.findall(value)


def test_origins_keep_only_scheme_host_and_port():
    value = "https://alice:S3CR1@npm.example:8443/p?t=S3CR2 http://x.example/a,ftp://y.example"
    assert _origin_label(value) == [
        "ftp://y.example",
        "http://x.example",
        "https://npm.example:8443",
    ]
    assert _origin_label("${REGISTRY}") == ["[unresolved]"]
    assert _origin_label("./wheels") == ["[local]"]
    assert _origin_label("") == []


def test_a_long_run_of_scheme_characters_is_read_in_linear_time():
    values = {scale: "a" * 200_000 * scale + "://" for scale in (1, 4)}
    assert scaling_ratio(lambda scale: _origin_label(values[scale])) < 8


def test_a_long_registry_value_does_not_hold_the_mcp_collector(tmp_path: Path):
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"lookup": {"command": "npx", "args": ["-y", "lookup-mcp@1.2.3"]}}}'
    )

    def run(scale: int) -> None:
        (tmp_path / ".npmrc").write_text("registry=" + "a" * 100_000 * scale + "\n")
        result = MCPScanner().scan(tmp_path)
        [server] = [c for c in result.components if c.component_type.value == "mcp-server"]
        assert server.properties["package_sources"] == [".npmrc:registry=[local]"]

    assert scaling_ratio(run) < 8
