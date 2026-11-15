"""Lockfile origin normalization must preserve the private-advisory boundary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.advisories import fetch_advisories
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.scanners.live_mcp import HTTPReply
from nexus_symbiote.scanners.registry import RegistryScanner


class _Transport:
    def __init__(self) -> None:
        self.calls: list[list[dict]] = []

    def request(self, endpoint, body, headers, *, timeout, max_bytes):
        queries = json.loads(body)["queries"]
        self.calls.append(queries)
        return HTTPReply(
            200,
            {"content-type": "application/json"},
            json.dumps({"results": [{} for _ in queries]}).encode(),
        )


def _scan(root: Path, lock: str, origin: object):
    (root / "requirements.txt").write_text("openai-internal-agent>=1\n")
    field = "registry" if lock == "uv.lock" else "url"
    (root / lock).write_text(
        '[[package]]\nname="openai-internal-agent"\nversion="1.2.3"\n'
        + "source={"
        + field
        + "="
        + json.dumps(origin)
        + "}\n"
    )
    result = RegistryScanner().scan(root)
    assert len(result.components) == 1
    return result, result.components[0]


@pytest.mark.parametrize("lock", ["uv.lock", "poetry.lock"])
@pytest.mark.parametrize(
    "origin",
    [
        "HTTPS://private.example/simple",
        "HtTpS://private.example/simple",
        "HTTP://private.example/simple",
        "ftp://private.example/simple",
        "https:///simple",
        "https://[bad",
        "",
        7,
        "https://private.example:bad/simple",
        "https://private.example/white space",
        "https://private.example\\@pypi.org/simple",
        "https://pypi%2eorg/simple",
        "https://pr\u00edvate.example/simple",
        "https://private.example/" + "x" * 4096,
    ],
)
def test_ambiguous_index_sources_never_reach_public_identity_or_advisories(
    tmp_path: Path, lock: str, origin: object
) -> None:
    result, component = _scan(tmp_path, lock, origin)
    assert result.surfaces_excluded
    assert component.package_url is None and component.registry_uri is None
    assert "package_resolution" not in component.claims
    transport = _Transport()
    report = fetch_advisories(
        AIBOM(components=result.components), exclude_private_origins=True, transport=transport
    )
    assert not report.queries and not transport.calls


@pytest.mark.parametrize("lock", ["uv.lock", "poetry.lock"])
@pytest.mark.parametrize(
    ("origin", "normalized", "severity"),
    [
        ("https://Private.Example:443/simple", "https://private.example", RiskSeverity.LOW),
        ("http://Private.Example/simple", "http://private.example", RiskSeverity.HIGH),
        ("https://PyPI.org:443/simple", "https://pypi.org", None),
    ],
)
def test_case_and_default_port_normalization_keep_the_origin_boundary(
    tmp_path: Path, lock: str, origin: str, normalized: str, severity: RiskSeverity | None
) -> None:
    result, component = _scan(tmp_path, lock, origin)
    assert not result.scan_failures and not result.surfaces_excluded
    assert component.registry_uri == normalized
    risks = [risk for risk in component.risks if risk.category == "registry_origin"]
    public_purl = "pkg:pypi/openai-internal-agent@1.2.3"
    if severity is None:
        assert not risks and component.package_url == public_purl
    else:
        assert [risk.severity for risk in risks] == [severity]
        assert component.package_url == public_purl + "?repository_url=" + normalized
    transport = _Transport()
    report = fetch_advisories(
        AIBOM(components=result.components), exclude_private_origins=True, transport=transport
    )
    assert len(report.queries) == (1 if severity is None else 0)
    assert len(transport.calls) == (1 if severity is None else 0)
