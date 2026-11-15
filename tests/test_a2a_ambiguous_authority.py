"""A URL authority that Python's urlsplit and WHATWG parsers read as different hosts.

urlsplit takes the host after the last "@", so for ``https://evil.example\\@good.example``
it reports ``good.example``. WHATWG parsers, used by browsers and Node, end the authority
at the backslash and connect to ``evil.example``. Exporting the urlsplit host would record
an endpoint the client never uses.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.core.models import A2AServerComponent
from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.scanners.source_binding import beyond_origin, odd_host, origin

AMBIGUOUS = [
    "https://evil.example\\@agents.example.com/a2a",
    "https://evil.example\\agents.example.com/a2a",
    "https://user\\x@agents.example.com",
]


@pytest.mark.parametrize("url", AMBIGUOUS)
def test_a_backslash_in_the_authority_is_never_exported_as_a_host(url):
    assert odd_host(url)
    assert origin(url) == "[redacted]"
    assert beyond_origin(url, frozenset({"", "/"}))


def test_an_unambiguous_url_keeps_its_origin():
    assert not odd_host("https://agents.example.com/a2a")
    assert origin("https://agents.example.com/a2a") == "https://agents.example.com"


def test_an_a2a_card_with_an_ambiguous_authority_records_no_host(tmp_path: Path):
    card = {
        "name": "billing-agent",
        "version": "1.0.0",
        "url": AMBIGUOUS[0],
        "protocols": ["a2a/0.3"],
        "skills": [{"id": "lookup", "name": "lookup-invoice"}],
    }
    (tmp_path / ".well-known").mkdir()
    (tmp_path / ".well-known" / "agent.json").write_text(json.dumps(card))
    result = A2AScanner().scan(tmp_path)
    (server,) = [c for c in result.components if isinstance(c, A2AServerComponent)]
    assert server.endpoint_url == "[redacted]"
    assert "agents.example.com" not in json.dumps(server.model_dump(mode="json"))
