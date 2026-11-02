from __future__ import annotations

from datetime import date

import pytest

from symbiote.advisories.retirements import find_retirement, load_retirements, retirements_version


def test_table_loads_and_every_entry_is_sourced() -> None:
    entries = load_retirements()
    assert entries and retirements_version()
    for e in entries:
        assert e.source and e.ids
        if "recalled" in e.source or "third-party" in e.source:
            assert e.confidence == "low", e


@pytest.mark.parametrize("ref", ["claude-sonnet-4-5", "claude-sonnet-4-5-20250929"])
def test_alias_and_snapshot_both_resolve(ref: str) -> None:
    entry = find_retirement(ref)
    assert entry is not None
    assert entry.provider == "anthropic"
    assert entry.retires_on == date(2026, 11, 30)


def test_unknown_or_other_provider_does_not_match() -> None:
    assert find_retirement("claude-opus-4-5-20251101") is None
    assert find_retirement("my-local-llama") is None
    # The same identifier through a different provider has its own lifecycle.
    assert find_retirement("gpt-4o", provider="azure-openai") is None
