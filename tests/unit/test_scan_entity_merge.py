"""Assurance-ranked same-id entity merge in scan (I2; SYM-TOOL-002 depends on it).

The original defect: first-collector-wins (alphabetical), so a declared stub in
mcp.json beat mcp-live's served definition — the served digest never reached the
document and rug-pull detection was silently disabled.
"""

from __future__ import annotations

from symbiote.digest.tooldef import tooldef_digest
from symbiote.model.common import EvidenceRef, Provenance
from symbiote.model.entities import ToolDefinition
from symbiote.model.enums import CollectorMode, ToolSource, ToolState
from symbiote.scan import DIGEST_CONFLICT_TAG, _absorb

DECLARED = CollectorMode.DECLARED
OBSERVED = CollectorMode.OBSERVED


def _tool(source: ToolSource, state: ToolState, description: str, evidence_digest: str | None = None):
    raw = {"name": "create_issue", "description": description, "inputSchema": {"type": "object"}}
    provenance = (
        Provenance(evidence=[EvidenceRef(digest=evidence_digest, media_type="application/json")])
        if evidence_digest
        else Provenance()
    )
    return ToolDefinition(
        id="tool:github/create_issue",
        server_ref="server:github",
        tool_name="create_issue",
        input_schema=raw["inputSchema"],
        digest=tooldef_digest(raw),
        source=source,
        state=state,
        provenance=provenance,
    )


def _declared_stub():
    return _tool(ToolSource.DECLARED_CONFIG, ToolState.DECLARED, "benign stub")


def _served():
    return _tool(
        ToolSource.SERVED_LIVE, ToolState.SERVED, "the real served definition", "sha256:" + "ab" * 32
    )


def test_observed_supersedes_declared_stub_in_both_orders() -> None:
    stub, served = _declared_stub(), _served()
    # stub arrives first (alphabetical collector order: mcp-config < mcp-live)
    survivor, mode, note = _absorb(stub, DECLARED, served, OBSERVED)
    assert survivor.digest == served.digest and survivor.state is ToolState.SERVED
    assert mode is OBSERVED and note and "supersedes" in note
    # served arrives first: the stub corroborates, never replaces
    survivor2, mode2, _ = _absorb(served, OBSERVED, _declared_stub(), DECLARED)
    assert survivor2.digest == served.digest and survivor2.state is ToolState.SERVED
    assert mode2 is OBSERVED


def test_equal_rank_digest_conflict_is_tagged_into_the_document() -> None:
    a = _tool(ToolSource.SERVED_LIVE, ToolState.SERVED, "definition A", "sha256:" + "aa" * 32)
    b = _tool(ToolSource.SERVED_LIVE, ToolState.SERVED, "definition B", "sha256:" + "bb" * 32)
    assert a.digest.value != b.digest.value
    survivor, mode, note = _absorb(a, OBSERVED, b, OBSERVED)
    assert DIGEST_CONFLICT_TAG in survivor.tags  # visible to document consumers, not only warnings
    assert note and "conflicting digest" in note
    assert mode is OBSERVED
