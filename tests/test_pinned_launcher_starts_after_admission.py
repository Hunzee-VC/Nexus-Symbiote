"""A pinned launcher runs only for evidence that passes every check before the descriptor.

Audit 2026-11-14 L25: ``invoke_pinned_stdio`` used to stage and start the operator's
launcher, and complete the MCP ``initialize`` handshake, before the gateway verified
the trust status or the snapshot, so any caller could make it run. The launcher now
starts when the gateway first asks for the served descriptor (step 8 of the
verification order), after the trust status, snapshot, workload context, companion
BOM, scope and grant have been checked.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from nexus_symbiote.live.session import invoke_pinned_stdio
from nexus_symbiote.runtime import AuthorizationError, sign_contract
from tests.test_runtime_authorization import fixture
from tests.test_runtime_stdio_session import launcher, signed_inputs


def started_launcher(tmp_path: Path) -> tuple[Path, str, Path]:
    """The suite's launcher, which also records that it started before reading input."""
    path, _, _ = launcher(tmp_path)
    started = tmp_path / "started"
    script = path.read_text().replace(
        "for line in sys.stdin:",
        f"open({str(started)!r}, 'a').close()\nfor line in sys.stdin:",
        1,
    )
    path.write_text(script)
    return path, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(), started


def test_an_admitted_call_starts_the_launcher(tmp_path):
    values = fixture(tmp_path)
    path, pin, started = started_launcher(tmp_path)
    result = invoke_pinned_stdio(
        values[0], values[1], command=str(path), sha256=pin, **signed_inputs(values, pin)
    )
    assert result["content"][0]["text"] == "ok"
    assert started.exists()


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        ("trust-signer", "signers-insufficient"),
        ("snapshot-signer", "signers-insufficient"),
        ("workload", "trust-tenant-mismatch"),
        ("bom", "bom-mismatch"),
        ("scope", "scope-mismatch"),
        ("revocation", "tool-revoked"),
    ],
)
def test_evidence_refused_before_the_descriptor_never_starts_the_launcher(
    tmp_path, failure, reason
):
    values = list(fixture(tmp_path))
    gateway, call, _, snapshot, status, _, _, human, trust_key, _ = values
    path, pin, started = started_launcher(tmp_path)
    kwargs = signed_inputs(values, pin)
    decisions = []
    gateway.on_decision = decisions.append
    if failure == "trust-signer":
        kwargs["trust"] = sign_contract(status, "trust", (human,))
    elif failure == "snapshot-signer":
        grant = snapshot.tools[0].model_copy(update={"endpoint_identity": "stdio+launcher:" + pin})
        pinned = snapshot.model_copy(update={"tools": (grant,)})
        kwargs["snapshot"] = sign_contract(pinned, "snapshot", (human,))
    elif failure == "workload":
        context = gateway.authenticate()
        gateway.authenticate = lambda: context.model_copy(update={"tenant": "other"})
    elif failure == "bom":
        kwargs["bom"] = {"agent": "triage", "tools": ["send", "delete"]}
    elif failure == "scope":
        gateway.resolve_scope = lambda _: ("send", "mailbox:admin")
    elif failure == "revocation":
        status = status.model_copy(update={"revoked_tools": (snapshot.tools[0].definition_digest,)})
        kwargs["trust"] = sign_contract(status, "trust", (trust_key,))
    with pytest.raises(AuthorizationError) as denied:
        invoke_pinned_stdio(gateway, call, command=str(path), sha256=pin, **kwargs)
    assert denied.value.reason == reason
    assert not started.exists()
    [decision] = decisions
    assert (decision.admitted, decision.reason) == (False, reason)


def test_a_launcher_that_cannot_be_staged_is_reported_once_with_the_call_facts(tmp_path):
    values = fixture(tmp_path)
    path, _, started = started_launcher(tmp_path)
    pin = "sha256:" + "0" * 64
    decisions = []
    values[0].on_decision = decisions.append
    with pytest.raises(AuthorizationError, match="differs from approved digest"):
        invoke_pinned_stdio(
            values[0], values[1], command=str(path), sha256=pin, **signed_inputs(values, pin)
        )
    assert not started.exists()
    [decision] = decisions
    assert (decision.admitted, decision.reason) == (False, "denied")
    # The refusal comes from the gateway's descriptor step, so the decision carries the
    # verified tenant and snapshot, which a refusal before the gateway could not.
    assert decision.tenant == "acme"
    assert decision.snapshot_serial == 1
