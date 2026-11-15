"""docs/runtime-contract-reference.md matches the code it specifies."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import pytest

from nexus_symbiote.runtime import (
    REASONS,
    ActionApproval,
    ApprovedSnapshot,
    ExecutionContext,
    HostedModelAttestation,
    SignerScope,
    ToolGrant,
    TrustStatus,
)

REFERENCE = Path(__file__).resolve().parents[1] / "docs" / "runtime-contract-reference.md"
TEXT = REFERENCE.read_text(encoding="utf-8")


def section(heading: str) -> str:
    match = re.search(rf"^#+ {re.escape(heading)}$(.*?)(?=^#{{1,3}} |\Z)", TEXT, re.M | re.S)
    assert match is not None, heading
    return match.group(1)


def test_worked_example_runs_as_written(tmp_path, monkeypatch):
    blocks = re.findall(r"^```python\n(.*?)^```$", section("Worked example"), re.M | re.S)
    assert len(blocks) == 1
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    namespace = {"__name__": "runtime_example"}
    exec(compile(blocks[0], str(REFERENCE), "exec"), namespace)  # noqa: S102
    assert namespace["execution_attempts"] == [{"sent_to": "team@example.test"}]
    assert [(item.admitted, item.reason) for item in namespace["decisions"]] == [
        (True, "admitted"),
        (False, "approval-replayed"),
        (True, "admitted"),
        (False, "approval-replayed"),
        (False, "snapshot-superseded"),
    ]


def test_reason_code_table_lists_exactly_the_codes_the_code_raises():
    documented = set(re.findall(r"^\| `([a-z-]+)` \|", section("Reason codes"), re.M))
    assert documented == set(REASONS)


def test_reason_codes_raised_in_the_source_are_registered():
    source = "".join(
        (Path(__file__).resolve().parents[1] / "src" / "nexus_symbiote" / name).read_text()
        for name in ("runtime.py", "runtime_validation.py")
    )
    raised = set(re.findall(r'reason="([a-z-]+)"', source))
    purposes = ("snapshot", "trust", "approval", "model", "contract")
    windows = {f"{p}-{s}" for p in purposes for s in ("not-yet-valid", "expired")}
    windows |= {f"{p}-lifetime-exceeds-policy" for p in purposes}
    assert raised <= set(REASONS)
    assert windows <= set(REASONS)


@pytest.mark.parametrize(
    ("heading", "model"),
    [
        ("ApprovedSnapshot", ApprovedSnapshot),
        ("ToolGrant", ToolGrant),
        ("TrustStatus", TrustStatus),
        ("ActionApproval", ActionApproval),
        ("HostedModelAttestation", HostedModelAttestation),
        ("Unsigned inputs", ExecutionContext),
        ("Gateway configuration", SignerScope),
    ],
)
def test_every_contract_field_is_documented(heading, model):
    body = section(heading)
    missing = [name for name in model.model_fields if f"`{name}`" not in body]
    assert not missing, (heading, missing)
