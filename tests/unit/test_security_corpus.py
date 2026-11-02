"""Regression tests over the hand-labelled security specimens in ``tests/fixtures/security-corpus``.

The specimens were salvaged from the previous ``main``'s benchmark harness (its nexus-bound runner and manifest
were dropped). Each case directory holds a tiny ``project/`` (or an ``observed-tool.json``) whose condition maps
onto one Symbiote check or digest property:

* ``mcp-*`` — ``.mcp.json`` launchers: floating ``@latest``, no version and a floating container tag must raise
  ``SYM-MCP-002``; an exact npm version and a container digest must not.
* ``credential-export-redaction`` — an inline secret in ``.mcp.json`` raises ``SYM-CRED-001`` and the sentinel
  literal must never appear in any emitted document (``spec/cli.md``: secrets never appear in output).
* ``tool-*`` — ``observed-tool.json`` definitions: a changed description changes the ``tooldef/v1`` digest, a
  key-order-only change does not (RFC 8785).
* ``prompt-*`` — ``CLAUDE.md`` files: zero-width and bidi code points are hidden Unicode (``SYM-INSTR-004``'s
  predicate); plain ASCII and the *escaped* text ``\\u200b`` are negative controls.
* ``model-*`` — serialization risk: the pickle is inert (``\\x80\\x04N.`` = ``None``) and still
  ``code-exec-on-load``; the SafeTensors file is a valid zero-tensor; a text file named ``.safetensors`` is a
  format anomaly; ``model.sigstore`` next to a model is a decoy, not a signature.

No instructions or local-model collector exists on this branch yet, so the ``prompt-*`` and ``model-*`` cases
exercise the underlying predicates (``symbiote.digest.textflags``, ``symbiote.models_identity.serialization``)
directly; when those collectors land (WP9), extend these tests to assert the ``SYM-INSTR-004`` / ``SYM-MODEL-*``
findings through ``symbiote scan``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from symbiote.cli import app
from symbiote.digest.textflags import hidden_code_points
from symbiote.models_identity import serialization

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "security-corpus"
SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_00"


def _scan_and_check(case: str, tmp_path: Path) -> tuple[dict, dict]:
    runner = CliRunner()
    out = tmp_path / case
    r = runner.invoke(
        app, ["scan", str(CORPUS / case / "project"), "-o", str(out), "--format", "all", "--deterministic"]
    )
    assert r.exit_code == 0, r.output
    r = runner.invoke(app, ["policy", "check", str(out / "agentbom.json"), "--fail-on", "low", "--json"])
    assert r.exit_code in (0, 1), r.output
    return json.loads(r.stdout), {p.name: p.read_text(encoding="utf-8") for p in out.iterdir() if p.is_file()}


def _ids(report: dict, state: str = "fail") -> set[str]:
    return {f["checkId"] for f in report["findings"] if f["state"] == state}


@pytest.mark.parametrize("case", ["mcp-floating-latest", "mcp-unversioned", "mcp-container-floating"])
def test_unpinned_launchers_raise_sym_mcp_002(case: str, tmp_path: Path) -> None:
    report, _ = _scan_and_check(case, tmp_path)
    assert "SYM-MCP-002" in _ids(report)


@pytest.mark.parametrize("case", ["mcp-exact-version", "mcp-container-digest"])
def test_pinned_launchers_do_not_raise_sym_mcp_002(case: str, tmp_path: Path) -> None:
    report, _ = _scan_and_check(case, tmp_path)
    assert "SYM-MCP-002" not in _ids(report)
    assert "SYM-MCP-002" not in _ids(report, "indeterminate")


def test_inline_secret_is_found_and_never_exported(tmp_path: Path) -> None:
    report, documents = _scan_and_check("credential-export-redaction", tmp_path)
    assert "SYM-CRED-001" in _ids(report)
    assert {"agentbom.json", "agentbom.cdx.json", "agentbom.spdx.json"} <= set(documents)
    for name, text in documents.items():
        assert SENTINEL not in text, f"secret value leaked into {name}"
    assert SENTINEL not in json.dumps(report)
    assert "API_TOKEN" in documents["agentbom.json"], "the credential *name* is recorded"


def _tooldef_digest(case: str) -> str:
    r = CliRunner().invoke(app, ["digest", "tooldef", str(CORPUS / case / "observed-tool.json"), "--json"])
    assert r.exit_code == 0, r.output
    payload = json.loads(r.stdout)
    assert payload["algorithm"] == "tooldef/v1" and payload["status"] == "ok"
    return payload["value"]


def test_tooldef_digest_is_stable_under_key_reordering_and_changes_with_the_description() -> None:
    baseline = _tooldef_digest("tool-unchanged-no-annotations")
    assert _tooldef_digest("tool-key-order-only") == baseline
    assert _tooldef_digest("tool-description-change") != baseline


def _instruction(case: str) -> str:
    return (CORPUS / case / "project" / "CLAUDE.md").read_text(encoding="utf-8")


def test_hidden_unicode_specimens() -> None:
    assert hidden_code_points(_instruction("prompt-zero-width")) == ["U+200B"]
    assert set(hidden_code_points(_instruction("prompt-bidi"))) >= {"U+202E", "U+202C"}
    assert hidden_code_points(_instruction("prompt-ascii")) == []
    assert hidden_code_points(_instruction("prompt-escaped-unicode-text")) == [], (
        "the escape text is plain ASCII"
    )


def test_inert_pickle_is_still_code_exec_on_load() -> None:
    path = CORPUS / "model-pickle-loader" / "project" / "model.pkl"
    assert path.read_bytes() == b"\x80\x04N."
    assessment = serialization.assess_file(path)
    assert assessment.format == "pickle" and assessment.risk_class == "code-exec-on-load"


def test_valid_zero_tensor_safetensors_is_safe() -> None:
    path = CORPUS / "model-format-valid-unsigned" / "project" / "model.safetensors"
    assessment = serialization.assess_file(path)
    assert assessment.format == "safetensors" and assessment.risk_class == "none"
    header = serialization.read_safetensors_header(path)
    assert header.tensor_count == 1 and header.anomalies == ()


def test_disguised_safetensors_is_not_treated_as_safetensors() -> None:
    path = CORPUS / "model-format-disguised" / "project" / "model.safetensors"
    assert path.read_bytes().startswith(b"not-a-tensor")
    assessment = serialization.assess_file(path)
    assert assessment.format != "safetensors" or assessment.reasons, (
        "a text file with a .safetensors name must not pass silently"
    )


def test_signature_decoy_is_not_a_signature() -> None:
    decoy = CORPUS / "model-signature-decoy" / "project" / "model.sigstore"
    assert decoy.read_text(encoding="utf-8").startswith("This is not a signature")
    with pytest.raises(json.JSONDecodeError):
        json.loads(decoy.read_text(encoding="utf-8"))
