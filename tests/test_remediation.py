"""Regression tests for the remediation findings.

Each test names the behaviour it locks in. Every test uses tmp_path, makes no network
calls, and does not read the real home directory.
"""

from __future__ import annotations

import inspect
import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

import nexus_symbiote.scanners.model as model_module
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import ComponentType, RiskSeverity
from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.core.models import (
    AIBOMMetadata,
    CompletenessClaim,
    ModelComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.core.redact import redact_aibom, redact_string
from nexus_symbiote.core.textsafety import find_hidden_characters
from nexus_symbiote.core.vocab import (
    SCANNER_NAMES,
    SIGNING_NOT_FOUND,
    SIGNING_PRESENT_UNVERIFIED,
    normalize_signing_status,
)
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.policy import (
    DEFAULT_POLICY_YAML,
    PolicyError,
    default_policy,
    load_policy_file,
)
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.scanners.prompt import PromptScanner, detect_invisible_characters
from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.scanners.shadowscan import ShadowScanImporter
from nexus_symbiote.utils.fsio import MAX_MODEL_BYTES, hash_regular_file, write_text_safely
from nexus_symbiote.validators.coverage import assess_coverage
from nexus_symbiote.validators.integrity import IntegrityValidator
from nexus_symbiote.validators.risk import RiskScorer

ROOT = Path(__file__).resolve().parents[1]
GIB = 1024**3
VERSION_PIN = "rfc8785-jcs-v1"


def _claim(**overrides: Any) -> CompletenessClaim:
    """A claim in which every built-in scanner completed."""
    statuses = dict.fromkeys(SCANNER_NAMES, "complete")
    return CompletenessClaim(scope="test", scanner_status=statuses, **overrides)


def _bom(*components: Any, claim: CompletenessClaim | None = None) -> AIBOM:
    bom = AIBOM(metadata=AIBOMMetadata(completeness=claim))
    for component in components:
        bom.add_component(component)
    return bom


def _model(**fields: Any) -> ModelComponent:
    return ModelComponent(bom_ref="model:m", name="m", **fields)


def _tool(definition_hash: str) -> ToolComponent:
    return ToolComponent(
        bom_ref="tool:t",
        name="t",
        description_text="Ping the host",
        definition_hash=definition_hash,
        definition_hash_version=VERSION_PIN,
    )


def _walk_dicts(node: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(node, dict):
        found.append(node)
        for value in node.values():
            found.extend(_walk_dicts(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_walk_dicts(item))
    return found


# COVERAGE

def test_repository_without_optional_surfaces_is_complete_and_passes(tmp_path):
    out = tmp_path / "bom.json"
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "--policy", "none", "-o", str(out)])
    assert result.exit_code == 0, result.output
    bom = AIBOM.load(out)
    assert assess_coverage(bom.metadata.completeness).state == "complete"
    passed, report = RiskScorer().passes_gate(bom)
    assert report.coverage_status == "complete"
    assert passed


def test_scanner_that_drops_a_file_records_failure_and_fails_gate(tmp_path):
    (tmp_path / ".mcp.json").write_text("{not valid json", encoding="utf-8")
    out = tmp_path / "bom.json"
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "--policy", "none", "-o", str(out)])
    assert result.exit_code == 1
    bom = AIBOM.load(out)
    assert bom.metadata.completeness.scanner_status["mcp"] == "failed"
    assert bom.metadata.completeness.scan_failures
    passed, report = RiskScorer().passes_gate(bom)
    assert report.coverage_status == "failed"
    assert not passed


def test_excluded_path_makes_coverage_partial(tmp_path):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    result = MCPScanner(exclude_paths=[".mcp.json"]).scan(tmp_path)
    assert result.surfaces_excluded
    assert not result.scan_failures
    claim = _claim(surfaces_excluded=list(result.surfaces_excluded))
    assert assess_coverage(claim).state == "partial"
    passed, report = RiskScorer().passes_gate(_bom(claim=claim))
    assert report.coverage_status == "partial"
    assert not passed


# GATE

class TestGate:
    def test_unknown_coverage_fails(self):
        passed, report = RiskScorer(fail_threshold=50).passes_gate(_bom())
        assert report.coverage_status == "unknown"
        assert not passed

    def test_partial_coverage_fails(self):
        claim = _claim(surfaces_excluded=["mcp-config .mcp.json (excluded by policy)"])
        passed, report = RiskScorer(fail_threshold=50).passes_gate(_bom(claim=claim))
        assert report.coverage_status == "partial"
        assert not passed

    def test_failed_coverage_fails(self):
        claim = _claim(scan_failures=["mcp: malformed JSON"])
        passed, report = RiskScorer(fail_threshold=50).passes_gate(_bom(claim=claim))
        assert report.coverage_status == "failed"
        assert not passed

    def test_complete_with_low_score_passes(self):
        low = RiskAssessment(severity=RiskSeverity.LOW, category="minor", detail="low note")
        tool = ToolComponent(bom_ref="tool:a", name="a", risks=[low])
        passed, report = RiskScorer(fail_threshold=50).passes_gate(_bom(tool, claim=_claim()))
        assert report.coverage_status == "complete"
        assert report.overall_score == 1.0
        assert passed

    def test_critical_finding_fails_even_when_category_is_ignored(self):
        critical = RiskAssessment(
            severity=RiskSeverity.CRITICAL, category="shadow", detail="critical finding"
        )
        tool = ToolComponent(bom_ref="tool:b", name="b", risks=[critical])
        scorer = RiskScorer(fail_threshold=50, ignore_categories=["shadow"])
        passed, report = scorer.passes_gate(_bom(tool, claim=_claim()))
        assert not passed
        assert report.suppressed == 0
        assert report.severity_counts.get("critical") == 1


# POLICY

class TestPolicy:
    def test_symlinked_policy_file_is_refused(self, tmp_path):
        pytest.importorskip("yaml")
        real = tmp_path / "real.yaml"
        real.write_text("version: '1.0'\n", encoding="utf-8")
        link = tmp_path / "link.yaml"
        link.symlink_to(real)
        with pytest.raises(PolicyError):
            load_policy_file(link)

    def test_out_of_range_threshold_is_rejected_without_echoing_value(self, tmp_path):
        pytest.importorskip("yaml")
        path = tmp_path / "policy.yaml"
        path.write_text("risk:\n  fail_threshold: 7777.25\n", encoding="utf-8")
        with pytest.raises(PolicyError) as excinfo:
            load_policy_file(path)
        message = str(excinfo.value)
        assert "fail_threshold" in message
        assert "7777" not in message

    def test_warn_threshold_above_fail_threshold_is_rejected(self, tmp_path):
        pytest.importorskip("yaml")
        path = tmp_path / "policy.yaml"
        path.write_text("risk:\n  fail_threshold: 40\n  warn_threshold: 60\n", encoding="utf-8")
        with pytest.raises(PolicyError):
            load_policy_file(path)

    def test_default_policy_lists_all_eight_scanners(self, tmp_path):
        pytest.importorskip("yaml")
        assert len(SCANNER_NAMES) == 8
        assert default_policy().scan.scanners == list(SCANNER_NAMES)
        for name in SCANNER_NAMES:
            assert f'"{name}"' in DEFAULT_POLICY_YAML
        path = tmp_path / "default.yaml"
        path.write_text(DEFAULT_POLICY_YAML, encoding="utf-8")
        assert load_policy_file(path).scan.scanners == list(SCANNER_NAMES)


# INTEGRITY

class TestIntegrity:
    def test_scanner_hashed_tool_with_empty_annotations_validates(self, tmp_path):
        config = {
            "mcpServers": {
                "pinned": {
                    "command": "npx",
                    "args": ["-y", "some-server@1.0.0"],
                    "tools": [{"name": "ping", "description": "Ping the host", "annotations": {}}],
                }
            }
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")
        result = MCPScanner().scan(tmp_path)
        tools = [c for c in result.components if c.component_type == ComponentType.TOOL]
        assert len(tools) == 1
        assert tools[0].annotations == {}
        report = IntegrityValidator().validate(_bom(*result.components))
        assert report.is_valid
        assert report.hashes_verified >= 1

    def test_hash_without_description_text_is_unverifiable(self):
        tool = ToolComponent(
            bom_ref="tool:x",
            name="x",
            definition_hash="sha256:" + "0" * 64,
            definition_hash_version=VERSION_PIN,
            description_text=None,
        )
        report = IntegrityValidator().validate(_bom(tool))
        assert not report.is_valid
        assert [i.category for i in report.issues] == ["unverifiable_definition"]
        assert report.issues[0].severity == "error"

    def test_relabelled_component_still_runs_tool_checks(self):
        original = hash_tool_definition("t", "Original text", None, {})
        relabelled = ToolComponent(
            bom_ref="tool:t",
            name="t",
            component_type=ComponentType.MODEL,
            description_text="Changed text",
            definition_hash=original,
            definition_hash_version=VERSION_PIN,
        )
        report = IntegrityValidator().validate(_bom(relabelled))
        assert not report.is_valid
        assert [i.category for i in report.issues] == ["hash_mismatch"]


# SIGNING

class TestSigning:
    def test_legacy_spellings_map_to_current_vocabulary(self):
        assert normalize_signing_status("unsigned") == SIGNING_NOT_FOUND
        assert normalize_signing_status("sigstore-signed") == SIGNING_PRESENT_UNVERIFIED
        assert normalize_signing_status(None) is None

    def test_signing_evidence_removed_is_high(self):
        old = _bom(_model(signing_status=SIGNING_PRESENT_UNVERIFIED))
        new = _bom(_model(signing_status=None))
        report = AIBOMDiffer().diff(old, new)
        assert len(report.components_modified) == 1
        change = report.components_modified[0]
        assert change.severity == "high"
        assert any("signing evidence removed" in detail for detail in change.details)

    def test_removed_model_component_with_signature_is_high(self):
        old = _bom(_model(signing_status=SIGNING_PRESENT_UNVERIFIED))
        report = AIBOMDiffer().diff(old, _bom())
        assert [c.severity for c in report.components_removed] == ["high"]


# DIFF

class TestDiff:
    def test_removed_file_hash_is_high(self):
        old = _bom(_model(hashes={"sha256": "sha256:" + "a" * 64}))
        new = _bom(_model(hashes={}))
        report = AIBOMDiffer().diff(old, new)
        assert report.components_modified[0].severity == "high"
        assert "evidence removed: hashes.sha256" in report.components_modified[0].details

    def test_highest_severity_is_none_without_changes(self):
        assert AIBOMDiffer().diff(_bom(), _bom()).highest_severity() is None

    def test_highest_severity_reports_critical(self):
        old = _bom(_tool("sha256:" + "a" * 64))
        new = _bom(_tool("sha256:" + "b" * 64))
        assert AIBOMDiffer().diff(old, new).highest_severity() == "critical"

    def test_diff_command_fails_on_high_by_default(self, tmp_path):
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"
        old_path.write_text(
            _bom(_model(signing_status=SIGNING_PRESENT_UNVERIFIED)).to_json(), encoding="utf-8"
        )
        new_path.write_text(_bom(_model(signing_status=None)).to_json(), encoding="utf-8")
        runner = CliRunner()
        base = ["diff", str(old_path), str(new_path)]
        assert runner.invoke(main, base).exit_code == 1
        assert runner.invoke(main, [*base, "--fail-on", "critical"]).exit_code == 0
        assert runner.invoke(main, [*base, "--fail-on", "none"]).exit_code == 0


# MODEL

class TestModel:
    def test_model_size_bound_is_at_least_256_gib(self):
        assert MAX_MODEL_BYTES >= 256 * GIB
        default = inspect.signature(hash_regular_file).parameters["max_bytes"].default
        assert default >= 256 * GIB

    def test_weight_above_one_gib_is_hashed_without_a_scanner_cap(self, tmp_path, monkeypatch):
        calls: list[dict[str, Any]] = []

        def spy(path: Path, **kwargs: Any) -> str:
            calls.append(kwargs)
            return "sha256:" + "0" * 64

        monkeypatch.setattr(model_module, "hash_regular_file", spy)
        folder = tmp_path / "big"
        folder.mkdir()
        with (folder / "model.safetensors").open("wb") as handle:
            handle.truncate(GIB + 1)  # sparse file; the hasher is replaced by the spy
        result = ModelScanner().scan(tmp_path)
        assert calls == [{}]
        assert len(result.components) == 1
        assert not result.scan_failures

    def test_two_model_directories_get_distinct_refs(self, tmp_path):
        for folder in ("one/model", "two/model"):
            (tmp_path / folder).mkdir(parents=True)
            (tmp_path / folder / "model.safetensors").write_bytes(b"\x00" * 16)
        refs = [c.bom_ref for c in ModelScanner().scan(tmp_path).components]
        assert len(refs) == 2
        assert len(set(refs)) == 2


# RAG

def test_env_and_env_example_naming_same_store_get_distinct_refs(tmp_path):
    text = "PINECONE_API_KEY=xxx\nPINECONE_INDEX=idx\n"
    (tmp_path / ".env").write_text(text, encoding="utf-8")
    (tmp_path / ".env.example").write_text(text, encoding="utf-8")
    refs = sorted(c.bom_ref for c in RAGScanner().scan(tmp_path).components)
    assert refs == ["rag:env-pinecone:.env", "rag:env-pinecone:.env.example"]


# SHADOWSCAN

class TestShadowScan:
    def test_symlinked_report_is_refused(self, tmp_path):
        real = tmp_path / "real.json"
        real.write_text(json.dumps([{"kind": "mcp-server", "title": "svc"}]), encoding="utf-8")
        link = tmp_path / "report.json"
        link.symlink_to(real)
        result = ShadowScanImporter(trusted_report=link).scan(tmp_path)
        assert result.scan_failures
        assert not result.components

    def test_raw_fields_are_not_copied_into_properties(self, tmp_path):
        report = tmp_path / "report.json"
        finding = {
            "kind": "mcp-server",
            "title": "svc",
            "risk": {"level": "low"},
            "raw_secret": "CANARY-RAW-VALUE",
        }
        report.write_text(json.dumps([finding]), encoding="utf-8")
        components = ShadowScanImporter().import_report(report)
        assert components
        assert "CANARY-RAW-VALUE" not in repr(components)

    def test_discovery_without_risk_level_is_unassessed(self, tmp_path):
        report = tmp_path / "report.json"
        report.write_text(json.dumps([{"kind": "mcp-server", "title": "svc"}]), encoding="utf-8")
        components = ShadowScanImporter().import_report(report)
        unassessed = [
            r for c in components for r in c.risks if r.category == "unassessed-discovery"
        ]
        assert len(unassessed) == 1
        assert unassessed[0].severity == RiskSeverity.MEDIUM


# HIDDEN CHARACTERS

class TestHiddenCharacters:
    def test_bidi_and_tag_characters_are_flagged(self):
        bidi = find_hidden_characters("a‮b")
        assert [(h.codepoint, h.kind) for h in bidi] == [("U+202E", "bidi-control")]
        tag = find_hidden_characters("x\U000e0041")
        assert [(h.codepoint, h.kind) for h in tag] == [("U+E0041", "tag-character")]

    def test_joiners_and_variation_selectors_are_not_flagged(self):
        assert find_hidden_characters("‍️") == []

    def test_prompt_bidi_control_is_high(self):
        risks = detect_invisible_characters("Always use TypeScript.‮", "rules.md")
        assert [r.severity for r in risks] == [RiskSeverity.HIGH]

    def test_prompt_scanner_records_high_risk_for_bidi(self, tmp_path):
        (tmp_path / "CLAUDE.md").write_text("Be kind.‮", encoding="utf-8")
        comp = PromptScanner().scan(tmp_path).components[0]
        assert any(
            r.severity == RiskSeverity.HIGH and r.category == "hidden-characters"
            for r in comp.risks
        )


# REDACTION

class TestRedaction:
    def test_redact_string_removes_key_token_password_and_url_parts(self):
        aws = "AKIA" + "IOSFODNN7EXAMPLE"
        github = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        text = f"key={aws} tok={github} password=hunter2"
        redacted = redact_string(text)
        assert aws not in redacted
        assert github not in redacted
        assert "hunter2" not in redacted
        assert "[redacted]" in redacted

    def test_redact_string_drops_url_userinfo_and_query(self):
        redacted = redact_string("https://user:pw@example.com/private/path?token=abc123#frag")
        assert "user:pw" not in redacted
        assert "abc123" not in redacted
        assert "frag" not in redacted
        assert "example.com/private/path" in redacted

    def test_redact_aibom_leaves_definition_hash_and_description_text(self):
        digest = "sha256:" + "c" * 64
        tool = ToolComponent(
            bom_ref="tool:t",
            name="t",
            description_text="password=hunter2 is the admin password",
            definition_hash=digest,
            definition_hash_version=VERSION_PIN,
            description="token=abcdefgh12345678 visible",
        )
        bom = _bom(tool)
        changed = redact_aibom(bom)
        out = bom.components[0]
        assert changed >= 1
        assert out.description_text == "password=hunter2 is the admin password"
        assert out.definition_hash == digest
        assert "abcdefgh12345678" not in (out.description or "")


# REPRODUCIBLE OUTPUT

class TestReproducibleOutput:
    def test_source_date_epoch_gives_equal_serial_and_timestamp(self, monkeypatch):
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
        first = AIBOM()
        second = AIBOM()
        first.finalize()
        second.finalize()
        assert first.metadata.serial_number == second.metadata.serial_number
        assert first.metadata.timestamp == second.metadata.timestamp
        assert first.metadata.timestamp == datetime.fromtimestamp(1700000000, UTC)

    def test_finalize_keeps_existing_timestamp_without_epoch(self, monkeypatch):
        monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
        stamp = datetime(2020, 1, 2, 3, 4, 5, tzinfo=UTC)
        bom = AIBOM()
        bom.metadata.timestamp = stamp
        bom.finalize()
        assert bom.metadata.timestamp == stamp


# SAFE WRITES

class TestSafeWrites:
    def test_refuses_symlink_destination(self, tmp_path):
        real = tmp_path / "real.json"
        real.write_text("keep", encoding="utf-8")
        link = tmp_path / "link.json"
        link.symlink_to(real)
        with pytest.raises(OSError):
            write_text_safely(link, "replace")
        assert real.read_text(encoding="utf-8") == "keep"

    def test_overwrite_is_atomic_and_leaves_no_temp_files(self, tmp_path):
        target = tmp_path / "out.json"
        write_text_safely(target, "one")
        write_text_safely(target, "two")
        assert target.read_text(encoding="utf-8") == "two"
        assert [p.name for p in tmp_path.iterdir()] == ["out.json"]

    def test_creates_owner_only_files(self, tmp_path):
        if os.name == "nt":
            pytest.skip("POSIX file modes only")
        target = tmp_path / "out.json"
        write_text_safely(target, "x")
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_refuses_overwrite_when_disabled(self, tmp_path):
        target = tmp_path / "out.json"
        target.write_text("x", encoding="utf-8")
        with pytest.raises(FileExistsError):
            write_text_safely(target, "y", overwrite=False)
        assert target.read_text(encoding="utf-8") == "x"


# ACTION AND HOOK CONTRACTS

class TestContracts:
    def test_action_scanner_allowlist_equals_registry(self):
        text = (ROOT / "action.yml").read_text(encoding="utf-8")
        match = re.search(r'case "\$name" in ([a-z0-9_|]+)\)', text)
        assert match is not None
        assert set(match.group(1).split("|")) == set(SCANNER_NAMES)

    @pytest.mark.parametrize("name", ["fail-on-validation-error", "upload-artifact", "policy-file"])
    def test_action_declares_input(self, name):
        text = (ROOT / "action.yml").read_text(encoding="utf-8")
        assert re.search(rf"^  {re.escape(name)}:", text, re.MULTILINE)

    def test_pre_commit_hook_has_no_fixed_tmp_path(self):
        text = (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
        assert "/tmp/" not in text


# GENERATORS

class TestGenerators:
    def test_sarif_execution_unsuccessful_on_scan_failure(self):
        bom = _bom(claim=_claim(scan_failures=["mcp: malformed JSON"]))
        run = SARIFGenerator().generate(bom)["runs"][0]
        assert run["invocations"][0]["executionSuccessful"] is False

    def test_sarif_execution_successful_when_clean(self):
        run = SARIFGenerator().generate(_bom(claim=_claim()))["runs"][0]
        assert run["invocations"][0]["executionSuccessful"] is True

    def test_cyclonedx_has_dependencies_and_string_property_values(self):
        bom = _bom(
            ToolComponent(bom_ref="tool:a", name="a"),
            ToolComponent(bom_ref="tool:b", name="b"),
            claim=_claim(),
        )
        bom.add_dependency(
            DependencyEdge(source_ref="tool:a", target_ref="tool:b", relationship="invokes")
        )
        out = CycloneDXGenerator().generate(bom)
        assert {"ref": "tool:a", "dependsOn": ["tool:b"]} in out["dependencies"]
        values = [
            node["value"]
            for node in _walk_dicts(out)
            if "name" in node and "value" in node
        ]
        assert values
        assert all(isinstance(value, str) for value in values)

    def test_spdx_output_is_deterministic_and_relationships_are_camel_case(self, monkeypatch):
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")

        def build() -> AIBOM:
            bom = _bom(
                ToolComponent(bom_ref="tool:a", name="a"),
                ToolComponent(bom_ref="tool:b", name="b"),
                claim=_claim(),
            )
            bom.add_dependency(
                DependencyEdge(source_ref="tool:a", target_ref="tool:b", relationship="invokes")
            )
            return bom

        first = SPDXGenerator().generate(build())
        second = SPDXGenerator().generate(build())
        assert first == second
        relationships = [n for n in _walk_dicts(first) if n.get("type") == "Relationship"]
        assert relationships
        for rel in relationships:
            assert rel["relationshipType"] == "dependsOn"
