"""Collection stays fast on hostile inputs and keeps duplicate-component semantics."""

from __future__ import annotations

import json
import time
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import DependencyEdge
from nexus_symbiote.core.models import PromptComponent
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.registry import RegistryScanner


def test_container_image_pattern_is_linear_in_trailing_whitespace(tmp_path):
    # Two adjacent whitespace quantifiers made this quadratic: about 10 minutes
    # for this file, and over a day at the 4 MiB read limit.
    (tmp_path / "docker-compose.yml").write_text("services:\n  app:\n    image:" + " " * 300_000)
    started = time.monotonic()
    result = RegistryScanner().scan(tmp_path)
    assert time.monotonic() - started < 5
    assert not result.scan_failures


def test_container_image_pattern_still_finds_model_servers(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  llm:\n    image:   ollama/ollama:latest\n  web:\n    image: nginx:1.27\n"
    )
    (tmp_path / "Dockerfile").write_text("FROM vllm/vllm-openai:v0.6.0\n")
    names = {c.name for c in RegistryScanner().scan(tmp_path).components}
    assert names == {"ollama/ollama:latest", "vllm/vllm-openai:v0.6.0"}


def _scanners(*components: PromptComponent) -> dict[str, type[Scanner]]:
    def make(name: str, component: PromptComponent) -> type[Scanner]:
        class Fixed(Scanner):
            def scan(self, project_root: Path) -> ScanResult:
                # Independent copies, as two real collectors would return.
                return ScanResult(scanner_name=name, components=[component.model_copy(deep=True)])

        Fixed.name = name
        return Fixed

    return {f"s{i}": make(f"s{i}", c) for i, c in enumerate(components)}


def _scan(tmp_path: Path, monkeypatch, *components: PromptComponent) -> dict:
    scanners = _scanners(*components)
    monkeypatch.setattr("nexus_symbiote.cli._get_scanners", lambda: scanners)
    output = tmp_path / "bom.json"
    args = ["scan", str(tmp_path), "--report-only", "--no-project-policy", "-o", str(output)]
    for name in scanners:
        args += ["--scanner", name]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    return json.loads(output.read_text(encoding="utf-8"))


def test_identical_duplicate_from_two_collectors_is_kept_once(tmp_path, monkeypatch):
    prompt = PromptComponent(bom_ref="prompt:shared", name="shared.md")
    bom = _scan(tmp_path, monkeypatch, prompt, prompt)
    assert [c["bom_ref"] for c in bom["components"]].count("prompt:shared") == 1
    assert not any(
        "conflicting duplicate" in failure
        for failure in bom["metadata"]["completeness"]["scan_failures"]
    )
    (kept,) = [c for c in bom["components"] if c["bom_ref"] == "prompt:shared"]
    presence = kept["claims"]["repository_presence"]
    assert presence["collector"] == "s0" and presence["evidence_refs"] == ["collector:s1"]


def test_conflicting_duplicate_is_a_collection_failure(tmp_path, monkeypatch):
    first = PromptComponent(bom_ref="prompt:shared", name="shared.md")
    second = first.model_copy(update={"name": "other.md"})
    bom = _scan(tmp_path, monkeypatch, first, second)
    assert [c["name"] for c in bom["components"] if c["bom_ref"] == "prompt:shared"] == [
        "shared.md"
    ]
    assert (
        "s1: conflicting duplicate component prompt:shared"
        in bom["metadata"]["completeness"]["scan_failures"]
    )


def _scan_with_edge(tmp_path: Path, monkeypatch, edge: DependencyEdge) -> dict:
    class Dangling(Scanner):
        def scan(self, project_root: Path) -> ScanResult:
            return ScanResult(
                scanner_name="s0",
                components=[PromptComponent(bom_ref="prompt:only", name="only.md")],
                dependencies=[edge],
            )

    Dangling.name = "s0"
    monkeypatch.setattr("nexus_symbiote.cli._get_scanners", lambda: {"s0": Dangling})
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(tmp_path),
            "--report-only",
            "--no-project-policy",
            "--scanner",
            "s0",
            "-o",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    return json.loads(output.read_text(encoding="utf-8"))


def test_conflicting_duplicate_collector_is_not_reported_completed(tmp_path, monkeypatch):
    first = PromptComponent(bom_ref="prompt:shared", name="shared.md")
    second = first.model_copy(update={"name": "other.md"})
    coverage = _scan(tmp_path, monkeypatch, first, second)["metadata"]["completeness"]
    assert coverage["scanner_status"]["s1"] == "failed"
    assert "s1" not in coverage["collectors_completed"]
    assert coverage["collectors_completed"] == ["s0"]


def test_dangling_dependency_collector_is_not_reported_completed(tmp_path, monkeypatch):
    edge = DependencyEdge(
        source_ref="prompt:only", target_ref="prompt:absent", relationship="invokes"
    )
    coverage = _scan_with_edge(tmp_path, monkeypatch, edge)["metadata"]["completeness"]
    assert "s0: dependency endpoint was not imported" in coverage["scan_failures"]
    assert coverage["scanner_status"]["s0"] == "failed"
    assert coverage["collectors_completed"] == []


def test_only_orchestration_failures_still_downgrade_inventory_assurance(tmp_path, monkeypatch):
    edge = DependencyEdge(
        source_ref="prompt:only", target_ref="prompt:absent", relationship="invokes"
    )
    coverage = _scan_with_edge(tmp_path, monkeypatch, edge)["metadata"]["completeness"]
    assert coverage["assurance_level"] == "declared"


def test_clean_collector_is_still_reported_completed(tmp_path, monkeypatch):
    prompt = PromptComponent(bom_ref="prompt:shared", name="shared.md")
    coverage = _scan(tmp_path, monkeypatch, prompt)["metadata"]["completeness"]
    assert coverage["scanner_status"]["s0"] == "complete"
    assert coverage["collectors_completed"] == ["s0"]
