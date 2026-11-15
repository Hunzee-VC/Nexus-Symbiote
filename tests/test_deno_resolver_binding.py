"""Deno resolution changes cannot retain a trusted keyed baseline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV, MCPScanner

KEY = "synthetic-deno-binding-test-key-000000000000"
PACKAGE = "npm:trusted-mcp@1.2.3"


def _project(root: Path, options: list[str] | None = None) -> None:
    root.mkdir(exist_ok=True)
    (root / "CLAUDE.md").write_text("Fixed instructions.\n")
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "demo": {"command": "deno", "args": ["run", *(options or []), PACKAGE]}
                }
            }
        )
    )


def _scan(root: Path, output: Path) -> tuple[MCPServerComponent, int]:
    run = CliRunner().invoke(main, ["scan", str(root), "--no-project-policy", "-o", str(output)])
    assert output.is_file(), run.output
    server = next(c for c in AIBOM.load(output).components if isinstance(c, MCPServerComponent))
    return server, run.exit_code


def _gates(root: Path, baseline: Path, candidate: Path) -> list[int]:
    runner = CliRunner()
    results = [
        runner.invoke(main, ["diff", str(baseline), str(candidate), "--fail-on-alert"]),
        runner.invoke(
            main, ["validate", str(baseline), "--project", str(root), "--no-project-policy"]
        ),
        runner.invoke(main, ["risk", str(baseline), "--project", str(root), "--no-project-policy"]),
    ]
    return [run.exit_code for run in results]


@pytest.mark.parametrize(
    "options",
    [
        ["--config", "alternate.json"],
        ["--config=alternate.json"],
        ["-c", "alternate.json"],
        ["-calternate.json"],
        ["-c=alternate.json"],
        ["--config", "missing.json"],
        ["--config", "./deno.json"],
        ["--config", "sub/deno.jsonc"],
        ["--config", "${DENO_CONFIG}"],
        ["--no-config"],
        ["--import-map", "imports.json"],
        ["--import-map=imports.json"],
    ],
)
def test_explicit_config_selection_is_a_gap_with_or_without_a_binding_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, options: list[str]
) -> None:
    _project(tmp_path, options)
    (tmp_path / "alternate.json").write_text(json.dumps({"imports": {PACKAGE: "./first.ts"}}))
    for key in (None, KEY):
        if key is None:
            monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
        else:
            monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, key)
        result = MCPScanner().scan(tmp_path, config_only=True)
        [server] = [c for c in result.components if isinstance(c, MCPServerComponent)]
        assert server.package_url is None
        assert server.version_pinned is False
        assert any("launcher identity unknown" in gap for gap in result.surfaces_excluded)
        assert any(r.category == "launcher_identity" for r in server.risks)


def test_explicit_config_cannot_form_a_valid_project_baseline_even_with_a_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root = tmp_path / "project"
    _project(root, ["--config", "alternate.json"])
    selected = root / "alternate.json"
    selected.write_text(json.dumps({"imports": {PACKAGE: "./first.ts"}}))
    _, baseline_exit = _scan(root, tmp_path / "baseline.json")
    selected.write_text(json.dumps({"imports": {PACKAGE: "./second.ts"}}))
    _, candidate_exit = _scan(root, tmp_path / "candidate.json")
    assert baseline_exit == candidate_exit == 1
    assert _gates(root, tmp_path / "baseline.json", tmp_path / "candidate.json")[1:] == [1, 1]


@pytest.mark.parametrize("name", ["deno.json", "deno.jsonc"])
def test_swapping_import_targets_changes_private_binding_and_fails_all_gates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root = tmp_path / "project"
    _project(root)
    config = root / name
    config.write_text(
        json.dumps({"imports": {PACKAGE: "./first.ts", "private-alias": "./second.ts"}})
    )
    baseline, baseline_exit = _scan(root, tmp_path / "baseline.json")
    assert baseline_exit == 0
    assert (
        CliRunner()
        .invoke(
            main,
            [
                "validate",
                str(tmp_path / "baseline.json"),
                "--project",
                str(root),
                "--no-project-policy",
            ],
        )
        .exit_code
        == 0
    )
    config.write_text(
        json.dumps({"imports": {PACKAGE: "./second.ts", "private-alias": "./first.ts"}})
    )
    candidate, candidate_exit = _scan(root, tmp_path / "candidate.json")
    assert candidate_exit == 0
    assert candidate.properties["static_config_hash"] == baseline.properties["static_config_hash"]
    assert (
        candidate.properties["static_value_binding"] != baseline.properties["static_value_binding"]
    )
    assert candidate.properties["source_values_bound"] is True
    assert "private-alias" not in candidate.model_dump_json()
    assert "./first.ts" not in candidate.model_dump_json()
    assert _gates(root, tmp_path / "baseline.json", tmp_path / "candidate.json") == [1, 1, 1]


@pytest.mark.parametrize(
    "changed",
    [
        {"imports": {PACKAGE: "./first.ts", "renamed-private-alias": "./second.ts"}},
        {"imports": {PACKAGE: "./first.ts"}, "scopes": {"./": {"private-alias": "./second.ts"}}},
        {"scopes": {"./": {PACKAGE: "./second.ts", "private-alias": "./first.ts"}}},
    ],
)
def test_import_keys_and_scope_associations_are_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: dict
) -> None:
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    _project(tmp_path)
    config = tmp_path / "deno.json"
    original = {"imports": {PACKAGE: "./first.ts", "private-alias": "./second.ts"}}
    config.write_text(json.dumps(original))
    first = MCPScanner().scan(tmp_path, config_only=True).components[0]
    config.write_text(json.dumps(changed))
    second = MCPScanner().scan(tmp_path, config_only=True).components[0]
    assert first.properties["static_value_binding"] != second.properties["static_value_binding"]


def test_reordered_mapping_is_stable_and_old_profile_is_not_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root = tmp_path / "project"
    _project(root)
    config = root / "deno.json"
    config.write_text(
        json.dumps(
            {
                "imports": {PACKAGE: "./first.ts", "private-alias": "./second.ts"},
                "scopes": {"./scope/": {PACKAGE: "./third.ts", "private-scoped": "./fourth.ts"}},
            }
        )
    )
    baseline, _ = _scan(root, tmp_path / "baseline.json")
    config.write_text(
        "// comment\n"
        + json.dumps(
            {
                "scopes": {"./scope/": {"private-scoped": "./fourth.ts", PACKAGE: "./third.ts"}},
                "imports": {"private-alias": "./second.ts", PACKAGE: "./first.ts"},
            },
            indent=2,
        )
    )
    candidate, candidate_exit = _scan(root, tmp_path / "candidate.json")
    assert candidate_exit == 0
    assert (
        baseline.properties["static_value_binding"] == candidate.properties["static_value_binding"]
    )
    assert _gates(root, tmp_path / "baseline.json", tmp_path / "candidate.json") == [0, 0, 0]
    old = AIBOM.load(tmp_path / "baseline.json")
    server = next(c for c in old.components if isinstance(c, MCPServerComponent))
    server.properties["static_value_binding_profile"] = "nexus-symbiote/mcp-static-values/v2"
    old.save(tmp_path / "legacy.json")
    assert _gates(root, tmp_path / "legacy.json", tmp_path / "candidate.json") == [1, 1, 1]


@pytest.mark.parametrize(
    "resolver",
    [
        {"importMap": "imports.json"},
        {"imports": {PACKAGE: ["./first.ts", "./second.ts"]}},
        {"imports": {PACKAGE: None}},
        {"imports": "imports.json"},
        {"scopes": {"./": ["./first.ts"]}},
        {"scopes": {"./": {PACKAGE: None}}},
    ],
)
def test_uncollected_import_map_dependencies_and_shapes_are_gaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, resolver: dict
) -> None:
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    _project(tmp_path)
    (tmp_path / "deno.json").write_text(json.dumps(resolver))
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert any("Deno import" in gap for gap in result.surfaces_excluded)


def test_implicit_default_without_a_resolver_remains_supported(tmp_path: Path) -> None:
    _project(tmp_path)
    result = MCPScanner().scan(tmp_path, config_only=True)
    [server] = [c for c in result.components if isinstance(c, MCPServerComponent)]
    assert not result.scan_failures and not result.surfaces_excluded
    assert server.package_url == "pkg:npm/trusted-mcp@1.2.3"
