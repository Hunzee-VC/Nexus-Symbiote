"""Files and fields that decide what is installed are read, or are coverage gaps."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.registry import RegistryScanner

SHA512 = "sha512-" + base64.b64encode(b"x" * 64).decode()


def _write(root: Path, files: dict[str, object]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "AGENTS.md").write_text("Keep receipts.\n")
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else json.dumps(content))
    return root


def _scan(project: Path, out: Path, *extra: str) -> tuple[int, dict]:
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(out), *extra]
    )
    return result.exit_code, json.loads(out.read_text()) if out.exists() else {}


def _lock(resolved: str, version: str = "4.52.0") -> dict:
    record = {"version": version, "resolved": resolved, "integrity": SHA512}
    return {"lockfileVersion": 3, "packages": {"node_modules/openai": record}}


NPMJS = "https://registry.npmjs.org/openai/-/openai-4.52.0.tgz"


def test_npm_shrinkwrap_is_the_lock_source_when_present(tmp_path):
    # npm installs from npm-shrinkwrap.json and ignores package-lock.json.
    project = _write(
        tmp_path / "project",
        {
            "package.json": {"dependencies": {"openai": "^4.52.0"}},
            "package-lock.json": _lock(NPMJS),
        },
    )
    runner = CliRunner()
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o"]
    assert runner.invoke(main, [*args, str(tmp_path / "a.json")]).exit_code == 0
    (project / "npm-shrinkwrap.json").write_text(
        json.dumps(_lock("https://evil.example/openai-4.52.0.tgz"))
    )
    result = RegistryScanner().scan(project)
    (component,) = result.components
    assert component.source_path == "npm-shrinkwrap.json"
    assert component.registry_uri == "https://evil.example"
    assert component.properties["lockfile_record"].startswith("npm-shrinkwrap.json#/")
    assert "npm-shrinkwrap.json" in result.surfaces_scanned
    assert "package-lock.json" not in result.surfaces_scanned
    assert runner.invoke(main, [*args, str(tmp_path / "b.json")]).exit_code == 0
    diff = runner.invoke(
        main, ["diff", str(tmp_path / "a.json"), str(tmp_path / "b.json"), "--fail-on-alert"]
    )
    assert diff.exit_code == 1, diff.output
    assert "registry_uri" in diff.output


def test_an_unreadable_shrinkwrap_is_not_replaced_by_package_lock(tmp_path):
    project = _write(
        tmp_path / "project",
        {
            "package.json": {"dependencies": {"openai": "^4.52.0"}},
            "package-lock.json": _lock(NPMJS),
        },
    )
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(_lock(NPMJS)))
    (project / "npm-shrinkwrap.json").symlink_to(outside)
    result = RegistryScanner().scan(project)
    assert result.scan_failures
    (component,) = result.components
    assert component.source_path == "package.json"
    assert "lockfile_record" not in component.properties


@pytest.mark.parametrize(
    "fields",
    [
        {"overrides": {"openai": "4.0.0"}},
        {"overrides": {"some-lib": {"openai": "4.0.0"}}},
        {"overrides": {"openai@^4": "npm:@evil/openai@1.0.0"}},
        {"resolutions": {"**/openai": "4.0.0"}},
        {"resolutions": {"some-lib/openai": "4.0.0"}},
        {"pnpm": {"overrides": {"some-lib>openai": "4.0.0"}}},
        {"pnpm": {"overrides": {"openai@<4": "4.0.0"}}},
        # An override that installs an AI package in place of another one.
        {"overrides": {"some-lib": "npm:@anthropic-ai/sdk@1.0.0"}},
    ],
)
def test_overrides_of_inventoried_packages_are_a_coverage_gap(tmp_path, fields):
    project = _write(
        tmp_path / "project",
        {"package.json": {"dependencies": {"openai": "4.52.0", "some-lib": "1.0.0"}, **fields}},
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == ["package.json: dependency override not translated"]
    if "openai" in json.dumps(fields):
        # What npm installs for it is not what package.json declares.
        assert result.components[0].package_url is None
    code, document = _scan(project, tmp_path / "bom.json")
    assert code == 1
    assert document["metadata"]["completeness"]["scanner_status"]["registry"] == "partial"


def test_an_override_of_another_package_is_not_a_gap(tmp_path):
    project = _write(
        tmp_path,
        {
            "package.json": {
                "dependencies": {"openai": "4.52.0"},
                "overrides": {"semver": "7.6.0"},
                "resolutions": {"**/lodash": "4.17.21"},
            }
        },
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [] and result.scan_failures == []
    assert result.components[0].package_url == "pkg:npm/openai@4.52.0"


def test_workspaces_are_a_coverage_gap(tmp_path):
    project = _write(
        tmp_path,
        {
            "package.json": {"workspaces": ["packages/*"]},
            "packages/agent/package.json": {"dependencies": {"openai": "4.52.0"}},
        },
    )
    assert RegistryScanner().scan(project).surfaces_excluded == [
        "package.json: workspaces not followed"
    ]


def test_peer_dependencies_are_read_with_npm_precedence(tmp_path):
    # npm 7 and later install peer dependencies; a later section's spec wins.
    project = _write(
        tmp_path,
        {
            "package.json": {
                "peerDependencies": {"openai": "^4.0.0", "@anthropic-ai/sdk": "0.30.1"},
                "devDependencies": {"openai": "4.52.0"},
            }
        },
    )
    by_ref = {c.bom_ref: c for c in RegistryScanner().scan(project).components}
    assert by_ref["registry:npm/@anthropic-ai/sdk"].version == "0.30.1"
    openai = by_ref["registry:npm/openai"]
    assert openai.version == "4.52.0" and openai.risks == []
    assert openai.properties["declarations"] == [
        "devDependencies: 4.52.0",
        "peerDependencies: ^4.0.0",
    ]


@pytest.mark.parametrize(
    "spec,record",
    [
        ("npm:openai@4.52.0", None),
        ("npm:openai@4.52.0", {"name": "openai"}),
        ("npm:@anthropic-ai/sdk@0.30.1", None),
    ],
)
def test_an_ai_package_behind_a_non_ai_alias_is_inventoried_by_its_target(tmp_path, spec, record):
    files: dict[str, object] = {"package.json": {"dependencies": {"app-utils": spec}}}
    target, version = spec[4:].rsplit("@", 1)
    if record is not None:
        tarball = f"https://registry.npmjs.org/{target}/-/{target}-{version}.tgz"
        files["package-lock.json"] = {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/app-utils": {
                    **record,
                    "version": version,
                    "resolved": tarball,
                    "integrity": SHA512,
                }
            },
        }
    project = _write(tmp_path, files)
    result = RegistryScanner().scan(project)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    (component,) = result.components
    assert component.bom_ref == "registry:npm/app-utils"
    assert component.name == target and component.version == version
    assert component.properties["npm_alias"] == "app-utils"
    assert component.package_url is not None and target.replace("@", "%40") in (
        component.package_url
    )
    assert [r.category for r in component.risks] == ["package_alias"]


def test_a_lock_record_naming_an_ai_package_under_another_key_is_visible(tmp_path):
    project = _write(
        tmp_path,
        {
            "package.json": {"dependencies": {"app-utils": "^1.0.0"}},
            "package-lock.json": {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/app-utils": {
                        "name": "openai",
                        "version": "4.52.0",
                        "resolved": NPMJS,
                        "integrity": SHA512,
                    }
                },
            },
        },
    )
    result = RegistryScanner().scan(project)
    assert [c.bom_ref for c in result.components] == ["registry:npm/app-utils"]
    assert result.surfaces_excluded == ["package-lock.json: aliased package identity is unresolved"]


@pytest.mark.parametrize(
    "spec",
    ["github:attacker/openai-node", "attacker/openai-node", "file:../openai", "https://h/x.tgz"],
)
def test_an_unclassified_source_without_a_lock_record_is_a_gap(tmp_path, spec):
    # npm installs the source under the key, whatever package it holds.
    project = _write(tmp_path, {"package.json": {"dependencies": {"app-utils": spec}}})
    result = RegistryScanner().scan(project)
    assert result.components == []
    assert result.surfaces_excluded == ["package.json: git, URL or path dependency not classified"]


def test_a_source_whose_lock_record_names_another_package_is_classified(tmp_path):
    project = _write(
        tmp_path,
        {
            "package.json": {"dependencies": {"app-utils": "github:org/app-utils#v1"}},
            "package-lock.json": {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/app-utils": {
                        "version": "1.0.0",
                        "resolved": "git+ssh://git@github.com/org/app-utils.git#" + "a" * 40,
                    }
                },
            },
        },
    )
    result = RegistryScanner().scan(project)
    assert result.components == [] and result.surfaces_excluded == []


@pytest.mark.parametrize(
    "body,gap",
    [
        (
            '[tool.uv.sources]\nopenai = { git = "https://github.com/attacker/openai-python", '
            'rev = "abc" }\n',
            "pyproject.toml: uv source not translated",
        ),
        (
            '[tool.uv.sources]\nopenai = { index = "pytorch" }\n',
            "pyproject.toml: uv source not translated",
        ),
        (
            '[tool.uv]\noverride-dependencies = ["openai @ https://evil.example/o.whl"]\n',
            "pyproject.toml: uv override or constraint not followed",
        ),
        (
            '[tool.uv]\nconstraint-dependencies = ["openai<2"]\n',
            "pyproject.toml: uv override or constraint not followed",
        ),
        (
            '[tool.pdm.resolution.overrides]\nopenai = "1.0.0"\n',
            "pyproject.toml: PDM override not followed",
        ),
    ],
)
def test_uv_and_pdm_replacements_of_inventoried_packages_are_gaps(tmp_path, body, gap):
    project = _write(
        tmp_path / "project",
        {
            "pyproject.toml": '[project]\nname = "agent"\nversion = "0.1.0"\n'
            'dependencies = ["openai==1.51.0"]\n' + body
        },
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [gap] and result.scan_failures == []
    (component,) = result.components
    if "constraint" not in body:
        # What is installed is not what [project] declares, so no exact identity.
        assert component.package_url is None and component.registry_uri is None
    code, document = _scan(project, tmp_path / "bom.json")
    assert code == 1
    assert document["metadata"]["completeness"]["scanner_status"]["registry"] == "partial"


def test_uv_sources_for_other_packages_are_not_gaps(tmp_path):
    project = _write(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "agent"\nversion = "0.1.0"\n'
            'dependencies = ["openai==1.51.0", "mylib"]\n'
            '[tool.uv.sources]\nmylib = { path = "../mylib" }\n'
        },
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == []
    assert result.components[0].package_url == "pkg:pypi/openai@1.51.0"


def test_dependency_groups_build_requirements_and_tool_dev_dependencies_are_read(tmp_path):
    project = _write(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "agent"\nversion = "0.1.0"\ndependencies = []\n'
            '[dependency-groups]\ndev = ["openai==1.51.0", {include-group = "Test"}]\n'
            'test = ["mcp>=1.2"]\n'
            '[build-system]\nrequires = ["torch==2.3.0", "setuptools"]\n'
            '[tool.uv]\ndev-dependencies = ["langgraph==0.2.0"]\n'
            '[tool.pdm.dev-dependencies]\nlint = ["anthropic==0.30.0"]\n'
        },
    )
    result = RegistryScanner().scan(project)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert sorted(c.name for c in result.components) == [
        "anthropic",
        "langgraph",
        "mcp",
        "openai",
        "torch",
    ]


@pytest.mark.parametrize(
    "body",
    [
        '[dependency-groups]\ndev = "openai"\n',
        '[dependency-groups]\ndev = [{include-group = "missing"}]\n',
        "[dependency-groups]\ndev = [1]\n",
    ],
)
def test_invalid_dependency_groups_are_a_failure(tmp_path, body):
    _write(tmp_path, {"pyproject.toml": body})
    assert RegistryScanner().scan(tmp_path).scan_failures == [
        "pyproject.toml: invalid dependency groups"
    ]


@pytest.mark.parametrize(
    "lockfiles,ecosystem",
    [
        (["uv.lock"], "pypi"),
        (["poetry.lock", "pdm.lock"], "pypi"),
        (["Pipfile.lock"], "pypi"),
        (["yarn.lock"], "npm"),
        (["pnpm-lock.yaml", "bun.lockb"], "npm"),
        (["bun.lock"], "npm"),
    ],
)
def test_lockfiles_the_collector_cannot_read_are_a_low_finding(tmp_path, lockfiles, ecosystem):
    # The declarations are read, so coverage stays complete; that the resolution is
    # not is visible on each package it may affect.
    files: dict[str, object] = {
        "requirements.txt": "openai==1.51.0\n",
        "package.json": {"dependencies": {"openai": "4.52.0"}},
    }
    files.update(dict.fromkeys(lockfiles, ""))
    project = _write(tmp_path / "project", files)
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [] and result.scan_failures == []
    for component in result.components:
        findings = [r for r in component.risks if r.category == "lockfile_unread"]
        if component.registry_type == ecosystem:
            (finding,) = findings
            assert finding.severity.value == "low"
            assert all(name in finding.detail for name in lockfiles)
        else:
            assert findings == []
    code, _ = _scan(project, tmp_path / "bom.json")
    assert code == 0


def test_a_pipfile_is_a_coverage_gap(tmp_path):
    _write(tmp_path, {"Pipfile": '[packages]\nopenai = "*"\n'})
    assert RegistryScanner().scan(tmp_path).surfaces_excluded == ["Pipfile: dependencies not read"]


COMPOSE_NAMES = [
    "compose.yaml",
    "compose.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.override.yml",
    "compose.override.yaml",
    "docker-compose.override.yml",
    "docker-compose.override.yaml",
]


@pytest.mark.parametrize("name", COMPOSE_NAMES)
def test_every_file_compose_reads_by_default_is_read(tmp_path, name):
    _write(tmp_path, {name: "services:\n  llm:\n    image: ollama/ollama:0.5.7\n"})
    result = RegistryScanner().scan(tmp_path)
    assert [(c.name, c.source_path) for c in result.components] == [("ollama/ollama:0.5.7", name)]
    assert name in result.surfaces_scanned


def test_a_compose_override_that_swaps_an_image_is_drift(tmp_path):
    project = _write(
        tmp_path / "project",
        {"docker-compose.yml": "services:\n  llm:\n    image: ollama/ollama:0.5.7\n"},
    )
    runner = CliRunner()
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o"]
    assert runner.invoke(main, [*args, str(tmp_path / "a.json")]).exit_code == 0
    (project / "compose.override.yaml").write_text(
        "services:\n  llm:\n    image: attacker.example/ollama/ollama:0.5.7\n"
    )
    assert runner.invoke(main, [*args, str(tmp_path / "b.json")]).exit_code == 0
    diff = runner.invoke(
        main, ["diff", str(tmp_path / "a.json"), str(tmp_path / "b.json"), "--fail-on-alert"]
    )
    assert diff.exit_code == 1, diff.output
    assert "attacker.example/ollama/ollama:0.5.7" in diff.output


def test_the_same_image_in_several_files_is_one_component(tmp_path):
    project = _write(
        tmp_path / "project",
        {
            "Dockerfile": "FROM ollama/ollama:0.5.7\n",
            "Dockerfile.agent": "FROM ollama/ollama:0.5.7\n",
            "compose.yaml": "services:\n  llm:\n    image: ollama/ollama:0.5.7\n",
        },
    )
    result = RegistryScanner().scan(project)
    assert result.scan_failures == []
    (component,) = result.components
    assert component.source_path == "Dockerfile"
    assert component.properties["source_paths"] == [
        "Dockerfile",
        "Dockerfile.agent",
        "compose.yaml",
    ]
    code, document = _scan(project, tmp_path / "bom.json")
    assert code == 0, document["metadata"]["completeness"]
    assert not any(
        "conflicting duplicate" in failure
        for failure in document["metadata"]["completeness"]["scan_failures"]
    )


DIGEST = "a" * 64


@pytest.mark.parametrize(
    ("compose", "expected"),
    [
        # Quotes are YAML syntax, not part of the image.
        (f'services:\n  a:\n    image: "vllm/vllm-openai@sha256:{DIGEST}"\n', []),
        ("services:\n  a:\n    image: 'ollama/ollama:latest'\n", ["version_pinning"]),
        ('services:\n  a: {"image": "ollama/ollama:latest"}\n', ["version_pinning"]),
        ("services:\n  a:\n    image : ollama/ollama:0.5.7\n", ["mutable_image_tag"]),
        ("services:\n  a:\n    image: >-\n      ollama/ollama:0.5.7\n", ["mutable_image_tag"]),
        ("services:\n  a:\n    image: !override ollama/ollama:0.5.7\n", ["mutable_image_tag"]),
        (
            "x-base: &base\n  image: ollama/ollama:0.5.7\nservices:\n  a:\n    <<: *base\n",
            ["mutable_image_tag"],
        ),
        (
            "x-base: &base\n  image: ollama/ollama:1\nservices:\n"
            "  a:\n    <<: *base\n    image: ollama/ollama:0.5.7\n",
            ["mutable_image_tag"],
        ),
    ],
)
def test_compose_images_are_read_as_yaml(tmp_path, compose, expected):
    _write(tmp_path, {"docker-compose.yml": compose})
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    (component,) = result.components
    assert '"' not in component.name and "'" not in component.name
    assert component.name in {
        f"vllm/vllm-openai@sha256:{DIGEST}",
        "ollama/ollama:latest",
        "ollama/ollama:0.5.7",
    }
    assert [r.category for r in component.risks] == expected


def test_text_that_is_not_a_service_image_is_not_a_component(tmp_path):
    _write(
        tmp_path,
        {
            "docker-compose.yml": "services:\n  web:\n    image: nginx:1.27\n"
            "    # image: ollama/ollama:old\n"
            "    environment:\n      - SMTP_FROM=model-alerts@corp.example\n"
            '    command: ["FROM", "ollama/ollama:2"]\n'
            "  reset:\n    image: !reset null\n"
            "x-unused:\n  image: ollama/ollama:3\n"
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.components == [] and result.surfaces_excluded == []


@pytest.mark.parametrize(
    ("service", "gap"),
    [
        (
            "image: ollama/ollama:${TAG:-latest}",
            "docker-compose.yml: image substitution not resolved",
        ),
        ("build: ./agent", "docker-compose.yml: build context not followed"),
        (
            "build:\n      context: .\n      dockerfile: docker/Dockerfile",
            "docker-compose.yml: build context not followed",
        ),
        (
            "extends:\n      file: common.yaml\n      service: base",
            "docker-compose.yml: extends not followed",
        ),
        ("image: !custom ollama/ollama:1", "docker-compose.yml: tagged image value not resolved"),
    ],
)
def test_compose_forms_that_are_not_followed_are_gaps(tmp_path, service, gap):
    _write(tmp_path, {"docker-compose.yml": f"services:\n  a:\n    {service}\n"})
    assert RegistryScanner().scan(tmp_path).surfaces_excluded == [gap]


def test_compose_include_is_a_gap_and_root_builds_are_covered(tmp_path):
    _write(
        tmp_path,
        {
            "docker-compose.yml": "include:\n  - other.yaml\nservices:\n  a:\n    build: .\n"
            "  b:\n    build:\n      context: ./\n      dockerfile: ./Dockerfile.agent\n",
            "Dockerfile": "FROM ollama/ollama:0.5.7\n",
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded == ["docker-compose.yml: include not followed"]
    assert [c.name for c in result.components] == ["ollama/ollama:0.5.7"]


def test_an_inline_dockerfile_is_read(tmp_path):
    _write(
        tmp_path,
        {
            "docker-compose.yml": "services:\n  a:\n    build:\n      dockerfile_inline: |\n"
            "        FROM ghcr.io/huggingface/text-generation-inference:2.0\n"
            "        RUN echo FROM ollama/ollama:1\n"
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert [c.name for c in result.components] == [
        "ghcr.io/huggingface/text-generation-inference:2.0"
    ]


@pytest.mark.parametrize(
    "compose",
    [
        "services: [1, 2]\n",
        "services:\n  a:\n    image: ollama/ollama:1\n    image: ollama/ollama:2\n",
        "services:\n  a:\n    <<: [1]\n",
        "- not a mapping\n",
        "services:\n  a: {image: [ollama, ollama]",
    ],
)
def test_compose_files_that_are_not_readable_mappings_fail(tmp_path, compose):
    _write(tmp_path, {"docker-compose.yml": compose})
    assert RegistryScanner().scan(tmp_path).scan_failures == [
        "docker-compose.yml: YAML mapping parse failed or unsupported"
    ]


def test_merge_keys_are_followed_once_per_mapping(tmp_path):
    # Each level merges the previous one twice: expanding every merge would take
    # 2**60 steps.
    levels = "".join(f"a{i}: &a{i} {{<<: [*a{i - 1}, *a{i - 1}]}}\n" for i in range(1, 60))
    _write(
        tmp_path,
        {
            "docker-compose.yml": "a0: &a0 {image: ollama/ollama:0.5.7}\n"
            + levels
            + "services:\n  s:\n    <<: *a59\n"
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert [c.name for c in result.components] == ["ollama/ollama:0.5.7"]


def test_a_mapping_that_merges_itself_is_a_gap(tmp_path):
    _write(
        tmp_path,
        {"docker-compose.yml": "services:\n  s: &s\n    <<: *s\n    image: ollama/ollama:1\n"},
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded == ["docker-compose.yml: YAML merge key cycle not followed"]
    assert [c.name for c in result.components] == ["ollama/ollama:1"]


def test_a_compose_file_with_too_many_tokens_fails(tmp_path):
    _write(
        tmp_path,
        {"docker-compose.yml": "services:\n" + "".join(f"  s{i}: {{}}\n" for i in range(9000))},
    )
    assert RegistryScanner().scan(tmp_path).scan_failures == [
        "docker-compose.yml: YAML mapping parse failed or unsupported"
    ]


def test_a_containerfile_is_read_like_a_dockerfile(tmp_path):
    _write(tmp_path, {"Containerfile": "FROM ollama/ollama:0.5.7\n"})
    result = RegistryScanner().scan(tmp_path)
    assert [(c.name, c.source_path) for c in result.components] == [
        ("ollama/ollama:0.5.7", "Containerfile")
    ]


def test_compose_models_are_inventoried_whatever_their_name(tmp_path):
    # Docker Model Runner pulls these as OCI artifacts; none matches an image keyword.
    _write(
        tmp_path,
        {
            "compose.yaml": "models:\n  chat:\n    model: ai/smollm2:360M-Q4_K_M\n"
            "  embed: ai/mxbai-embed-large\n"
            "services:\n  app:\n    image: nginx:1.27\n    models: [chat]\n"
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded == [] and result.scan_failures == []
    by_name = {c.name: c for c in result.components}
    assert sorted(by_name) == ["ai/mxbai-embed-large", "ai/smollm2:360M-Q4_K_M"]
    chat = by_name["ai/smollm2:360M-Q4_K_M"]
    assert chat.properties["artifact_type"] == "model"
    assert [r.category for r in chat.risks] == ["mutable_image_tag"]


@pytest.mark.parametrize(("target_name", "inventoried"), [("my-lib", False), ("openai", True)])
def test_a_linked_path_dependency_is_classified_by_the_package_it_links(
    tmp_path, target_name, inventoried
):
    # npm records a file: directory as a link; the entry it links to names the package.
    project = _write(
        tmp_path,
        {
            "package.json": {"dependencies": {"my-lib": "file:packages/my-lib"}},
            "package-lock.json": {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/my-lib": {"resolved": "packages/my-lib", "link": True},
                    "packages/my-lib": {"name": target_name, "version": "1.0.0"},
                },
            },
        },
    )
    result = RegistryScanner().scan(project)
    assert [c.bom_ref for c in result.components] == (
        ["registry:npm/my-lib"] if inventoried else []
    )
    if inventoried:
        assert result.surfaces_excluded == []
        assert [r.category for r in result.components[0].risks] == ["nonregistry_source"]
    else:
        assert result.surfaces_excluded == [] and result.scan_failures == []
