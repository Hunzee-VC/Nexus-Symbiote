"""Ratings and identities follow every declaration, and inventories do not depend on where
the tree is checked out."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import RegistryEntryComponent
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.package_identifiers import package_identifier
from nexus_symbiote.generators.validation import validate_cyclonedx
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.registry import RegistryScanner, parse_image_reference

DIGEST = "b" * 64


def _scan(tmp_path: Path, files: dict[str, str]) -> dict[str, RegistryEntryComponent]:
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    result = RegistryScanner().scan(tmp_path)
    return {c.bom_ref: c for c in result.components if isinstance(c, RegistryEntryComponent)}


def test_a_url_declaration_behind_a_pin_is_a_finding_and_no_package_url(tmp_path):
    # pip takes the explicit URL candidate, which satisfies ==1.51.0; the marker is
    # always true, so the pin cannot speak for what is installed.
    (component,) = _scan(
        tmp_path,
        {
            "requirements.txt": "openai==1.51.0\n"
            "openai @ https://evil.example/openai-1.51.0-py3-none-any.whl"
            ' ; python_version >= "3"\n'
        },
    ).values()
    assert component.package_url is None and component.registry_uri is None
    assert [(r.category, r.severity.value) for r in component.risks] == [
        ("nonregistry_source", "medium")
    ]
    assert "requirements.txt" in component.risks[0].detail


@pytest.mark.parametrize(
    ("line", "severity", "origin"),
    [
        (
            "openai @ git+https://github.com/openai/openai-python@main",
            "high",
            "git+https://github.com",
        ),
        (
            "openai @ git+https://github.com/openai/openai-python@" + "c" * 40,
            "medium",
            "git+https://github.com",
        ),
        (
            "openai @ https://files.example/openai-1.0.0-py3-none-any.whl",
            "medium",
            "https://files.example",
        ),
    ],
)
def test_a_url_or_vcs_declaration_names_its_origin(tmp_path, line, severity, origin):
    (component,) = _scan(tmp_path, {"requirements.txt": line + "\n"}).values()
    assert component.registry_uri == origin
    assert [(r.category, r.severity.value) for r in component.risks] == [
        ("nonregistry_source", severity)
    ]


def test_pins_only_under_markers_are_a_low_finding(tmp_path):
    (component,) = _scan(
        tmp_path,
        {
            "requirements.txt": "torch==2.3.0 ; sys_platform == 'linux'\n"
            "torch==2.2.2 ; sys_platform == 'darwin'\n"
        },
    ).values()
    assert [(r.category, r.severity.value) for r in component.risks] == [("version_pinning", "low")]
    assert component.package_url is None


@pytest.mark.parametrize(
    "files",
    [
        {"requirements.txt": "openai>=1.40\n", "requirements-lock.txt": "openai==1.51.0\n"},
        {"requirements.txt": "openai==1.51.0\n", "requirements-lock.txt": "openai>=1.40\n"},
        {
            "requirements.txt": "openai==1.51.0\n",
            "pyproject.toml": '[project]\nname = "a"\nversion = "1"\ndependencies = ["openai>=1.40"]\n',
        },
    ],
)
def test_the_rating_does_not_depend_on_which_file_is_read_first(tmp_path, files):
    (component,) = _scan(tmp_path, files).values()
    assert component.risks == []
    assert component.version == "==1.51.0"
    assert component.package_url == "pkg:pypi/openai@1.51.0"


PYPROJECT = '[project]\nname = "a"\nversion = "1"\n'


@pytest.mark.parametrize(
    ("files", "unsatisfied"),
    [
        # An extra or a marker keeps a declaration from being compared with the pin,
        # but pip installs it there all the same.
        (
            {
                "requirements.txt": "openai==1.40.0\n",
                "pyproject.toml": PYPROJECT
                + '[project.optional-dependencies]\nfast = ["openai>=1.50"]\n',
            },
            "pyproject.toml",
        ),
        (
            {
                "requirements.txt": "openai==1.40.0\n",
                "requirements-gpu.txt": 'openai>=1.50 ; python_version >= "3"\n',
            },
            "requirements-gpu.txt",
        ),
        # A clause too long to compare is not taken as satisfied.
        (
            {
                "requirements.txt": "openai==1.40.0\n",
                "requirements-dev.txt": "openai>=" + "1." * 70 + "0\n",
            },
            "requirements-dev.txt",
        ),
        # A pin resolves the ranges it satisfies, in any file or group.
        (
            {
                "requirements.txt": "openai==1.51.0\n",
                "pyproject.toml": PYPROJECT
                + '[project.optional-dependencies]\nfast = ["openai>=1.50"]\n',
            },
            None,
        ),
    ],
)
def test_a_range_the_pin_does_not_satisfy_is_a_finding_in_any_group(tmp_path, files, unsatisfied):
    (component,) = _scan(tmp_path, files).values()
    if unsatisfied is None:
        assert component.risks == []
        assert component.package_url == "pkg:pypi/openai@1.51.0"
        return
    assert component.version == "==1.40.0" and component.package_url is None
    assert [(r.category, r.severity.value) for r in component.risks] == [
        ("version_pinning", "medium")
    ]
    assert f"in {unsatisfied} that its exact pin does not satisfy" in component.risks[0].detail


def test_pins_that_disagree_give_no_package_url(tmp_path):
    (component,) = _scan(
        tmp_path,
        {"requirements.txt": "openai==1.51.0\n", "requirements-gpu.txt": "openai==1.52.0\n"},
    ).values()
    assert component.package_url is None
    assert [r.category for r in component.risks] == ["version_pinning"]


def test_a_name_that_ends_in_a_credential_word_keeps_its_version(tmp_path):
    (component,) = _scan(tmp_path, {"requirements.txt": "mcp-auth-token==1.2.3\n"}).values()
    assert component.properties["requested_requirement"] == "mcp-auth-token==1.2.3"


def test_requirement_hashes_are_recorded_and_their_change_is_drift(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    requirements = project / "requirements.txt"
    runner = CliRunner()
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o"]
    requirements.write_text(f"openai==1.51.0 \\\n    --hash=sha256:{'a' * 64}\n")
    assert runner.invoke(main, [*args, str(tmp_path / "a.json")]).exit_code == 0
    components = json.loads((tmp_path / "a.json").read_text())["components"]
    (openai,) = [c for c in components if c["bom_ref"] == "registry:pypi/openai"]
    assert openai["properties"]["requirement_hashes"] == [f"requirements.txt: sha256:{'a' * 64}"]
    for changed in (f"openai==1.51.0 --hash=sha256:{'d' * 64}\n", "openai==1.51.0\n"):
        requirements.write_text(changed)
        assert runner.invoke(main, [*args, str(tmp_path / "b.json")]).exit_code == 0
        diff = runner.invoke(
            main, ["diff", str(tmp_path / "a.json"), str(tmp_path / "b.json"), "--fail-on-alert"]
        )
        assert diff.exit_code == 1, diff.output


@pytest.mark.parametrize(
    ("image", "registry_type", "registry_uri", "repository"),
    [
        ("ollama/ollama:0.5.7", "docker-hub", "https://docker.io", "docker.io/ollama/ollama"),
        ("ollama:0.5.7", "docker-hub", "https://docker.io", "docker.io/library/ollama"),
        (
            "ghcr.io/huggingface/text-generation-inference:2.0",
            "oci",
            "https://ghcr.io",
            "ghcr.io/huggingface/text-generation-inference",
        ),
        (
            "nvcr.io/nvidia/tritonserver:24.01-py3",
            "oci",
            "https://nvcr.io",
            "nvcr.io/nvidia/tritonserver",
        ),
        ("localhost:5000/llama:1", "oci", "https://localhost:5000", "localhost:5000/llama"),
    ],
)
def test_images_record_the_registry_they_are_pulled_from(
    tmp_path, image, registry_type, registry_uri, repository
):
    (component,) = _scan(tmp_path, {"Dockerfile": f"FROM {image}\n"}).values()
    assert component.registry_type == registry_type
    assert component.registry_uri == registry_uri
    assert component.properties["image_repository"] == repository


def test_tags_that_look_like_credentials_are_not_collapsed(tmp_path):
    # Redaction turned both into corp/llama-token:***, one component for two images.
    compose = "services:\n  a:\n    image: corp/llama-token:1.0\n"
    compose += "  b:\n    image: corp/llama-token:2.0\n"
    by_ref = _scan(tmp_path, {"docker-compose.yml": compose})
    assert sorted(by_ref) == [
        "registry:docker/corp/llama-token:1.0",
        "registry:docker/corp/llama-token:2.0",
    ]


def test_a_digest_pinned_image_has_an_oci_package_url_that_exports(tmp_path):
    (component,) = _scan(
        tmp_path, {"Dockerfile": f"FROM ghcr.io/org/vllm-server:1.0@sha256:{DIGEST}\n"}
    ).values()
    assert component.package_url == (
        f"pkg:oci/vllm-server@sha256:{DIGEST}?repository_url=ghcr.io/org/vllm-server&tag=1.0"
    )
    assert component.risks == []
    assert package_identifier(component).status == "declared"
    document = CycloneDXGenerator().generate(AIBOM(components=[component]))
    assert validate_cyclonedx(document) == []
    assert document["components"][0]["purl"] == component.package_url


@pytest.mark.parametrize(
    ("digest", "pinned"),
    [
        ("sha256:" + "a" * 64, True),
        ("sha384:" + "a" * 96, True),
        ("sha512:" + "a" * 128, True),
        # Docker refuses these, though the reference grammar admits them.
        ("sha256:" + "a" * 32, False),
        ("sha256:" + "a" * 65, False),
        ("md5:" + "a" * 32, False),
        ("sha256:" + "A" * 64, False),
    ],
)
@pytest.mark.parametrize("prefix", ["", "${REGISTRY}/"])
def test_only_a_digest_docker_pulls_pins_an_image(tmp_path, digest, pinned, prefix):
    (component,) = _scan(
        tmp_path, {"Dockerfile": f"ARG REGISTRY\nFROM {prefix}ollama/ollama:0.5.7@{digest}\n"}
    ).values()
    if pinned:
        assert component.risks == []
        assert prefix or component.package_url.startswith(f"pkg:oci/ollama@{digest}?")
    else:
        assert [r.category for r in component.risks] == ["mutable_image_tag"]
        assert component.package_url is None


def test_an_oci_identity_needs_a_digest_docker_pulls():
    digest = "md5:" + "a" * 32
    component = _component(
        name=f"ghcr.io/org/vllm-server@{digest}",
        package_url=f"pkg:oci/vllm-server@{digest}?repository_url=ghcr.io/org/vllm-server",
    )
    assert package_identifier(component).status == "unavailable-invalid"


def _component(**changes) -> RegistryEntryComponent:
    values = {
        "bom_ref": "registry:docker/x",
        "name": f"ghcr.io/org/vllm-server@sha256:{DIGEST}",
        "registry_type": "oci",
        "package_url": f"pkg:oci/vllm-server@sha256:{DIGEST}?repository_url=ghcr.io/org/vllm-server",
    }
    return RegistryEntryComponent(**(values | changes))


@pytest.mark.parametrize(
    "changes",
    [
        {"package_url": f"pkg:oci/other@sha256:{DIGEST}"},
        {"package_url": f"pkg:oci/vllm-server@sha256:{'c' * 64}"},
        {"package_url": f"pkg:oci/vllm-server@sha256:{DIGEST}?repository_url=evil.example/x"},
        {"package_url": f"pkg:oci/vllm-server@sha256:{DIGEST}?tag=2.0"},
        {"name": "ghcr.io/org/vllm-server:1.0"},
        {"registry_type": "npm"},
        {"package_url": "pkg:golang/github.com/org/vllm-server@v1.0.0"},
        {
            "registry_type": "npm",
            "name": "openai",
            "version": "1.2.3",
            "registry_uri": "https://registry.npmjs.org",
            "package_url": "pkg:npm/openai@1.2.3?repository_url=https://evil.example",
        },
        {
            "registry_type": "pypi",
            "name": "openai",
            "version": "==1.2.3",
            "package_url": "pkg:pypi/openai@1.2.3?file_name=evil.whl",
        },
    ],
)
def test_identities_without_a_matching_rule_are_not_projected(changes):
    assert package_identifier(_component(**changes)).status == "unavailable-invalid"


def test_an_npm_identity_from_another_registry_names_it():
    component = _component(
        registry_type="npm",
        name="openai",
        version="1.2.3",
        registry_uri="https://npm.corp.example",
        package_url="pkg:npm/openai@1.2.3?repository_url=https://npm.corp.example",
    )
    assert package_identifier(component).status == "declared"


def _tree(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "requirements.txt").write_text("openai==1.51.0\nmcp>=1\n-r more.txt\n")
    (root / "pyproject.toml").write_text('[project]\nname = "a"\nversion = "1"\ndependencies = [\n')
    (root / "package.json").write_text('{"dependencies": {"@anthropic-ai/sdk": "^0.30.0"}}')
    (root / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/@anthropic-ai/sdk": {
                        "version": "0.30.1",
                        "resolved": "https://registry.npmjs.org/@anthropic-ai/sdk/-/sdk-0.30.1.tgz",
                    }
                },
            }
        )
    )
    (root / "Dockerfile").write_text("FROM ollama/ollama:0.5.7\n")
    (root / "compose.yaml").write_text("services:\n  llm:\n    image: ollama/ollama:0.5.7\n")
    (root / "docker-compose.yml").write_text("services: [\n")
    (root / "Dockerfile.agent").symlink_to(root / "Dockerfile")
    return root


def test_the_same_tree_at_two_locations_has_the_same_inventory(tmp_path):
    first = _tree(tmp_path / "one" / "project")
    second = tmp_path / "elsewhere" / "deeper" / "project"
    shutil.copytree(first, second, symlinks=True)
    results = [RegistryScanner().scan(root) for root in (first, second)]
    dumped = [
        (
            [c.model_dump(mode="json") for c in result.components],
            result.surfaces_scanned,
            result.surfaces_excluded,
            result.scan_failures,
        )
        for result in results
    ]
    assert dumped[0] == dumped[1]
    text = json.dumps(dumped[0])
    assert str(tmp_path) not in text
    assert all(not path.startswith(("/", "./")) for path in dumped[0][1])
    assert {c.source_path for c in results[0].components} <= {
        "requirements.txt",
        "package-lock.json",
        "Dockerfile",
    }
    assert any(failure.startswith("Dockerfile.agent: ") for failure in dumped[0][3])


def test_registry_components_carry_the_keys_an_agent_link_needs(tmp_path):
    # MCP launchers name registry packages as "<registry>:<name>"; the registry
    # components that declare the same packages carry the same type and name, and
    # an image's repository is normalised the way an OCI launcher's can be.
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.1.14"],
                    },
                    "fetch": {"command": "uvx", "args": ["mcp-server-fetch==2025.1.17"]},
                    "image": {"command": "docker", "args": ["run", "-i", "mcp/fetch:1.0"]},
                }
            }
        )
    )
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@modelcontextprotocol/server-filesystem": "2025.1.14"}}'
    )
    (tmp_path / "requirements.txt").write_text("mcp_server.fetch==2025.1.17\n")
    (tmp_path / "Dockerfile").write_text("FROM mcp/fetch:1.0\n")
    launchers = {
        getattr(c, "launcher_package", None) for c in MCPScanner().scan(tmp_path).components
    } - {None}
    registry = RegistryScanner().scan(tmp_path).components
    linked = set()
    for component in registry:
        assert isinstance(component, RegistryEntryComponent)
        assert component.properties["collection_mode"] != "imported-unverified-report"
        if component.registry_type in ("npm", "pypi"):
            linked.add(f"{component.registry_type}:{component.name}")
    images = {c.properties.get("image_repository") for c in registry}
    for launcher in launchers:
        kind, _, name = launcher.partition(":")
        if kind == "oci":
            reference = parse_image_reference(name)
            assert reference is not None and reference.repository in images
        else:
            assert launcher in linked
