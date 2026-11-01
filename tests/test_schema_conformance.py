"""The native JSON Schema must describe exactly what the tool emits.

Regression for NS-07: the hand-written schema omitted component types the
scanners produce, so real `scan` output failed the project's own schema.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

from click.testing import CliRunner  # noqa: E402

from nexus_symbiote.cli import main  # noqa: E402
from nexus_symbiote.core import models as m  # noqa: E402
from nexus_symbiote.core.aibom import AIBOM  # noqa: E402
from nexus_symbiote.core.enums import ComponentType  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "schemas" / "nexus-symbiote-aibom-1.0.schema.json").read_text())

COMPONENT_CLASSES = [
    m.AgentComponent,
    m.MCPServerComponent,
    m.MCPClientComponent,
    m.ToolComponent,
    m.ModelComponent,
    m.PromptComponent,
    m.GuardrailComponent,
    m.MemoryStoreComponent,
    m.RAGSourceComponent,
    m.DataSourceComponent,
    m.RegistryEntryComponent,
    m.SkillPackageComponent,
    m.A2AClientComponent,
    m.A2AServerComponent,
    m.IDEAgentComponent,
    m.VerifiedExtensionComponent,
]


def _validator() -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(SCHEMA)


def test_schema_is_a_valid_metaschema() -> None:
    jsonschema.Draft202012Validator.check_schema(SCHEMA)


@pytest.mark.parametrize(
    "rel", ["schemas/examples/minimal-aibom.json", "examples/customer-support-agent.json"]
)
def test_shipped_examples_validate(rel: str) -> None:
    data = json.loads((ROOT / rel).read_text())
    assert list(_validator().iter_errors(data)) == []


def test_every_component_type_has_a_model_and_validates() -> None:
    covered = {cls(bom_ref="x", name="y").component_type for cls in COMPONENT_CLASSES}
    assert covered == set(ComponentType), "a ComponentType enum value has no model class"

    bom = AIBOM()
    for i, cls in enumerate(COMPONENT_CLASSES):
        bom.add_component(cls(bom_ref=f"c{i}", name=f"n{i}"))
    data = json.loads(bom.to_json())
    assert list(_validator().iter_errors(data)) == []


def test_live_scan_output_validates(tmp_path) -> None:
    # A normal scan emits an mcp-client component; its output must validate.
    (tmp_path / ".mcp.json").write_text('{"mcpServers":{"fs":{"command":"npx","args":["x"]}}}')
    out = tmp_path / "bom.json"
    CliRunner().invoke(main, ["scan", str(tmp_path), "-o", str(out)])
    data = json.loads(out.read_text())
    assert "mcp-client" in {c["component_type"] for c in data["components"]}
    assert list(_validator().iter_errors(data)) == []
