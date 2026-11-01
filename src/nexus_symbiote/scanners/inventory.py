"""Connect only references supported by an explicit declaration or source record."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

import yaml

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AutonomyLevel
from nexus_symbiote.core.models import (
    AgentComponent,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
)
from nexus_symbiote.scanners.base import read_regular_text
from nexus_symbiote.utils.confined import hash_confined_file


def add_inventory_graph(bom: AIBOM, root: Path, failures: list[str]) -> None:
    def edge(source: str, target: str, kind: str) -> None:
        relation = DependencyEdge(
            source_ref=source, target_ref=target, relationship=kind, assurance_level="declared"
        )
        if relation not in bom.dependencies:
            bom.add_dependency(relation)

    for component in bom.components:
        if isinstance(component, MCPServerComponent):
            for tool in component.tool_refs:
                edge(component.bom_ref, tool, "declares-tool")

    manifest = root / "agent.yaml"
    if not manifest.exists() and not manifest.is_symlink():
        return
    try:
        doc = yaml.safe_load(read_regular_text(manifest))
        if (
            not isinstance(doc, dict)
            or not isinstance(doc.get("name"), str)
            or not doc["name"].strip()
        ):
            raise ValueError
        root_ref = "agent:" + quote(doc["name"], safe="")
        agent = AgentComponent(
            bom_ref=root_ref,
            name=doc["name"],
            version=str(doc["version"]) if "version" in doc else None,
            source_path="agent.yaml",
            autonomy_level=AutonomyLevel(doc.get("autonomy_level", "unknown")),
        )
        bom.add_component(agent)
        instructions = doc.get("instructions", [])
        models = doc.get("models", {})
        if not isinstance(instructions, list) or not isinstance(models, dict):
            raise ValueError
        for instruction in instructions:
            if not isinstance(instruction, str):
                raise ValueError
            path = Path(instruction)
            digest = hash_confined_file(root, str(path))
            ref = "prompt:" + path.as_posix()
            if not bom.get_component(ref):
                bom.add_component(
                    PromptComponent(
                        bom_ref=ref,
                        name=path.name,
                        source_path=path.as_posix(),
                        content_hash=digest,
                    )
                )
            agent.prompt_refs.append(ref)
            edge(root_ref, ref, "loads-instruction")
        for key, model in models.items():
            if not isinstance(model, dict):
                raise ValueError
            if isinstance(model.get("path"), str):
                local = Path(model["path"])
                for comp in bom.components:
                    if isinstance(comp, ModelComponent) and comp.source_path:
                        path = Path(comp.source_path)
                        if local == path or local == path.parent:
                            agent.model_refs.append(comp.bom_ref)
                            edge(root_ref, comp.bom_ref, "declares-model")
            elif isinstance(model.get("requested_ref"), str) and isinstance(
                model.get("provider"), str
            ):
                ref = f"model:{root_ref}/hosted/{quote(str(key), safe='')}"
                bom.add_component(
                    ModelComponent(
                        bom_ref=ref,
                        name=model["requested_ref"],
                        provider=model["provider"],
                        requested_alias=model["requested_ref"],
                        model_type="hosted",
                        source_path="agent.yaml",
                    )
                )
                agent.model_refs.append(ref)
                edge(root_ref, ref, "declares-model")
    except (OSError, ValueError, yaml.YAMLError, RecursionError):
        failures.append("Invalid or unreadable agent.yaml or referenced instruction")
