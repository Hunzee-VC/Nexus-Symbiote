"""Import native 1.0 inventory declarations without inheriting producer trust or coverage."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from symbiote import __version__
from symbiote.digest import bytes_digest, parse_json_strict
from symbiote.model import Claim, Edge, Producer
from symbiote.model.common import DigestResult, EvidenceRef, Provenance
from symbiote.model.document import AgentBOM
from symbiote.model.entities import (
    Agent,
    DataSource,
    Entity,
    Evidence,
    ForeignProperty,
    HostedIdentity,
    Model,
    ToolDefinition,
    ToolServer,
)
from symbiote.model.enums import (
    AgentRole,
    DataSourceKind,
    DigestStatus,
    EdgeScope,
    EdgeType,
    EvidenceKind,
    ModelKind,
    SnapshotKind,
    ToolServerKind,
    ToolSource,
    Transport,
    UnknownReason,
)
from symbiote.snapshot import finalize, new_document


def _identifier(kind: str, ref: str) -> str:
    return kind + ":" + bytes_digest(ref.encode()).split(":", 1)[1]


def import_legacy(raw: bytes, *, root_ref: str | None = None, now: datetime | None = None) -> AgentBOM:
    doc = parse_json_strict(raw)
    if (
        not isinstance(doc, dict)
        or not isinstance(doc.get("metadata"), dict)
        or doc["metadata"].get("spec_version") != "1.0.0"
    ):
        raise ValueError("expected a native 1.0.0 inventory")
    components = doc.get("components")
    if not isinstance(components, list):
        raise ValueError("components must be an array")
    by_ref = {}
    for c in components:
        if not isinstance(c, dict) or any(
            not isinstance(c.get(k), str) or not c[k] for k in ("bom_ref", "component_type", "name")
        ):
            raise ValueError("invalid component declaration")
        if c["bom_ref"] in by_ref:
            raise ValueError("duplicate component reference")
        by_ref[c["bom_ref"]] = c
    roots = [
        ref
        for ref, c in by_ref.items()
        if c["component_type"] == "agent" and (root_ref is None or ref == root_ref)
    ]
    if len(roots) != 1:
        raise ValueError("provide exactly one root agent (use --agent to select its bom_ref)")
    subject = _identifier("agent", roots[0])
    digest = bytes_digest(raw)
    stamp = now or datetime.now(UTC)
    ev = Evidence(
        id="ev:" + digest[7:19],
        evidence_kind=EvidenceKind.SCAN_REPORT,
        media_type="application/json",
        digest=digest,
        created=stamp,
    )
    provenance = Provenance(evidence=[EvidenceRef(digest=digest, media_type="application/json")])
    unknown = UnknownReason.NOT_COLLECTED
    mapping: dict[str, str] = {}
    entities: dict[str, list[Any]] = {
        "agents": [],
        "models": [],
        "tool_servers": [],
        "tools": [],
        "data_sources": [],
    }
    loss: list[ForeignProperty] = []
    edges: list[Edge] = []

    def note(element: str, reason: str, fields: list[str]) -> None:
        if fields:
            loss.append(
                ForeignProperty(
                    dialect="symbiote-native/1.0.0",
                    element_id=element,
                    name=reason,
                    value=", ".join(sorted(fields)),
                )
            )

    def relation(source: str, target: str, kind: EdgeType) -> None:
        e = Edge(type=kind, from_ref=source, to_ref=target, scope=EdgeScope.DESIGN)
        if e not in edges:
            edges.append(e)

    for ref, c in by_ref.items():
        kind = c["component_type"]
        name = c["name"]
        common = {"name": name, "provenance": provenance}
        fields = {"bom_ref", "component_type", "name"}
        entity: Entity
        if ref == roots[0]:
            entity = Agent(id=subject, version=c.get("version") or "unknown", role=AgentRole.ROOT, **common)
            fields.add("version")
            if not c.get("version"):
                note(subject, "unknown", ["version"])
            collection = "agents"
        elif kind == "mcp-server":
            transport = (
                Claim.declared(Transport(c["transport"]))
                if c.get("transport") in set(Transport)
                else Claim.unknown(unknown)
            )
            entity = ToolServer(
                id=_identifier("server", ref),
                server_kind=ToolServerKind.MCP,
                transport=transport,
                authentication=Claim.unknown(unknown),
                crosses_trust_boundary=Claim.unknown(unknown),
                **common,
            )
            if transport.value:
                fields.add("transport")
            collection = "tool_servers"
        elif (
            kind == "tool"
            and isinstance(c.get("mcp_server_ref"), str)
            and by_ref.get(c["mcp_server_ref"], {}).get("component_type") == "mcp-server"
        ):
            server = _identifier("server", c["mcp_server_ref"])
            schema = c.get("input_schema")
            entity = ToolDefinition(
                id=_identifier("tool", ref),
                server_ref=server,
                tool_name=name,
                input_schema=schema if isinstance(schema, dict) else {},
                digest=DigestResult(
                    algorithm="tooldef/v1",
                    status=DigestStatus.UNDIGESTABLE,
                    reason="legacy projection does not establish the complete MCP descriptor",
                ),
                source=ToolSource.DECLARED_CONFIG,
                **common,
            )
            relation(server, entity.id, EdgeType.PROVIDES_TOOL)
            fields.add("mcp_server_ref")
            if isinstance(schema, dict):
                fields.add("input_schema")
            else:
                note(entity.id, "unknown", ["input_schema"])
            collection = "tools"
        elif (
            kind == "model"
            and c.get("serialization_format") == "api"
            and isinstance(c.get("provider"), str)
            and c["provider"]
        ):
            entity = Model(
                id=_identifier("model", ref),
                model_kind=ModelKind.HOSTED,
                hosted=Claim.declared(
                    HostedIdentity(
                        provider=c["provider"], requested_ref=name, resolved_ref=Claim.unknown(unknown)
                    )
                ),
                **common,
            )
            fields.update(("provider", "serialization_format"))
            collection = "models"
        elif kind in {"rag-source", "data-source", "memory-store"}:
            data_kind = {
                "rag-source": DataSourceKind.RAG_INDEX,
                "data-source": DataSourceKind.DATASET,
                "memory-store": DataSourceKind.MEMORY_STORE,
            }[kind]
            entity = DataSource(
                id=_identifier("data", ref),
                data_kind=data_kind,
                instruction_bearing=Claim.unknown(unknown),
                **common,
            )
            collection = "data_sources"
        else:
            note(_identifier("legacy", ref), "unmapped-component", list(c))
            continue
        mapping[ref] = entity.id
        entities[collection].append(entity)
        note(entity.id, "unmapped-fields", list(c.keys() - fields))

    legacy_edges = doc.get("dependencies", [])
    if not isinstance(legacy_edges, list):
        raise ValueError("dependencies must be an array")
    for i, e in enumerate(legacy_edges):
        if not isinstance(e, Mapping) or any(
            not isinstance(e.get(k), str) for k in ("source_ref", "target_ref", "relationship")
        ):
            raise ValueError("invalid dependency")
        a, b, rel = e["source_ref"], e["target_ref"], e["relationship"]
        if a not in by_ref or b not in by_ref:
            raise ValueError("dangling legacy dependency")
        edge_kind = None
        if a in mapping and b in mapping:
            if rel == "depends-on":
                edge_kind = EdgeType.DEPENDS_ON
            elif rel == "retrieves-from" and mapping[b].startswith("data:"):
                edge_kind = EdgeType.READS_CONTEXT_FROM
            elif rel == "invokes" and mapping[a].startswith("agent:") and mapping[b].startswith("tool:"):
                edge_kind = EdgeType.INVOKES_TOOL
            elif rel == "invokes" and by_ref[b].get("mcp_server_ref") == a:
                edge_kind = EdgeType.PROVIDES_TOOL
        if edge_kind is None:
            note(f"edge:{i}", "unmapped-edge", [rel])
        else:
            relation(mapping[a], mapping[b], edge_kind)
            note(
                f"edge:{i}", "unmapped-fields", list(e.keys() - {"source_ref", "target_ref", "relationship"})
            )
    note("metadata", "unmapped-fields", list(doc["metadata"].keys() - {"spec_version"}))
    note("document", "unmapped-fields", list(doc.keys() - {"metadata", "components", "dependencies"}))
    return finalize(
        new_document(
            subject=subject,
            producer=Producer(version=__version__),
            kind=SnapshotKind.DECLARED,
            produced_at=stamp,
            evidence=[ev],
            foreign_properties=loss,
            edges=edges,
            agents=entities["agents"],
            models=entities["models"],
            tool_servers=entities["tool_servers"],
            tools=entities["tools"],
            data_sources=entities["data_sources"],
        )
    )
