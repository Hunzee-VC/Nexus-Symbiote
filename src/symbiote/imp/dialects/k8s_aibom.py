"""k8s-aibom dialect adapter: wires :func:`symbiote.imp.k8s_aibom.import_k8s_aibom` into the CycloneDX importer.

The k8s-aibom controller observes a running Kubernetes workload, so the natural snapshot kind is
``deployed`` (``spec/collectors.md``). Models, the deployment record, redactions and the per-attribute
confidence mapping (``spec/agentbom-profile.md §5``) come from the existing importer; this adapter adds the
``usesModel`` edges, the deployment reference on the snapshot header, the controller as a collector run and
the coverage statement (``runtime`` and ``model-gateway`` were examined by the controller; a recorded
truncation marks ``model-gateway`` as ``truncated``). Whatever the controller emitted on the workload
component itself is kept on the root agent as foreign properties.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from symbiote.imp._common import ImportContext
from symbiote.imp.k8s_aibom import import_k8s_aibom
from symbiote.imp.native import Draft
from symbiote.model import enums as E
from symbiote.model.entities import Agent, CollectorRun, SourceRun, SurfaceCoverage
from symbiote.model.snapshot import Collector

PREFIXES = ("aibom.", "k8s-aibom:", "signature.", "model.k8saibom.dev/")


class K8sAibomAdapter:
    name = "k8s-aibom"
    default_kind = E.SnapshotKind.DEPLOYED
    prefixes = PREFIXES

    def adapt(self, doc: Mapping[str, Any], ctx: ImportContext, draft: Draft, root: Agent) -> set[str]:
        md = doc.get("metadata") if isinstance(doc.get("metadata"), Mapping) else {}
        comp = (
            md.get("component")
            if isinstance(md, Mapping) and isinstance(md.get("component"), Mapping)
            else {}
        )
        self.root_bom_ref = str(comp.get("bom-ref") or comp.get("name") or "component")
        result = import_k8s_aibom(doc, agent_id=root.id, now=ctx.now)
        for model in result.models:
            draft.add(model, bom_ref=result.model_refs.get(model.id))
            draft.edge(E.EdgeType.USES_MODEL, root.id, model.id)
        for dep in result.deployments:
            if draft.add(dep) and draft.deployment_ref is None:
                draft.deployment_ref = dep.id
        draft.redactions.extend(result.redactions)
        mapped_prefixes = (
            "aibom.workload.",
            "k8s-aibom:workload:",
            "aibom.controller.",
            "k8s-aibom:controller:",
        )
        mapped_names = {
            "aibom.redaction.applied",
            "k8s-aibom:redaction:applied",
            "aibom.truncation.applied",
            "k8s-aibom:truncation:applied",
        }
        consumed = {
            n for n in root.foreign if n.lower().startswith(mapped_prefixes) or n.lower() in mapped_names
        }
        if consumed:
            ctx.unforeign(root.id, consumed)
            root = root.replace(foreign={k: v for k, v in root.foreign.items() if k not in consumed})
            draft.replace(root)
        for fp in result.foreign_properties:
            if fp.name.lower().startswith(mapped_prefixes) or fp.name.lower() in mapped_names:
                continue
            element = draft.map_ref(fp.element_id) or fp.element_id
            if fp.element_id == self.root_bom_ref:
                element = root.id
            ctx.foreign_property(element, fp.name, fp.value, dialect=self.name)
        ctx.warnings.extend(result.warnings)
        ctx.facts.extend(result.facts)
        for fact in result.facts:
            ctx.lose(
                "/models/*/signature",
                E.LossReason.ENUM_NARROWED,
                E.LossPreservedIn.DROPPED,
                E.LossSeverity.SECURITY_RELEVANT,
                field_name=fact,
            )
        self.result = result
        return set(result.handled_refs)

    def post(self, doc: Mapping[str, Any], ctx: ImportContext, draft: Draft, root: Agent) -> None:
        result = self.result
        controller_name, controller_version = result.controller or ("k8s-aibom", "unknown")
        collector_name = (
            controller_name if controller_name.replace("-", "").replace(".", "").isalnum() else "k8s-aibom"
        )
        if draft.producer is not None and not any(
            c.name == collector_name for c in draft.producer.collectors
        ):
            draft.producer = draft.producer.replace(
                collectors=[
                    *draft.producer.collectors,
                    Collector(name=collector_name, version=controller_version, mode=E.CollectorMode.OBSERVED),
                ]
            )
        if not any(r.name == collector_name for r in draft.collector_runs):
            draft.collector_runs.append(
                CollectorRun(name=collector_name, version=controller_version, status=E.CollectorStatus.OK)
            )
        locator = None
        if result.workload:
            w = result.workload
            locator = "/".join(p for p in (w.get("namespace"), w.get("kind"), w.get("name")) if p) or None
        source = SourceRun(source=collector_name, locator=locator, ok=True, items=len(result.models))
        surfaces = dict(draft.coverage.surfaces)
        for surface in (E.Surface.RUNTIME, E.Surface.MODEL_GATEWAY):
            cov = surfaces.get(surface, SurfaceCoverage())
            if cov.status is E.CoverageStatus.NOT_ATTEMPTED:
                status = (
                    E.CoverageStatus.TRUNCATED
                    if surface is E.Surface.MODEL_GATEWAY and result.truncations
                    else E.CoverageStatus.QUERIED
                )
                surfaces[surface] = SurfaceCoverage(
                    status=status, sources=[source], items_seen=len(result.models)
                )
        draft.coverage = draft.coverage.replace(surfaces=surfaces)
        for t in result.truncations:
            ctx.lose(
                "/coverage/surfaces/model-gateway",
                E.LossReason.CARDINALITY_COLLAPSED,
                E.LossPreservedIn.PROPERTY,
                E.LossSeverity.SECURITY_RELEVANT,
                field_name=t,
            )


__all__ = ["PREFIXES", "K8sAibomAdapter"]
