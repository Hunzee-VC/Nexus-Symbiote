"""k8s-aibom importer (``spec/collectors.md`` row ``k8s-aibom``, ``spec/agentbom-profile.md §5``).

Accepts either a k8s-aibom CycloneDX 1.6 ML-BOM document or an ``AIBOM`` custom resource
(``apiVersion: aibom.k8saibom.dev/v1alpha1``): the controller inlines the BOM at
``status.bomDocument.inline.data`` (base64, documents under 256 KiB) or references it by URL —
a URL reference is never fetched here; it is reported as an unresolved input.

Unsigned input confidence mapping (``agentbom-profile.md §5``):

* ``declared``   → ``assurance=declared``
* ``inferred``   → an external declaration, retaining the source locator
* ``unresolved`` → ``state=unknown``
* ``verified`` → a supplier declaration. Signature properties describe the supplier's claim.
  A separate verifier must authenticate the artifact and signer under the consumer's policy.

Every unmapped ``aibom.*`` / ``k8s-aibom:*`` property is preserved verbatim as a
``ForeignProperty`` (dialect ``k8s-aibom``), and ``aibom.redaction.applied`` becomes a
``Redaction`` record — redaction is recorded, never silent.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from symbiote.model.common import Claim
from symbiote.model.entities import (
    Deployment,
    Environment,
    ForeignProperty,
    HostedIdentity,
    Model,
    Redaction,
    SignatureFacts,
    WorkloadRef,
)
from symbiote.model.enums import (
    EnvironmentKind,
    ModelKind,
    SignatureOutcome,
    SignatureStatus,
    UnknownReason,
)
from symbiote.model.ids import make_id

DIALECT = "k8s-aibom"
_PROPERTY_PREFIXES = ("aibom.", "k8s-aibom:", "signature.", "model.k8saibom.dev/")
VERIFIED_WITHOUT_CONSTRAINT = "imported-verified-without-constraint"

#: Documents are specified under 256 KiB; 400k base64 chars (~300 KiB decoded) is a
#: generous ceiling that still stops a hostile CR from forcing an unbounded decode.
_MAX_INLINE_B64_CHARS = 400_000


class K8sAibomError(ValueError):
    """The input is not a k8s-aibom document this importer understands."""


@dataclass(slots=True)
class K8sAibomImport:
    """What one k8s-aibom document contributes, with assurance already mapped."""

    models: list[Model] = field(default_factory=list)
    deployments: list[Deployment] = field(default_factory=list)
    redactions: list[Redaction] = field(default_factory=list)
    foreign_properties: list[ForeignProperty] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source_serial_number: str | None = None


def extract_bom_document(payload: Mapping[str, Any]) -> tuple[Mapping[str, Any], str | None]:
    """Return ``(cyclonedx_document, warning)`` from a CR or a bare CycloneDX document."""
    api_version = str(payload.get("apiVersion", ""))
    if api_version.startswith("aibom.k8saibom.dev/") and payload.get("kind") == "AIBOM":
        bom_doc = payload.get("status", {}).get("bomDocument")
        if not isinstance(bom_doc, Mapping):
            raise K8sAibomError("AIBOM resource has no status.bomDocument")
        inline = bom_doc.get("inline")
        if isinstance(inline, Mapping) and isinstance(inline.get("data"), str):
            if len(inline["data"]) > _MAX_INLINE_B64_CHARS:
                raise K8sAibomError(
                    f"inline BOM exceeds the {_MAX_INLINE_B64_CHARS}-char inline bound; refusing to decode it"
                )
            try:
                decoded = base64.b64decode(inline["data"], validate=True)
                document = json.loads(decoded)
            except (binascii.Error, ValueError) as exc:
                raise K8sAibomError(f"status.bomDocument.inline.data is not base64 JSON: {exc}") from exc
            if not isinstance(document, Mapping):
                raise K8sAibomError("inline BOM is not a JSON object")
            return document, None
        url = bom_doc.get("url")
        if isinstance(url, str) and url:
            raise K8sAibomError(
                f"AIBOM resource references its BOM by URL ({url}); fetch it and import the document"
            )
        raise K8sAibomError("status.bomDocument carries neither inline data nor a url")
    if payload.get("bomFormat") == "CycloneDX":
        return payload, None
    raise K8sAibomError("input is neither an AIBOM custom resource nor a CycloneDX document")


def _properties(component: Mapping[str, Any]) -> list[tuple[str, str]]:
    return [
        (str(p.get("name", "")), str(p.get("value", "")))
        for p in component.get("properties", []) or []
        if isinstance(p, Mapping)
    ]


def _dialect_value(props: list[tuple[str, str]], *names: str) -> str | None:
    wanted = {n.lower() for n in names}
    for name, value in props:
        if name.lower() in wanted:
            return value
    return None


def _confidence_claim(
    value: Any,
    confidence: str | None,
    *,
    locator: str,
    facts: list[str],
) -> Claim[Any]:
    tier = (confidence or "declared").lower()
    if tier == "unresolved":
        return Claim.unknown(UnknownReason.PROVIDER_UNDISCLOSED, locator=locator)
    if tier == "verified":
        facts.append(VERIFIED_WITHOUT_CONSTRAINT)
    return Claim.declared(value, locator=locator)


def _signature_facts(props: list[tuple[str, str]]) -> SignatureFacts | None:
    """Keep upstream signature metadata as a claim. Raw producer fields remain in foreign_properties."""
    prefixes = ("signature.", "k8s-aibom:signature:")
    raw = {
        name[len(prefix) :]: value for name, value in props for prefix in prefixes if name.startswith(prefix)
    }
    if not raw:
        return None
    bundle = raw.get("bundleDigest") or raw.get("bundle-digest")
    return SignatureFacts(
        status=SignatureStatus.UNSIGNED if raw.get("status") == "unsigned" else SignatureStatus.CLAIMED,
        outcome=SignatureOutcome.NONE,
        identity=raw.get("identity"),
        issuer=raw.get("issuer"),
        log_entry=raw.get("logEntry") or raw.get("log-entry"),
        bundle_digest=bundle if bundle and re.fullmatch(r"sha256:[0-9a-f]{64}", bundle) else None,
    )


def import_k8s_aibom(
    payload: Mapping[str, Any],
    *,
    agent_id: str = "agent:imported",
    now: datetime | None = None,
) -> K8sAibomImport:
    """Map one k8s-aibom document into AgentBOM entities with §5 confidence semantics."""
    now = now or datetime.now(UTC)
    document, _ = extract_bom_document(payload)
    result = K8sAibomImport(source_serial_number=document.get("serialNumber"))
    workload: dict[str, str] = {}
    seen_components: dict[str, Model] = {}
    model_refs: dict[str, str] = {}
    namespace = None
    for component in [
        document.get("metadata", {}).get("component"),
        *list(document.get("components", []) or []),
    ]:
        if not isinstance(component, Mapping):
            continue
        props = _properties(component)
        bom_ref = str(component.get("bom-ref", component.get("name", "component")))
        for name, value in props:
            lowered = name.lower()
            if lowered.startswith(("aibom.workload.", "k8s-aibom:workload:")):
                workload[lowered.rsplit(".", 1)[-1].rsplit(":", 1)[-1]] = value
                continue
            if lowered in ("aibom.redaction.applied", "k8s-aibom:redaction:applied"):
                result.redactions.append(
                    Redaction(
                        redaction_class=value or "unspecified",
                        count=1,
                        applied_by="k8s-aibom-controller",
                        applied_at=now,
                    )
                )
                continue
            if lowered.startswith(_PROPERTY_PREFIXES):
                result.foreign_properties.append(
                    ForeignProperty(dialect=DIALECT, element_id=bom_ref, name=name, value=value)
                )
        if component.get("type") != "machine-learning-model":
            continue
        name = str(component.get("name", "model"))
        confidence = _dialect_value(props, "aibom.confidence", "k8s-aibom:confidence")
        signature = _signature_facts(props)
        source = _dialect_value(props, "aibom.model.source", "k8s-aibom:model:source")
        digest = None
        for hash_entry in component.get("hashes", []) or []:
            if isinstance(hash_entry, Mapping) and hash_entry.get("alg") == "SHA-256":
                digest = "sha256:" + str(hash_entry.get("content", "")).lower()
        if digest and not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise K8sAibomError(f"invalid SHA-256 for model {bom_ref}")
        locator = f"cdx:{bom_ref}"
        # A display name can cover many weight revisions, endpoints and BOM subjects.
        source_ref: str | list[str] = bom_ref
        props_by_name = dict(props)
        meta = document.get("metadata", {}).get("component") or {}
        workload_ref = meta.get("bom-ref")
        container = props_by_name.get("container.name")
        selector = props_by_name.get("aibom.evidence.source")
        primary_arg = selector == "container_arg" and props_by_name.get("identity.argFlag") == "--model"
        primary_env = selector == "env_var" and props_by_name.get("identity.envVarName") == "HF_MODEL_ID"
        if (
            not digest
            and workload_ref
            and container
            and (primary_arg or primary_env)
            and props_by_name.get("aibom.evidence.locator")
        ):
            # Coalesce a declaration for the same primary selector in the same container.
            # Keep both original observation locations. This does not identify model bytes.
            source_ref = [workload_ref, container, "primary-model"]
        subject = [
            agent_id,
            document.get("serialNumber"),
            source_ref,
            source,
            name,
            component.get("version"),
            digest,
        ]
        key = hashlib.sha256(json.dumps(subject, ensure_ascii=False).encode()).hexdigest()
        model_id = make_id("model", name, key)
        if component.get("bom-ref") and model_refs.setdefault(bom_ref, model_id) != model_id:
            raise K8sAibomError(f"conflicting components at model reference {bom_ref}")
        artifact = (
            _confidence_claim(digest, confidence, locator=locator, facts=result.facts) if digest else None
        )
        hosting = _dialect_value(props, "aibom.model.hosting", "k8s-aibom:model:hosting")
        if hosting == "hosted" and source:
            hosted = _confidence_claim(
                HostedIdentity(
                    provider=source,
                    requested_ref=name,
                    resolved_ref=Claim.unknown(UnknownReason.PROVIDER_UNDISCLOSED),
                ),
                confidence,
                locator=locator,
                facts=result.facts,
            )
            model = Model(
                id=model_id,
                name=name,
                model_kind=ModelKind.HOSTED,
                hosted=hosted,
                signature=signature,
                artifact_digest=artifact,
            )
        else:
            model = Model(
                id=model_id,
                name=name,
                model_kind=ModelKind.UNKNOWN,
                signature=signature,
                artifact_digest=artifact,
            )
        if source_ref != bom_ref:
            result.foreign_properties.append(
                ForeignProperty(dialect=DIALECT, element_id=model_id, name="sourceComponent", value=bom_ref)
            )
        previous = seen_components.get(model.id)
        if previous is not None and previous != model:
            raise K8sAibomError(f"conflicting assertions for model {bom_ref}")
        if previous is None:
            seen_components[model.id] = model
            result.models.append(model)
        if ns := _dialect_value(props, "aibom.workload.namespace", "k8s-aibom:workload:namespace"):
            namespace = ns
    if workload:
        result.deployments.append(
            Deployment(
                id=make_id("deploy", workload.get("name", "workload"), collision_seed=workload.get("uid")),
                agent_ref=agent_id,
                environment=Environment(
                    kind=EnvironmentKind.K8S, namespace=workload.get("namespace", namespace)
                ),
                workload_ref=WorkloadRef(
                    group=workload.get("group"),
                    kind=workload.get("kind"),
                    namespace=workload.get("namespace"),
                    name=workload.get("name"),
                    uid=workload.get("uid"),
                ),
            )
        )
    return result


__all__ = [
    "DIALECT",
    "VERIFIED_WITHOUT_CONSTRAINT",
    "K8sAibomError",
    "K8sAibomImport",
    "extract_bom_document",
    "import_k8s_aibom",
]
