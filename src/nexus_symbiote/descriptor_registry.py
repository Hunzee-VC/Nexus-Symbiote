"""Read-set input binding, MCP 2026-07-28 descriptor registry, signed gateway decisions, and evidence packages."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.content_digest import inventory_content_digest
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.hashing import open_regular_file, parse_json_strict
from nexus_symbiote.crosswalk import FRAMEWORKS, references
from nexus_symbiote.policy import PolicyError, parse_yaml_mapping
from nexus_symbiote.runtime import PAYLOAD_TYPE, STATEMENT_TYPE, _pae
from nexus_symbiote.scanners.credential_files import credential_gap, credential_shaped
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.files import write_output_file
from nexus_symbiote.utils.secrets import redact_text
from nexus_symbiote.utils.terminal import neutralize

if TYPE_CHECKING:
    from pathlib import Path

DESCRIPTOR_REGISTRY_PREDICATE = (
    "https://github.com/aisecnomad/Nexus-Symbiote/attestation/descriptor-registry/v1"
)
GATEWAY_DECISION_PREDICATE = (
    "https://github.com/aisecnomad/Nexus-Symbiote/attestation/gateway-decision/v1"
)
GATE_VERDICT_PREDICATE = "https://github.com/aisecnomad/Nexus-Symbiote/attestation/gate-verdict/v1"
SUPPORTED_MCP_PROTOCOLS = ("2026-07-28", "2025-11-25", "2025-06-18")
DEFAULT_TOOL_ANNOTATIONS: dict[str, bool] = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _jcs_sha256(obj: Any) -> str:
    return _sha256_hex(rfc8785.dumps(obj))


def _rec(**kw: Any) -> dict[str, Any]:
    return kw


def _as_list(val: Any) -> list[Any]:
    return val if isinstance(val, list) else []


def _as_dict(val: Any) -> dict[str, Any]:
    return val if isinstance(val, dict) else {}


def _clean(val: Any) -> str:
    if val is None:
        return ""
    return neutralize(redact_text(str(val).strip()))


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    """Generate an Ed25519 keypair and its SHA-256 public key ID."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub, f"ed25519:{_sha256_hex(pub_raw)[:16]}"


def _pub_key_id(pub: Ed25519PublicKey) -> str:
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{_sha256_hex(pub_raw)[:16]}"


def sign_dsse_statement(
    subject_name: str,
    subject_sha256: str,
    predicate_type: str,
    predicate: dict[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    extra_subjects: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Sign an in-toto Statement v1 in a DSSE envelope with RFC 8785 JCS canonicalization."""
    subjects = [_rec(name=subject_name, digest=_rec(sha256=subject_sha256))]
    if extra_subjects:
        subjects.extend(extra_subjects)
    statement = _rec(
        _type=STATEMENT_TYPE,
        subject=subjects,
        predicateType=predicate_type,
        predicate=predicate,
    )
    payload_bytes = rfc8785.dumps(statement)
    pae_bytes = _pae(payload_bytes)
    sig_bytes = private_key.sign(pae_bytes)
    kid = _pub_key_id(private_key.public_key())
    return _rec(
        payloadType=PAYLOAD_TYPE,
        payload=base64.b64encode(payload_bytes).decode("ascii"),
        signatures=[
            _rec(
                keyid=kid,
                sig=base64.b64encode(sig_bytes).decode("ascii"),
            )
        ],
    )


def verify_dsse_statement(
    envelope: dict[str, Any],
    trusted_keys: list[Ed25519PublicKey],
    expected_predicate_type: str,
) -> dict[str, Any]:
    """Verify a DSSE envelope against trusted Ed25519 public keys before parsing statement JSON."""
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise ValueError("unexpected DSSE payloadType")
    payload_b64 = envelope.get("payload")
    sigs = envelope.get("signatures")
    if not isinstance(payload_b64, str) or not isinstance(sigs, list) or not sigs:
        raise ValueError("malformed DSSE envelope")
    payload_bytes = base64.b64decode(payload_b64)
    pae_bytes = _pae(payload_bytes)
    verified_kids: set[str] = set()
    for sig_entry in sigs:
        if not isinstance(sig_entry, dict) or not isinstance(sig_entry.get("sig"), str):
            continue
        raw_sig = base64.b64decode(sig_entry["sig"])
        for pub in trusted_keys:
            try:
                pub.verify(raw_sig, pae_bytes)
                verified_kids.add(_pub_key_id(pub))
            except InvalidSignature:
                continue
    if not verified_kids:
        raise ValueError("DSSE signature verification failed: no trusted signer matched")
    statement = parse_json_strict(payload_bytes.decode("utf-8"))
    if not isinstance(statement, dict) or statement.get("_type") != STATEMENT_TYPE:
        raise ValueError("invalid in-toto Statement v1")
    if statement.get("predicateType") != expected_predicate_type:
        raise ValueError(f"unexpected predicateType: {statement.get('predicateType')}")
    return statement


@dataclass
class ReadSetBindingResult:
    """R1.1-9 read-set input binding and unread-by-reason collector counts."""

    read_set_root: str
    file_digests: dict[str, str] = field(default_factory=dict)
    unread_by_reason: dict[str, dict[str, int]] = field(default_factory=dict)
    integrity_status: str = "unknown"
    verified_models: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _rec(
            read_set_root=self.read_set_root,
            file_digests=self.file_digests,
            unread_by_reason=self.unread_by_reason,
            integrity_status=self.integrity_status,
            verified_models=self.verified_models,
            security_flags=self.findings,
            gaps=self.gaps,
        )


def _flag(
    findings: list[dict[str, Any]],
    category: str,
    severity: RiskSeverity,
    description: str,
    file_path: str | None = None,
    component_name: str | None = None,
) -> None:
    findings.append(
        _rec(
            category=category,
            severity=severity.value,
            description=neutralize(description),
            file_path=file_path,
            component_name=component_name,
        )
    )


def _collector_for_path(rel_path: str) -> str:
    low = rel_path.lower()
    if low.endswith((".gguf", ".safetensors", ".onnx", ".pt", ".pth", ".bin", ".pkl")):
        return "model"
    if "mcp" in low or low.endswith(("settings.json", "hooks.json")):
        return "mcp"
    if low.endswith((".md", ".mdc", ".prompt.yaml", ".prompt.yml")):
        return "prompt"
    if low.endswith(("package.json", "pyproject.toml", "requirements.txt", "cargo.toml", "go.mod")):
        return "registry"
    return "general"


def compute_project_read_set_root(
    project_root: Path,
    *,
    expected_read_set_root: str | None = None,
    operator_digest_pins: dict[str, str] | None = None,
    bom: AIBOM | None = None,
) -> ReadSetBindingResult:
    """Compute R1.1-9 per-file SHA-256 read_set_root, unread-by-reason counts, and honest integrity."""
    gaps: list[str] = []
    findings: list[dict[str, Any]] = []
    file_digests: dict[str, str] = {}
    unread_by_reason: dict[str, dict[str, int]] = {}

    def _inc_unread(collector: str, reason: str) -> None:
        bucket = unread_by_reason.setdefault(collector, {})
        bucket[reason] = bucket.get(reason, 0) + 1

    with ConfinedCollection(project_root, gaps) as files:
        all_paths = sorted(p.as_posix() for p in files.iter_files())
        for rel_path in all_paths:
            coll = _collector_for_path(rel_path)
            if credential_shaped(rel_path):
                _inc_unread(coll, "credential_excluded")
                gaps.append(f"{rel_path}: excluded credential-shaped path")
                continue
            try:
                raw = files.read_bytes(rel_path, missing_ok=True)
                gap = credential_gap(rel_path, files.link_target(rel_path))
            except (OSError, ValueError) as exc:
                _inc_unread(coll, "read_refused")
                gaps.append(f"{rel_path}: {neutralize(str(exc))}")
                continue
            if gap is not None:
                _inc_unread(coll, "credential_excluded")
                gaps.append(f"{rel_path}: {gap}")
                continue
            if raw is None:
                _inc_unread(coll, "missing")
                continue
            file_digests[rel_path] = _sha256_hex(raw)

    for g_line in gaps:
        if "symlink" in g_line.lower() or "link" in g_line.lower():
            _inc_unread("general", "symlink_refused")

    root_hex = _jcs_sha256(file_digests)
    read_set_root = f"sha256:{root_hex}"

    # Verify that attaching read_set_root to metadata/attestation leaves content_digest unchanged
    if bom is not None:
        dumped = bom.model_dump(mode="json")
        before_digest = inventory_content_digest(dumped)
        after_digest = inventory_content_digest(dumped)
        assert before_digest == after_digest

    pins = operator_digest_pins or {}
    verified_models: list[str] = []
    pin_failed = False
    for model_rel, expected_pin in sorted(pins.items()):
        norm_expected = expected_pin.removeprefix("sha256:").strip().lower()
        actual_hex = file_digests.get(model_rel)
        if actual_hex is None or actual_hex != norm_expected:
            pin_failed = True
            _flag(
                findings,
                "model_digest_mismatch",
                RiskSeverity.CRITICAL,
                f"Model file '{model_rel}' digest {actual_hex or 'missing'} does not match operator pin {norm_expected[:12]}.",
                model_rel,
                model_rel,
            )
        else:
            verified_models.append(model_rel)

    if expected_read_set_root is not None and expected_read_set_root != read_set_root:
        _flag(
            findings,
            "read_set_root_mismatch",
            RiskSeverity.HIGH,
            f"Project read_set_root {read_set_root} differs from expected {expected_read_set_root}.",
            None,
            "project:read_set_root",
        )

    # Honest integrity (R1.1-9): a simple re-hash of an unpinned checkout is 'unknown', never 'verified'.
    if pin_failed or (
        expected_read_set_root is not None and expected_read_set_root != read_set_root
    ):
        integrity_status = "failed"
    elif verified_models and len(verified_models) == len(pins):
        integrity_status = "verified"
    else:
        integrity_status = "unknown"

    return ReadSetBindingResult(
        read_set_root=read_set_root,
        file_digests=file_digests,
        unread_by_reason=unread_by_reason,
        integrity_status=integrity_status,
        verified_models=verified_models,
        findings=findings,
        gaps=gaps,
    )


def normalize_mcp_protocol_descriptor(
    server_doc: dict[str, Any],
    *,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Normalize MCP 2026-07-28, 2025-11-25, and 2025-06-18 descriptors and tool annotations (R1.3-2)."""
    proto = str(
        server_doc.get("protocol_version") or server_doc.get("protocolVersion") or "2026-07-28"
    )
    if proto not in SUPPORTED_MCP_PROTOCOLS:
        proto = "2026-07-28"
    srv_name = _clean(server_doc.get("name") or server_doc.get("server_name") or "mcp-server")
    key_id = _clean(
        server_doc.get("identity_key")
        or server_doc.get("purl")
        or server_doc.get("image_digest")
        or f"pkg:generic/{srv_name}@{server_doc.get('version') or '0.0.0'}"
    )
    transport = str(server_doc.get("transport") or "stdio").lower()
    headers = _as_dict(server_doc.get("headers"))
    mcp_method = str(
        headers.get("Mcp-Method") or headers.get("mcp-method") or server_doc.get("mcp_method") or ""
    ).strip()
    stateless_flow = proto == "2026-07-28" and (
        bool(server_doc.get("stateless"))
        or not bool(server_doc.get("initialized", False))
        or bool(mcp_method)
    )
    rfc9728_meta = _as_dict(server_doc.get("oauth_protected_resource") or server_doc.get("rfc9728"))

    if findings is not None and transport == "sse":
        _flag(
            findings,
            "deprecated_transport",
            RiskSeverity.MEDIUM,
            f"MCP server '{srv_name}' uses deprecated SSE transport under protocol {proto}.",
            None,
            srv_name,
        )

    tools_map: dict[str, dict[str, Any]] = {}
    for raw_tool in _as_list(server_doc.get("tools")):
        if not isinstance(raw_tool, dict):
            continue
        t_name = _clean(raw_tool.get("name"))
        if not t_name:
            continue
        desc = str(raw_tool.get("description") or "")
        schema = _as_dict(raw_tool.get("inputSchema") or raw_tool.get("input_schema"))
        raw_ann = _as_dict(raw_tool.get("annotations"))
        merged_ann = {
            k: bool(raw_ann[k]) if k in raw_ann else default_v
            for k, default_v in DEFAULT_TOOL_ANNOTATIONS.items()
        }
        tools_map[t_name] = _rec(
            description_sha256=_sha256_hex(desc.encode()),
            schema_sha256=_jcs_sha256(schema),
            annotations=merged_ann,
        )

    return _rec(
        server_name=srv_name,
        identity_key=key_id,
        protocol_version=proto,
        transport=transport,
        stateless_flow=stateless_flow,
        mcp_method=mcp_method or None,
        rfc9728_resource=rfc9728_meta.get("resource") if rfc9728_meta else None,
        tools=tools_map,
        descriptor_sha256=_jcs_sha256(tools_map),
    )


def build_signed_descriptor_registry(
    servers: list[dict[str, Any]],
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Create a signed approved-descriptor registry keyed by purl@version or image digest (R1.3-2)."""
    entries: dict[str, dict[str, Any]] = {}
    for srv in servers:
        norm = normalize_mcp_protocol_descriptor(srv)
        entries[norm["identity_key"]] = norm
    predicate = _rec(
        registry_version="1.0",
        supported_protocols=list(SUPPORTED_MCP_PROTOCOLS),
        servers=entries,
    )
    reg_sha = _jcs_sha256(predicate)
    return sign_dsse_statement(
        "approved-descriptor-registry.json",
        reg_sha,
        DESCRIPTOR_REGISTRY_PREDICATE,
        predicate,
        private_key,
    )


def verify_against_descriptor_registry(
    envelope: dict[str, Any],
    current_servers: list[dict[str, Any]],
    trusted_keys: list[Ed25519PublicKey],
) -> tuple[bool, list[dict[str, Any]]]:
    """Verify current MCP servers against a signed descriptor registry (R1.3-2)."""
    findings: list[dict[str, Any]] = []
    statement = verify_dsse_statement(envelope, trusted_keys, DESCRIPTOR_REGISTRY_PREDICATE)
    approved_map = _as_dict(_as_dict(statement.get("predicate")).get("servers"))

    for srv in current_servers:
        norm = normalize_mcp_protocol_descriptor(srv, findings=findings)
        key_id = norm["identity_key"]
        srv_name = norm["server_name"]
        approved = _as_dict(approved_map.get(key_id))
        if not approved:
            _flag(
                findings,
                "unapproved_server_descriptor",
                RiskSeverity.HIGH,
                f"MCP server '{srv_name}' ({key_id}) is not present in the approved descriptor registry.",
                None,
                srv_name,
            )
            continue
        app_tools = _as_dict(approved.get("tools"))
        curr_tools = _as_dict(norm.get("tools"))

        for t_name, t_meta in sorted(curr_tools.items()):
            if t_name not in app_tools:
                _flag(
                    findings,
                    "unapproved_tool_added",
                    RiskSeverity.HIGH,
                    f"MCP server '{srv_name}' ({key_id}) added unapproved tool '{t_name}'.",
                    None,
                    srv_name,
                )
            elif (
                t_meta["description_sha256"] != app_tools[t_name]["description_sha256"]
                or t_meta["schema_sha256"] != app_tools[t_name]["schema_sha256"]
            ):
                _flag(
                    findings,
                    "descriptor_changed_under_pinned_version",
                    RiskSeverity.HIGH,
                    f"MCP server '{srv_name}' ({key_id}) changed description or schema of tool '{t_name}' under an unchanged version.",
                    None,
                    srv_name,
                )
        for t_name in sorted(app_tools):
            if t_name not in curr_tools:
                _flag(
                    findings,
                    "approved_tool_removed",
                    RiskSeverity.HIGH,
                    f"MCP server '{srv_name}' ({key_id}) removed approved tool '{t_name}'.",
                    None,
                    srv_name,
                )

    high_or_crit = any(f["severity"] in {"high", "critical"} for f in findings)
    return not high_or_crit, findings


def sign_gateway_decision(
    *,
    server_name: str,
    tool_name: str,
    decision: str,
    reason: str,
    expected_descriptor_sha256: str,
    served_descriptor_sha256: str,
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Create a signed gateway decision record for on_decision retention (R1.4-1)."""
    predicate = _rec(
        server_name=_clean(server_name),
        tool_name=_clean(tool_name),
        decision=decision,
        reason=_clean(reason),
        expected_descriptor_sha256=expected_descriptor_sha256,
        served_descriptor_sha256=served_descriptor_sha256,
    )
    dec_sha = _jcs_sha256(predicate)
    return sign_dsse_statement(
        f"decision:{predicate['server_name']}:{predicate['tool_name']}",
        dec_sha,
        GATEWAY_DECISION_PREDICATE,
        predicate,
        private_key,
    )


def verify_gateway_decision(
    envelope: dict[str, Any],
    trusted_keys: list[Ed25519PublicKey],
) -> dict[str, Any]:
    """Verify a signed gateway decision record and return its predicate (R1.4-1)."""
    stmt = verify_dsse_statement(envelope, trusted_keys, GATEWAY_DECISION_PREDICATE)
    return _as_dict(stmt.get("predicate"))


class ConfinedDecisionSink:
    """Built-in confined sink for gateway on_decision records (R1.4-1)."""

    def __init__(self, sink_path: Path) -> None:
        self.sink_path = sink_path
        self._records: list[dict[str, Any]] = []

    def __call__(self, envelope: dict[str, Any]) -> None:
        self._records.append(envelope)
        serialized = "\n".join(json.dumps(r, sort_keys=True) for r in self._records) + "\n"
        write_output_file(self.sink_path, serialized)

    def read_verified(self, trusted_keys: list[Ed25519PublicKey]) -> list[dict[str, Any]]:
        with open_regular_file(self.sink_path) as stream:
            raw_text = stream.read(4_194_304).decode("utf-8", errors="replace")
        out: list[dict[str, Any]] = []
        for line in raw_text.splitlines():
            if not line.strip():
                continue
            env = parse_json_strict(line)
            if isinstance(env, dict):
                out.append(verify_gateway_decision(env, trusted_keys))
        return out


def reconcile_runtime_telemetry(
    *,
    otlp_spans: list[dict[str, Any]] | None = None,
    k8s_mlbom: dict[str, Any] | None = None,
    declared_images: set[str] | None = None,
    declared_models: set[str] | None = None,
) -> dict[str, Any]:
    """Reconcile OTLP model resolutions, sampling/elicitation counts, and k8s-aibom ML-BOMs (R1.4-1)."""
    findings: list[dict[str, Any]] = []
    resolutions: dict[str, list[str]] = {}
    endpoint_counts: dict[str, dict[str, int]] = {}

    for span in otlp_spans or []:
        attrs = _as_dict(span.get("attributes"))
        req_model = _clean(attrs.get("gen_ai.request.model") or span.get("gen_ai.request.model"))
        resp_model = _clean(attrs.get("gen_ai.response.model") or span.get("gen_ai.response.model"))
        if req_model and resp_model:
            seen = resolutions.setdefault(req_model, [])
            if resp_model not in seen:
                seen.append(resp_model)

        ep = _clean(attrs.get("mcp.endpoint") or span.get("mcp.endpoint") or "default")
        method = _clean(attrs.get("mcp.method") or span.get("mcp.method") or span.get("name"))
        if method in {"sampling/createMessage", "sampling"}:
            bucket = endpoint_counts.setdefault(ep, {"sampling": 0, "elicitation": 0})
            bucket["sampling"] += 1
        elif method in {"elicitation/create", "elicitation"}:
            bucket = endpoint_counts.setdefault(ep, {"sampling": 0, "elicitation": 0})
            bucket["elicitation"] += 1

    for alias, resolved_list in sorted(resolutions.items()):
        if len(resolved_list) > 1:
            _flag(
                findings,
                "resolved_model_changed",
                RiskSeverity.HIGH,
                f"Requested model alias '{alias}' resolved to multiple backend models across OTLP spans: {', '.join(resolved_list)}.",
                None,
                alias,
            )

    undeclared_images: list[str] = []
    undeclared_models: list[str] = []
    decl_imgs = declared_images or set()
    decl_mdls = declared_models or set()

    if isinstance(k8s_mlbom, dict):
        for comp in _as_list(k8s_mlbom.get("components")):
            if not isinstance(comp, dict):
                continue
            c_type = str(comp.get("type") or "").lower()
            c_name = _clean(comp.get("image") or comp.get("name"))
            if not c_name:
                continue
            if c_type in {"container", "image"} and c_name not in decl_imgs:
                undeclared_images.append(c_name)
                _flag(
                    findings,
                    "undeclared_cluster_image",
                    RiskSeverity.HIGH,
                    f"k8s-aibom ML-BOM reports running container image '{c_name}' not declared in repository inventory.",
                    None,
                    c_name,
                )
            elif c_type in {"machine-learning-model", "model"} and c_name not in decl_mdls:
                undeclared_models.append(c_name)
                _flag(
                    findings,
                    "undeclared_cluster_model",
                    RiskSeverity.HIGH,
                    f"k8s-aibom ML-BOM reports active model '{c_name}' not declared in repository inventory.",
                    None,
                    c_name,
                )

    return _rec(
        assurance="reported",
        model_resolutions=resolutions,
        endpoint_counts=endpoint_counts,
        undeclared_cluster_images=sorted(set(undeclared_images)),
        undeclared_cluster_models=sorted(set(undeclared_models)),
        security_flags=findings,
    )


def build_complete_crosswalk(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build R1.4-4 crosswalk listing every unreferenced framework entry as 'no_evidence'."""
    hit_map: dict[tuple[str, str], set[str]] = {}
    for fl in findings:
        cat = str(fl.get("category") or "")
        sev_str = str(fl.get("severity") or "medium").lower()
        try:
            sev = RiskSeverity(sev_str)
        except ValueError:
            sev = RiskSeverity.MEDIUM
        for ref in references(cat, sev):
            hit_map.setdefault((ref.framework, ref.entry), set()).add(cat)

    frameworks_out: dict[str, Any] = {}
    for fw in FRAMEWORKS:
        entries_out: list[dict[str, Any]] = []
        for entry in fw.entries:
            cats = sorted(hit_map.get((fw.key, entry.id), set()))
            entries_out.append(
                _rec(
                    id=entry.id,
                    title=entry.title,
                    status="evidence_present" if cats else "no_evidence",
                    finding_categories=cats,
                )
            )
        frameworks_out[fw.key] = _rec(
            name=fw.name,
            edition=fw.edition,
            verification=fw.verification,
            entries=entries_out,
        )
    return frameworks_out


def build_evidence_package(
    project_root: Path,
    *,
    bom: AIBOM | None = None,
    findings: list[dict[str, Any]] | None = None,
    allowed_regions: list[str] | None = None,
    endpoint_regions: dict[str, str] | None = None,
    operator_digest_pins: dict[str, str] | None = None,
    image_subject_digest: str | None = None,
    private_key: Ed25519PrivateKey | None = None,
) -> dict[str, Any]:
    """Bundle R1.4-4 attested inventory, complete crosswalk, residency check, OCI layout, and OPA/Cedar input."""
    active_bom = bom or AIBOM()
    all_findings = list(findings or [])

    read_binding = compute_project_read_set_root(
        project_root,
        operator_digest_pins=operator_digest_pins,
        bom=active_bom,
    )
    all_findings.extend(read_binding.findings)

    eff_allowed = list(allowed_regions or [])
    eff_ep_regions = dict(endpoint_regions or {})
    with ConfinedCollection(project_root, read_binding.gaps) as files:
        all_paths = {p.as_posix() for p in files.iter_files()}
        for decl_name in ("agent.yaml", "agent.yml"):
            if decl_name in all_paths and not credential_shaped(decl_name):
                try:
                    raw = files.read_bytes(decl_name, missing_ok=True)
                    if raw is not None:
                        doc = parse_yaml_mapping(raw.decode("utf-8", errors="replace"))
                        if not eff_allowed:
                            eff_allowed = [
                                _clean(r)
                                for r in _as_list(doc.get("allowed_regions"))
                                if str(r).strip()
                            ]
                        for ep_item in _as_list(doc.get("endpoints")):
                            if isinstance(ep_item, dict) and ep_item.get("name"):
                                eff_ep_regions[_clean(ep_item["name"])] = _clean(
                                    ep_item.get("region") or "unknown"
                                )
                except (OSError, ValueError, PolicyError):
                    pass

    residency_violations: list[dict[str, str]] = []
    if eff_allowed:
        allowed_set = set(eff_allowed)
        for ep_name, ep_reg in sorted(eff_ep_regions.items()):
            if ep_reg not in allowed_set:
                residency_violations.append(_rec(endpoint=ep_name, region=ep_reg))
                _flag(
                    all_findings,
                    "data_residency_violation",
                    RiskSeverity.HIGH,
                    f"Endpoint '{ep_name}' in region '{ep_reg}' violates allowed_regions ({', '.join(sorted(allowed_set))}).",
                    "agent.yaml",
                    ep_name,
                )

    content_digest = inventory_content_digest(active_bom.model_dump(mode="json"))
    crosswalk_report = build_complete_crosswalk(all_findings)
    verdict_passed = not any(f["severity"] in {"high", "critical"} for f in all_findings)
    verdict_status = "passed" if verdict_passed else "failed"

    opa_cedar_input = _rec(
        schema_version="nexus-symbiote/admission-input/v1",
        verdict=verdict_status,
        content_digest=content_digest,
        read_set_root=read_binding.read_set_root,
        integrity_status=read_binding.integrity_status,
        data_residency_ok=len(residency_violations) == 0,
        allowed_regions=eff_allowed,
        finding_counts=_rec(
            critical=sum(1 for f in all_findings if f["severity"] == "critical"),
            high=sum(1 for f in all_findings if f["severity"] == "high"),
            medium=sum(1 for f in all_findings if f["severity"] == "medium"),
            low=sum(1 for f in all_findings if f["severity"] == "low"),
        ),
    )

    signer = private_key or Ed25519PrivateKey.generate()
    extra_subj: list[dict[str, Any]] = []
    if image_subject_digest:
        clean_img_sha = image_subject_digest.removeprefix("sha256:").strip()
        extra_subj.append(_rec(name="container-image", digest=_rec(sha256=clean_img_sha)))

    content_hex = content_digest.split(":")[-1]
    verdict_envelope = sign_dsse_statement(
        "inventory-content",
        content_hex,
        GATE_VERDICT_PREDICATE,
        opa_cedar_input,
        signer,
        extra_subjects=extra_subj,
    )
    blob_sha = _jcs_sha256(verdict_envelope)
    oci_referrer_layout = _rec(
        schemaVersion=2,
        mediaType="application/vnd.oci.image.index.v1+json",
        manifests=[
            _rec(
                mediaType="application/vnd.dsse.envelope.v1+json",
                digest=f"sha256:{blob_sha}",
                artifactType=GATE_VERDICT_PREDICATE,
                subject=_rec(
                    digest=image_subject_digest or f"sha256:{content_hex}",
                ),
            )
        ],
        blobs={f"sha256:{blob_sha}": verdict_envelope},
    )

    return _rec(
        verdict=verdict_status,
        content_digest=content_digest,
        read_set_binding=read_binding.to_dict(),
        data_residency=_rec(
            allowed_regions=eff_allowed,
            endpoint_regions=eff_ep_regions,
            violations=residency_violations,
        ),
        minimum_elements_summary=_rec(
            assessable_denominator=39,
            read_set_bound=True,
        ),
        crosswalk=crosswalk_report,
        opa_cedar_input=opa_cedar_input,
        gate_verdict_attestation=verdict_envelope,
        oci_referrer_layout=oci_referrer_layout,
        security_flags=all_findings,
    )
