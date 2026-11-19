"""Deterministic MCP contract lockfiles for MCP 2026-07-28, 2025-11-25, and 2025-06-18.

Pins every MCP server's protocol revision, identity, and exact tool descriptors
(name, raw description, title, inputSchema, outputSchema, _meta, and annotations)
using canonical RFC 8785-compatible JSON digests so a one-character description change,
new tool, removed tool, schema/meta mutation, annotation drift, or protocol downgrade
fails CI deterministically and offline.
"""

from __future__ import annotations

import hmac
import os
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import (
    hash_bytes,
    hash_canonical,
    open_regular_file,
    parse_json_strict,
)
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent

MCPProtocolVersion = Literal["2026-07-28", "2025-11-25", "2025-06-18"]
LOCKFILE_FORMAT: Literal["nexus-symbiote/mcp-contract-lock/v1"] = (
    "nexus-symbiote/mcp-contract-lock/v1"
)
SUPPORTED_MCP_PROTOCOLS: tuple[MCPProtocolVersion, ...] = (
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
)
DEFAULT_MCP_PROTOCOL: MCPProtocolVersion = "2026-07-28"

MAX_LOCKFILE_BYTES = 8 * 1024 * 1024
MAX_SERVERS = 500
MAX_TOOLS_PER_SERVER = 5_000
MAX_KEY_BYTES = 64 * 1024

# Conservative MCP 2026-07-28 defaults when annotations are omitted by a server.
CONSERVATIVE_ANNOTATION_DEFAULTS: dict[str, bool] = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}


class MCPContractLockError(ValueError):
    """Raised when an MCP contract lockfile, snapshot, key, or attestation is unsafe or invalid."""


def _validate_identifier(value: str, label: str) -> str:
    if not value.strip() or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError(f"{label} must be non-empty without control characters")
    return value


class PinnedToolContract(BaseModel):
    """Exact canonical pin for one MCP tool descriptor."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=256)
    title: str | None = Field(default=None, max_length=1_024)
    description: str = Field(default="", max_length=65_536)
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    meta: dict[str, Any] | None = None
    annotations: dict[str, Any] = Field(default_factory=dict)
    effective_annotations: dict[str, bool] = Field(default_factory=dict)
    description_sha256: str
    schema_sha256: str
    annotations_sha256: str
    contract_sha256: str

    @field_validator("name")
    @classmethod
    def _clean_name(cls, value: str) -> str:
        return _validate_identifier(value, "tool name")


class PinnedServerContract(BaseModel):
    """Exact canonical pin for one MCP server and all of its tools."""

    model_config = ConfigDict(extra="forbid")

    server_ref: str = Field(min_length=1, max_length=512)
    server_name: str = Field(min_length=1, max_length=256)
    protocol_version: MCPProtocolVersion
    transport: str = Field(default="stdio", max_length=64)
    endpoint: str | None = Field(default=None, max_length=1_024)
    tools: list[PinnedToolContract] = Field(default_factory=list)
    server_contract_sha256: str

    @field_validator("server_ref", "server_name")
    @classmethod
    def _clean_server_id(cls, value: str) -> str:
        return _validate_identifier(value, "server identifier")

    @model_validator(mode="after")
    def _check_unique_tools(self) -> PinnedServerContract:
        if len(self.tools) > MAX_TOOLS_PER_SERVER:
            raise ValueError(f"server exceeds {MAX_TOOLS_PER_SERVER} tools")
        seen: set[str] = set()
        for tool in self.tools:
            if tool.name in seen:
                raise ValueError(
                    f"duplicate pinned tool {tool.name!r} in server {self.server_ref!r}"
                )
            seen.add(tool.name)
        return self


class MCPContractLockfile(BaseModel):
    """Deterministic MCP contract lockfile across one or more servers."""

    model_config = ConfigDict(extra="forbid")

    format: Literal["nexus-symbiote/mcp-contract-lock/v1"] = LOCKFILE_FORMAT
    supported_protocols: list[MCPProtocolVersion] = Field(
        default_factory=lambda: list(SUPPORTED_MCP_PROTOCOLS)
    )
    inventory_sha256: str | None = None
    servers: list[PinnedServerContract] = Field(default_factory=list)
    lockfile_content_sha256: str

    @model_validator(mode="after")
    def _check_unique_servers(self) -> MCPContractLockfile:
        if len(self.servers) > MAX_SERVERS:
            raise ValueError(f"lockfile exceeds {MAX_SERVERS} servers")
        seen: set[str] = set()
        for srv in self.servers:
            if srv.server_ref in seen:
                raise ValueError(f"duplicate server_ref {srv.server_ref!r}")
            seen.add(srv.server_ref)
        return self

    def server_map(self) -> dict[str, PinnedServerContract]:
        return {srv.server_ref: srv for srv in self.servers}


@dataclass(frozen=True)
class ContractDriftFinding:
    """One deterministic drift finding between a pinned lockfile and a candidate contract."""

    server_ref: str
    code: str
    severity: Literal["critical", "high", "medium"]
    tool_name: str | None
    detail: str
    expected_sha256: str | None = None
    actual_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ContractVerificationReport:
    """Outcome of verifying a candidate snapshot or AIBOM against a pinned MCP contract lockfile."""

    passed: bool
    lockfile_sha256: str
    servers_checked: int
    tools_checked: int
    findings: tuple[ContractDriftFinding, ...]
    attested: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "nexus-symbiote/mcp-contract-verify/v1",
            "passed": self.passed,
            "attested": self.attested,
            "lockfile_sha256": self.lockfile_sha256,
            "servers_checked": self.servers_checked,
            "tools_checked": self.tools_checked,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def _repository_roots(path: Path) -> list[Path]:
    return [cand for cand in (path, *path.parents) if os.path.lexists(cand / ".git")]


def _safe_stat(path: Path) -> os.stat_result | None:
    try:
        return path.stat()
    except OSError:
        return None


def ensure_outside_project(
    file_path: Path,
    project_root: Path | None,
    *,
    inventory_path: Path | None = None,
    forbid_inventory_dir: bool = False,
    label: str = "MCP contract lockfile",
) -> None:
    """Refuse policy, lockfile, attestation, or key files inside the untrusted project/git tree."""
    resolved = file_path.resolve()
    untrusted: list[Path] = []
    if project_root is not None:
        r_root = project_root.resolve()
        untrusted.append(r_root)
        untrusted.extend(_repository_roots(r_root))
    if inventory_path is not None:
        inv_dir = inventory_path.resolve().parent
        untrusted.extend(_repository_roots(inv_dir))
        if forbid_inventory_dir:
            untrusted.append(inv_dir)
    untrusted.extend(_repository_roots(Path.cwd().resolve()))

    msg = f"{label} must live outside the scanned project and enclosing git repositories"
    if any(resolved.is_relative_to(root) for root in untrusted):
        raise MCPContractLockError(msg)
    if os.name == "posix" and untrusted:
        untrusted_ids = {
            (st.st_dev, st.st_ino) for root in untrusted if (st := _safe_stat(root)) is not None
        }
        if any(
            (st.st_dev, st.st_ino) in untrusted_ids
            for parent in resolved.parents
            if (st := _safe_stat(parent)) is not None
        ):
            raise MCPContractLockError(msg)


def _read_regular(path: Path, max_bytes: int, label: str, *, single_link: bool = False) -> bytes:
    try:
        with open_regular_file(path) as handle:
            if single_link and os.name == "posix" and os.fstat(handle.fileno()).st_nlink != 1:
                raise MCPContractLockError(f"{label} must not have additional hard links")
            raw = handle.read(max_bytes + 1)
    except OSError as exc:
        raise MCPContractLockError(f"Cannot safely read {label.lower()}: {exc}") from exc
    if len(raw) > max_bytes:
        raise MCPContractLockError(f"{label} exceeds {max_bytes} bytes")
    return raw


def _effective_annotations(raw: Mapping[str, Any]) -> dict[str, bool]:
    eff = dict(CONSERVATIVE_ANNOTATION_DEFAULTS)
    for key in CONSERVATIVE_ANNOTATION_DEFAULTS:
        val = raw.get(key)
        if isinstance(val, bool):
            eff[key] = val
    return eff


def pin_tool_descriptor(tool: Mapping[str, Any]) -> PinnedToolContract:
    """Build a canonical digest-pinned contract for one MCP tool descriptor.

    Descriptions and titles are hashed verbatim without stripping or Unicode normalization so
    even a single whitespace or invisible character mutation changes the digest.
    """
    name = tool.get("name")
    if not isinstance(name, str) or not name.strip():
        raise MCPContractLockError("MCP tool descriptor requires a non-empty string 'name'")
    raw_title = tool.get("title")
    if raw_title is not None and not isinstance(raw_title, str):
        raise MCPContractLockError(f"MCP tool {name!r} 'title' must be a string or null")
    raw_desc = tool.get("description", "")
    raw_desc = "" if raw_desc is None else raw_desc
    if not isinstance(raw_desc, str):
        raise MCPContractLockError(f"MCP tool {name!r} 'description' must be a string")
    raw_input = tool.get("inputSchema", tool.get("input_schema", {}))
    raw_input = {} if raw_input is None else raw_input
    if not isinstance(raw_input, dict):
        raise MCPContractLockError(f"MCP tool {name!r} 'inputSchema' must be an object")
    raw_output = tool.get("outputSchema", tool.get("output_schema"))
    if raw_output is not None and not isinstance(raw_output, dict):
        raise MCPContractLockError(f"MCP tool {name!r} 'outputSchema' must be an object or null")
    raw_meta = tool.get("_meta", tool.get("meta"))
    if raw_meta is not None and not isinstance(raw_meta, dict):
        raise MCPContractLockError(f"MCP tool {name!r} '_meta' must be an object or null")
    raw_ann = tool.get("annotations", {})
    raw_ann = {} if raw_ann is None else raw_ann
    if not isinstance(raw_ann, dict):
        raise MCPContractLockError(f"MCP tool {name!r} 'annotations' must be an object")

    eff_ann = _effective_annotations(raw_ann)
    desc_obj: dict[str, Any] = {"description": raw_desc}
    if raw_title is not None:
        desc_obj["title"] = raw_title
    schema_obj: dict[str, Any] = {"inputSchema": raw_input, "outputSchema": raw_output}
    if raw_meta is not None:
        schema_obj["_meta"] = raw_meta
    desc_hash = hash_canonical(desc_obj)
    schema_hash = hash_canonical(schema_obj)
    ann_hash = hash_canonical({"annotations": raw_ann, "effective": eff_ann})
    contract_hash = hash_canonical(
        {
            "name": name,
            "description_sha256": desc_hash,
            "schema_sha256": schema_hash,
            "annotations_sha256": ann_hash,
        }
    )
    return PinnedToolContract(
        name=name,
        title=raw_title,
        description=raw_desc,
        input_schema=raw_input,
        output_schema=raw_output,
        meta=raw_meta,
        annotations=raw_ann,
        effective_annotations=eff_ann,
        description_sha256=desc_hash,
        schema_sha256=schema_hash,
        annotations_sha256=ann_hash,
        contract_sha256=contract_hash,
    )


def _validate_protocol(protocol_version: str) -> MCPProtocolVersion:
    if protocol_version not in SUPPORTED_MCP_PROTOCOLS:
        supported = ", ".join(SUPPORTED_MCP_PROTOCOLS)
        raise MCPContractLockError(
            f"Unsupported MCP protocol_version {protocol_version!r}; supported: {supported}"
        )
    return protocol_version


def build_server_contract(
    *,
    server_ref: str,
    server_name: str,
    protocol_version: str,
    tools: Sequence[Mapping[str, Any]],
    transport: str = "stdio",
    endpoint: str | None = None,
) -> PinnedServerContract:
    """Build a canonical pinned server contract from raw MCP tool descriptors."""
    proto = _validate_protocol(protocol_version)
    if len(tools) > MAX_TOOLS_PER_SERVER:
        raise MCPContractLockError(
            f"Server {server_ref!r} exceeds maximum tool limit ({MAX_TOOLS_PER_SERVER})"
        )
    pinned = sorted((pin_tool_descriptor(t) for t in tools), key=lambda item: item.name)
    seen: set[str] = set()
    for tool in pinned:
        if tool.name in seen:
            raise MCPContractLockError(
                f"Duplicate tool name {tool.name!r} on server {server_ref!r}"
            )
        seen.add(tool.name)
    srv_hash = hash_canonical(
        {
            "server_ref": server_ref,
            "server_name": server_name,
            "protocol_version": proto,
            "transport": transport,
            "endpoint": endpoint,
            "tools": [t.contract_sha256 for t in pinned],
        }
    )
    return PinnedServerContract(
        server_ref=server_ref,
        server_name=server_name,
        protocol_version=proto,
        transport=transport,
        endpoint=endpoint,
        tools=pinned,
        server_contract_sha256=srv_hash,
    )


def _tool_component_to_raw(comp: ToolComponent) -> dict[str, Any]:
    props = comp.properties if isinstance(comp.properties, dict) else {}
    annotations = (
        dict(comp.annotations)
        if comp.annotations
        else (dict(props["annotations"]) if isinstance(props.get("annotations"), dict) else {})
    )
    description = (
        comp.description_text if comp.description_text is not None else (comp.description or "")
    )
    return {
        "name": comp.name,
        "title": props.get("title") if isinstance(props.get("title"), str) else None,
        "description": description,
        "inputSchema": comp.input_schema or {},
        "outputSchema": props.get("output_schema") or props.get("outputSchema"),
        "_meta": props.get("_meta") if isinstance(props.get("_meta"), dict) else None,
        "annotations": annotations,
    }


def _servers_from_aibom(
    bom: AIBOM, *, default_protocol: str = DEFAULT_MCP_PROTOCOL
) -> list[PinnedServerContract]:
    tools_by_ref: dict[str, ToolComponent] = {}
    tools_by_server: dict[str, list[dict[str, Any]]] = {}
    seen_refs: dict[str, set[str]] = {}
    for comp in bom.components:
        if isinstance(comp, ToolComponent):
            tools_by_ref[comp.bom_ref] = comp
            if comp.mcp_server_ref:
                tools_by_server.setdefault(comp.mcp_server_ref, []).append(
                    _tool_component_to_raw(comp)
                )
                seen_refs.setdefault(comp.mcp_server_ref, set()).add(comp.bom_ref)
    contracts: list[PinnedServerContract] = []
    for comp in sorted(bom.components, key=lambda c: c.bom_ref):
        if not isinstance(comp, MCPServerComponent):
            continue
        props = comp.properties if isinstance(comp.properties, dict) else {}
        proto = (
            props.get("protocol_version") or props.get("mcp_protocol_version") or default_protocol
        )
        if not isinstance(proto, str):
            raise MCPContractLockError(f"Invalid protocol_version on server {comp.bom_ref!r}")
        raw_tools = list(tools_by_server.get(comp.bom_ref, ()))
        already = seen_refs.get(comp.bom_ref, set())
        for tref in comp.tool_refs:
            if tref not in already and (linked := tools_by_ref.get(tref)) is not None:
                raw_tools.append(_tool_component_to_raw(linked))
                already = already | {tref}
        contracts.append(
            build_server_contract(
                server_ref=comp.bom_ref,
                server_name=comp.name,
                protocol_version=proto,
                tools=raw_tools,
                transport=str(comp.transport or "stdio"),
                endpoint=comp.endpoint_url,
            )
        )
    return contracts


def create_lockfile_from_servers(
    servers: Sequence[PinnedServerContract], *, inventory_sha256: str | None = None
) -> MCPContractLockfile:
    """Assemble a deterministic MCP contract lockfile from pinned server contracts."""
    ordered = sorted(servers, key=lambda s: s.server_ref)
    content_hash = hash_canonical(
        {"format": LOCKFILE_FORMAT, "servers": [s.server_contract_sha256 for s in ordered]}
    )
    return MCPContractLockfile(
        inventory_sha256=inventory_sha256,
        servers=ordered,
        lockfile_content_sha256=content_hash,
    )


def create_lockfile_from_aibom(
    bom: AIBOM,
    *,
    protocol_version: str = DEFAULT_MCP_PROTOCOL,
    inventory_sha256: str | None = None,
) -> MCPContractLockfile:
    """Create a deterministic MCP contract lockfile from an AgentBOM."""
    _validate_protocol(protocol_version)
    return create_lockfile_from_servers(
        _servers_from_aibom(bom, default_protocol=protocol_version),
        inventory_sha256=inventory_sha256,
    )


def parse_snapshot_servers(payload: Mapping[str, Any]) -> list[PinnedServerContract]:
    """Parse an MCP server/tools snapshot JSON object into pinned server contracts."""
    raw_servers = payload.get("servers")
    if not isinstance(raw_servers, list):
        raise MCPContractLockError("MCP snapshot must be an object with a 'servers' array")
    if len(raw_servers) > MAX_SERVERS:
        raise MCPContractLockError(f"MCP snapshot exceeds {MAX_SERVERS} servers")
    contracts: list[PinnedServerContract] = []
    for entry in raw_servers:
        if not isinstance(entry, dict):
            raise MCPContractLockError("Each MCP snapshot server entry must be an object")
        sref = entry.get("server_ref")
        sname = entry.get("server_name") or sref
        proto = entry.get("protocol_version")
        raw_tools = entry.get("tools", [])
        if not isinstance(sref, str) or not sref.strip() or not isinstance(sname, str):
            raise MCPContractLockError("MCP snapshot server requires string 'server_ref'")
        if not isinstance(proto, str):
            raise MCPContractLockError(f"MCP snapshot server {sref!r} requires 'protocol_version'")
        if not isinstance(raw_tools, list) or not all(isinstance(t, dict) for t in raw_tools):
            raise MCPContractLockError(
                f"MCP snapshot server {sref!r} 'tools' must be a list of objects"
            )
        contracts.append(
            build_server_contract(
                server_ref=sref.strip(),
                server_name=sname.strip(),
                protocol_version=proto.strip(),
                tools=raw_tools,
                transport=str(entry.get("transport") or "stdio"),
                endpoint=entry.get("endpoint") if isinstance(entry.get("endpoint"), str) else None,
            )
        )
    return contracts


def load_mcp_lockfile(
    path: Path,
    *,
    project_root: Path | None = None,
    inventory_path: Path | None = None,
    attestation_path: Path | None = None,
    trusted_key_paths: Sequence[Path] = (),
    allow_unsigned: bool = False,
) -> tuple[MCPContractLockfile, str, bool]:
    """Load an operator-owned MCP contract lockfile, requiring Ed25519 DSSE attestation by default."""

    def check_outside(target: Path, label: str) -> None:
        ensure_outside_project(
            target,
            project_root,
            inventory_path=inventory_path,
            forbid_inventory_dir=True,
            label=label,
        )

    check_outside(path, "MCP contract lockfile")
    raw = _read_regular(path, MAX_LOCKFILE_BYTES, "MCP contract lockfile", single_link=True)
    if attestation_path is None:
        if not allow_unsigned:
            raise MCPContractLockError(
                "MCP contract lockfile requires --lockfile-attestation and --trusted-key "
                "(or explicit --allow-unsigned-lockfile)"
            )
        attested = False
    else:
        from nexus_symbiote.attestation import (
            MAX_ENVELOPE_BYTES,
            AttestationError,
            parse_envelope,
            verify_attestation,
        )
        from nexus_symbiote.runtime import key_id

        if not trusted_key_paths:
            raise MCPContractLockError("--lockfile-attestation requires at least one --trusted-key")
        check_outside(attestation_path, "Lockfile attestation")
        ring: dict[str, Ed25519PublicKey] = {}
        for kpath in trusted_key_paths:
            check_outside(kpath, "Trusted key file")
            kbytes = _read_regular(kpath, MAX_KEY_BYTES, "Trusted key file", single_link=True)
            try:
                pub = serialization.load_pem_public_key(kbytes)
            except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
                raise MCPContractLockError("Trusted key must be an Ed25519 PEM") from exc
            if not isinstance(pub, Ed25519PublicKey):
                raise MCPContractLockError("Only Ed25519 public keys are supported")
            ring[key_id(pub)] = pub
        env_bytes = _read_regular(
            attestation_path, MAX_ENVELOPE_BYTES, "Lockfile attestation", single_link=True
        )
        try:
            verify_attestation(
                parse_envelope(env_bytes), raw, trusted_keys=ring, purpose="reviewed", match="bytes"
            )
        except AttestationError as exc:
            raise MCPContractLockError(f"Lockfile attestation verification failed: {exc}") from exc
        attested = True

    try:
        doc = parse_json_strict(raw.decode("utf-8"), max_bytes=MAX_LOCKFILE_BYTES)
        lockfile = MCPContractLockfile.model_validate(doc)
    except Exception as exc:
        raise MCPContractLockError(f"Invalid MCP contract lockfile: {exc}") from exc

    # Recompute every tool, server, and lockfile digest so no field can mask mutated descriptors.
    rebuilt = create_lockfile_from_servers(
        [
            build_server_contract(
                server_ref=srv.server_ref,
                server_name=srv.server_name,
                protocol_version=srv.protocol_version,
                tools=[
                    {
                        "name": t.name,
                        "title": t.title,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                        "outputSchema": t.output_schema,
                        "_meta": t.meta,
                        "annotations": t.annotations,
                    }
                    for t in srv.tools
                ],
                transport=srv.transport,
                endpoint=srv.endpoint,
            )
            for srv in lockfile.servers
        ],
        inventory_sha256=lockfile.inventory_sha256,
    )
    if not hmac.compare_digest(
        hash_canonical(rebuilt.model_dump(mode="json")),
        hash_canonical(lockfile.model_dump(mode="json")),
    ):
        raise MCPContractLockError("MCP contract lockfile internal digest or metadata mismatch")
    return lockfile, hash_bytes(raw), attested


def verify_contracts(
    lockfile: MCPContractLockfile,
    candidate_servers: Sequence[PinnedServerContract],
    *,
    lockfile_sha256: str,
    attested: bool = False,
) -> ContractVerificationReport:
    """Compare candidate MCP server contracts against a pinned lockfile in linear O(S + T) time."""
    expected_map = lockfile.server_map()
    actual_map: dict[str, PinnedServerContract] = {}
    findings: list[ContractDriftFinding] = []

    def add(
        sref: str,
        code: str,
        sev: Literal["critical", "high", "medium"],
        tname: str | None,
        detail: str,
        exp_sha: str | None = None,
        act_sha: str | None = None,
    ) -> None:
        findings.append(ContractDriftFinding(sref, code, sev, tname, detail, exp_sha, act_sha))

    for srv in candidate_servers:
        if srv.server_ref in actual_map:
            add(srv.server_ref, "duplicate_server", "critical", None, "Duplicate server_ref")
            continue
        actual_map[srv.server_ref] = srv

    tools_checked = 0
    for sref in sorted(set(expected_map) | set(actual_map)):
        exp, act = expected_map.get(sref), actual_map.get(sref)
        if exp is None and act is not None:
            add(
                sref,
                "server_added",
                "high",
                None,
                f"Unpinned server {sref!r}",
                act_sha=act.server_contract_sha256,
            )
            continue
        if act is None and exp is not None:
            add(
                sref,
                "server_removed",
                "high",
                None,
                f"Pinned server {sref!r} missing",
                exp_sha=exp.server_contract_sha256,
            )
            continue
        assert exp is not None and act is not None
        if exp.protocol_version != act.protocol_version:
            add(
                sref,
                "protocol_version_changed",
                "high",
                None,
                f"Protocol drifted from {exp.protocol_version} to {act.protocol_version}",
            )
        exp_tools = {t.name: t for t in exp.tools}
        act_tools = {t.name: t for t in act.tools}
        for tname in sorted(set(exp_tools) | set(act_tools)):
            tools_checked += 1
            et, at = exp_tools.get(tname), act_tools.get(tname)
            if et is None and at is not None:
                add(
                    sref,
                    "tool_added",
                    "high",
                    tname,
                    f"Unpinned tool {tname!r} added",
                    act_sha=at.contract_sha256,
                )
            elif at is None and et is not None:
                add(
                    sref,
                    "tool_removed",
                    "high",
                    tname,
                    f"Pinned tool {tname!r} removed",
                    exp_sha=et.contract_sha256,
                )
            elif et is not None and at is not None:
                checks: tuple[
                    tuple[str, str, str, Literal["critical", "high", "medium"], str], ...
                ] = (
                    (
                        et.description_sha256,
                        at.description_sha256,
                        "tool_description_changed",
                        "critical",
                        f"Tool {tname!r} description/title changed",
                    ),
                    (
                        et.schema_sha256,
                        at.schema_sha256,
                        "tool_schema_changed",
                        "high",
                        f"Tool {tname!r} input/output schema or _meta drifted",
                    ),
                    (
                        et.annotations_sha256,
                        at.annotations_sha256,
                        "tool_annotations_changed",
                        "high",
                        f"Tool {tname!r} MCP annotations drifted",
                    ),
                )
                for exp_sha, act_sha, code, sev, detail in checks:
                    if not hmac.compare_digest(exp_sha, act_sha):
                        add(sref, code, sev, tname, detail, exp_sha, act_sha)
    return ContractVerificationReport(
        passed=not findings,
        lockfile_sha256=lockfile_sha256,
        servers_checked=len(set(expected_map) | set(actual_map)),
        tools_checked=tools_checked,
        findings=tuple(findings),
        attested=attested,
    )
