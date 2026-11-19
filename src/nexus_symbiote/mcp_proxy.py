"""Opt-in, unprivileged MCP contract-pinning proxy with Ed25519-signed decision records.

Filters MCP JSON-RPC 2.0 traffic against an operator-pinned MCP contract lockfile:
- Intercepts upstream ``initialize`` responses to block protocol downgrades.
- Intercepts upstream ``tools/list`` responses BEFORE the model sees them: a 1-character
  description/title mutation, added tool, removed tool, duplicate tool name, schema/_meta
  change, annotation drift, or paginated ``nextCursor`` smuggling is blocked with JSON-RPC
  error ``-32001`` and trips a fail-closed session drift latch.
- Intercepts ``notifications/tools/list_changed`` to require fresh ``tools/list``
  re-verification before any subsequent ``tools/call``.
- Intercepts client ``tools/call`` requests: blocks unpinned tools, calls awaiting
  re-verification, or any traffic after a session contract drift violation.
- Emits deterministic Ed25519-signed decision records (verifiable offline) recording only
  tool names, digests, and verdicts — never raw tool argument values or secrets.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from nexus_symbiote.core.hashing import hash_canonical, open_regular_file, parse_json_strict
from nexus_symbiote.mcp_contract_lock import (
    MAX_TOOLS_PER_SERVER,
    MCPContractLockError,
    PinnedServerContract,
    PinnedToolContract,
    pin_tool_descriptor,
)
from nexus_symbiote.runtime import ContractSigner, canonical_bytes, key_id

DECISION_FORMAT = "nexus-symbiote/mcp-proxy-decision/v1"
DECISION_DOMAIN = b"nexus-symbiote/mcp-proxy-decision/v1\x00"
CONTRACT_VIOLATION_CODE = -32001
INVALID_REQUEST_CODE = -32600
MAX_RPC_LINE_BYTES = 1 * 1024 * 1024
MAX_PRIVATE_KEY_BYTES = 64 * 1024


class MCPProxyError(ValueError):
    """Raised when proxy configuration, signing keys, or decision verification fails."""


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    """Load an owner-only Ed25519 private key PEM (mode 0600 on POSIX, no symlinks/hard links)."""
    try:
        with open_regular_file(path) as handle:
            if os.name == "posix":
                info = os.fstat(handle.fileno())
                if info.st_nlink != 1:
                    raise MCPProxyError("Signing key must not have additional hard links")
                if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()}:
                    raise MCPProxyError("Signing key must be owned by the current user or root")
                if info.st_mode & 0o077:
                    raise MCPProxyError("Signing key must deny group and other permissions (0600)")
            raw = handle.read(MAX_PRIVATE_KEY_BYTES + 1)
    except OSError as exc:
        raise MCPProxyError(f"Cannot safely read signing key: {exc}") from exc
    if len(raw) > MAX_PRIVATE_KEY_BYTES:
        raise MCPProxyError("Signing key file exceeds size limit")
    try:
        private = serialization.load_pem_private_key(raw, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise MCPProxyError(
            "Signing key could not be loaded as an unencrypted Ed25519 PEM"
        ) from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise MCPProxyError("Only Ed25519 private keys are supported")
    return private


def sign_decision_payload(payload: Mapping[str, Any], signer: ContractSigner) -> dict[str, Any]:
    """Sign a canonical proxy decision record with domain separation."""
    pub = signer.public_key()
    if not isinstance(pub, Ed25519PublicKey):
        raise MCPProxyError("Proxy decision signer must be Ed25519")
    body = dict(payload)
    sig = signer.sign(DECISION_DOMAIN + canonical_bytes(body))
    return {
        "format": DECISION_FORMAT,
        "decision": body,
        "signature": {
            "algorithm": "ed25519",
            "keyid": key_id(pub),
            "sig": base64.b64encode(sig).decode("ascii"),
        },
    }


def verify_decision_record(
    envelope: Mapping[str, Any],
    trusted_keys: Mapping[str, Ed25519PublicKey],
) -> dict[str, Any]:
    """Verify an Ed25519-signed proxy decision record offline against trusted public keys."""
    if envelope.get("format") != DECISION_FORMAT:
        raise MCPProxyError("Unsupported proxy decision record format")
    decision = envelope.get("decision")
    sig_block = envelope.get("signature")
    if not isinstance(decision, dict) or not isinstance(sig_block, dict):
        raise MCPProxyError("Malformed proxy decision record")
    if sig_block.get("algorithm") != "ed25519":
        raise MCPProxyError("Unsupported decision signature algorithm")
    kid, raw_sig = sig_block.get("keyid"), sig_block.get("sig")
    if not isinstance(kid, str) or not isinstance(raw_sig, str):
        raise MCPProxyError("Missing keyid or sig on proxy decision record")
    pub = trusted_keys.get(kid)
    if pub is None:
        raise MCPProxyError(f"Untrusted proxy decision signer keyid {kid!r}")
    try:
        sig_bytes = base64.b64decode(raw_sig.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise MCPProxyError("Malformed base64 signature") from exc
    try:
        pub.verify(sig_bytes, DECISION_DOMAIN + canonical_bytes(decision))
    except InvalidSignature as exc:
        raise MCPProxyError("Proxy decision record signature verification failed") from exc
    return decision


@dataclass(frozen=True)
class ProxyDecisionOutcome:
    """Result of filtering one MCP JSON-RPC message through ContractPinningProxy."""

    allowed: bool
    message: dict[str, Any]
    decision_record: dict[str, Any]
    reasons: tuple[str, ...] = ()


class ContractPinningProxy:
    """Stateful fail-closed MCP JSON-RPC 2.0 contract-pinning filter for one pinned server."""

    def __init__(
        self,
        server_contract: PinnedServerContract,
        *,
        lockfile_sha256: str,
        signer: ContractSigner,
    ) -> None:
        self._server = server_contract
        self._lockfile_sha256 = lockfile_sha256
        self._signer = signer
        self._pinned_tools: dict[str, PinnedToolContract] = {
            t.name: t for t in server_contract.tools
        }
        self._drift_latched = False
        self._reverify_required = False
        self._sequence = 0

    @property
    def drift_latched(self) -> bool:
        return self._drift_latched

    def _emit_decision(
        self,
        *,
        event: Literal["initialize", "tools/list", "tools/call", "rpc"],
        verdict: Literal["allow", "deny"],
        reasons: list[str],
        tool_name: str | None = None,
        contract_sha256: str | None = None,
        arguments_sha256: str | None = None,
        rpc_id: Any = None,
    ) -> dict[str, Any]:
        self._sequence += 1
        payload: dict[str, Any] = {
            "sequence": self._sequence,
            "timestamp": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "server_ref": self._server.server_ref,
            "protocol_version": self._server.protocol_version,
            "lockfile_sha256": self._lockfile_sha256,
            "event": event,
            "verdict": verdict,
            "reasons": sorted(set(reasons)),
            "tool_name": tool_name,
            "contract_sha256": contract_sha256,
            "arguments_sha256": arguments_sha256,
            "rpc_id": rpc_id if isinstance(rpc_id, (str, int)) else None,
        }
        return sign_decision_payload(payload, self._signer)

    def _allow(
        self,
        event: Literal["initialize", "tools/list", "tools/call", "rpc"],
        message: Mapping[str, Any],
        *,
        reasons: list[str] | None = None,
        tool_name: str | None = None,
        contract_sha256: str | None = None,
        arguments_sha256: str | None = None,
        rpc_id: Any = None,
    ) -> ProxyDecisionOutcome:
        return ProxyDecisionOutcome(
            allowed=True,
            message=dict(message),
            decision_record=self._emit_decision(
                event=event,
                verdict="allow",
                reasons=reasons or [],
                tool_name=tool_name,
                contract_sha256=contract_sha256,
                arguments_sha256=arguments_sha256,
                rpc_id=rpc_id,
            ),
        )

    def _deny(
        self,
        event: Literal["initialize", "tools/list", "tools/call", "rpc"],
        code: int,
        message: str,
        reasons: list[str],
        *,
        rpc_id: Any = None,
        tool_name: str | None = None,
        contract_sha256: str | None = None,
        arguments_sha256: str | None = None,
        latch_drift: bool = False,
    ) -> ProxyDecisionOutcome:
        if latch_drift:
            self._drift_latched = True
        dedup = sorted(set(reasons))
        err_msg = {
            "jsonrpc": "2.0",
            "id": rpc_id if isinstance(rpc_id, (str, int)) else None,
            "error": {
                "code": code,
                "message": message,
                "data": {"server_ref": self._server.server_ref, "reasons": dedup},
            },
        }
        return ProxyDecisionOutcome(
            allowed=False,
            message=err_msg,
            decision_record=self._emit_decision(
                event=event,
                verdict="deny",
                reasons=dedup,
                tool_name=tool_name,
                contract_sha256=contract_sha256,
                arguments_sha256=arguments_sha256,
                rpc_id=rpc_id,
            ),
            reasons=tuple(dedup),
        )

    def filter_initialize_response(self, response: Mapping[str, Any]) -> ProxyDecisionOutcome:
        """Verify an upstream ``initialize`` response matches the pinned MCP protocol revision."""
        rpc_id, result = response.get("id"), response.get("result")
        proto = result.get("protocolVersion") if isinstance(result, dict) else None
        if not isinstance(proto, str) or proto != self._server.protocol_version:
            msg = f"MCP contract violation: protocolVersion {proto!r} != {self._server.protocol_version!r}"
            return self._deny(
                "initialize",
                CONTRACT_VIOLATION_CODE,
                msg,
                ["protocol_version_mismatch"],
                rpc_id=rpc_id,
                contract_sha256=self._server.server_contract_sha256,
                latch_drift=True,
            )
        return self._allow(
            "initialize",
            response,
            contract_sha256=self._server.server_contract_sha256,
            rpc_id=rpc_id,
        )

    def filter_tools_list_response(self, response: Mapping[str, Any]) -> ProxyDecisionOutcome:
        """Verify an upstream ``tools/list`` JSON-RPC response before forwarding to the model."""
        rpc_id, result = response.get("id"), response.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return self._deny(
                "tools/list",
                CONTRACT_VIOLATION_CODE,
                "Malformed tools/list",
                ["malformed_tools_list_response"],
                rpc_id=rpc_id,
                latch_drift=True,
            )
        if result.get("nextCursor"):
            return self._deny(
                "tools/list",
                CONTRACT_VIOLATION_CODE,
                "Paginated tools/list with nextCursor refused",
                ["paginated_tools_list_refused"],
                rpc_id=rpc_id,
                latch_drift=True,
            )
        raw_tools = result["tools"]
        if len(raw_tools) > MAX_TOOLS_PER_SERVER:
            return self._deny(
                "tools/list",
                CONTRACT_VIOLATION_CODE,
                "Too many tools",
                ["tool_list_limit_exceeded"],
                rpc_id=rpc_id,
                latch_drift=True,
            )

        reasons: list[str] = []
        seen: dict[str, PinnedToolContract] = {}
        for item in raw_tools:
            if not isinstance(item, dict):
                reasons.append("malformed_tool_descriptor")
                continue
            try:
                pinned = pin_tool_descriptor(item)
            except MCPContractLockError:
                reasons.append("malformed_tool_descriptor")
                continue
            if pinned.name in seen:
                reasons.append(f"duplicate_tool_name:{pinned.name}")
                continue
            seen[pinned.name] = pinned
            expected = self._pinned_tools.get(pinned.name)
            if expected is None:
                reasons.append(f"tool_added:{pinned.name}")
                continue
            if not hmac.compare_digest(expected.description_sha256, pinned.description_sha256):
                reasons.append(f"tool_description_changed:{pinned.name}")
            if not hmac.compare_digest(expected.schema_sha256, pinned.schema_sha256):
                reasons.append(f"tool_schema_changed:{pinned.name}")
            if not hmac.compare_digest(expected.annotations_sha256, pinned.annotations_sha256):
                reasons.append(f"tool_annotations_changed:{pinned.name}")

        for missing in sorted(set(self._pinned_tools) - set(seen)):
            reasons.append(f"tool_removed:{missing}")

        if reasons:
            return self._deny(
                "tools/list",
                CONTRACT_VIOLATION_CODE,
                "Upstream tools/list drifted from pinned lockfile",
                reasons,
                rpc_id=rpc_id,
                contract_sha256=self._server.server_contract_sha256,
                latch_drift=True,
            )
        self._reverify_required = False
        return self._allow(
            "tools/list",
            response,
            contract_sha256=self._server.server_contract_sha256,
            rpc_id=rpc_id,
        )

    def filter_tool_call_request(self, request: Mapping[str, Any]) -> ProxyDecisionOutcome:
        """Verify a client ``tools/call`` request against the pinned lockfile and drift latch."""
        rpc_id, params = request.get("id"), request.get("params")
        tool_name = params.get("name") if isinstance(params, dict) else None
        arguments = params.get("arguments") if isinstance(params, dict) else None
        # Never log raw argument values; digest canonicalized arguments only.
        args_sha = hash_canonical(arguments if arguments is not None else {})

        if not isinstance(tool_name, str) or not tool_name.strip():
            return self._deny(
                "tools/call",
                INVALID_REQUEST_CODE,
                "Invalid tools/call request",
                ["malformed_tool_call"],
                rpc_id=rpc_id,
                arguments_sha256=args_sha,
            )
        if self._drift_latched:
            return self._deny(
                "tools/call",
                CONTRACT_VIOLATION_CODE,
                "Session blocked after upstream drift",
                ["session_drift_latched"],
                rpc_id=rpc_id,
                tool_name=tool_name,
                arguments_sha256=args_sha,
            )
        if self._reverify_required:
            return self._deny(
                "tools/call",
                CONTRACT_VIOLATION_CODE,
                "tools/list re-verification required",
                ["reverification_required_after_list_changed"],
                rpc_id=rpc_id,
                tool_name=tool_name,
                arguments_sha256=args_sha,
            )
        pinned = self._pinned_tools.get(tool_name)
        if pinned is None:
            return self._deny(
                "tools/call",
                CONTRACT_VIOLATION_CODE,
                f"Tool {tool_name!r} is not pinned in lockfile",
                [f"unpinned_tool:{tool_name}"],
                rpc_id=rpc_id,
                tool_name=tool_name,
                arguments_sha256=args_sha,
            )
        return self._allow(
            "tools/call",
            request,
            tool_name=tool_name,
            contract_sha256=pinned.contract_sha256,
            arguments_sha256=args_sha,
            rpc_id=rpc_id,
        )

    def process_rpc_line(self, raw_line: str) -> ProxyDecisionOutcome:
        """Parse and filter one bounded JSON-RPC 2.0 NDJSON line (refusing batch arrays)."""
        if len(raw_line.encode("utf-8")) > MAX_RPC_LINE_BYTES:
            return self._deny(
                "rpc", INVALID_REQUEST_CODE, "RPC message too large", ["rpc_message_too_large"]
            )
        try:
            msg = parse_json_strict(raw_line, max_bytes=MAX_RPC_LINE_BYTES)
        except ValueError:
            return self._deny(
                "rpc", INVALID_REQUEST_CODE, "Invalid JSON-RPC payload", ["invalid_json_rpc"]
            )
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            return self._deny(
                "rpc",
                INVALID_REQUEST_CODE,
                "Only JSON-RPC 2.0 objects are permitted",
                ["jsonrpc_batch_or_non_object_refused"],
            )
        if self._drift_latched:
            return self._deny(
                "rpc",
                CONTRACT_VIOLATION_CODE,
                "Session blocked after upstream drift",
                ["session_drift_latched"],
                rpc_id=msg.get("id"),
            )
        method = msg.get("method")
        if method == "tools/call":
            return self.filter_tool_call_request(msg)
        if method == "notifications/tools/list_changed":
            self._reverify_required = True
            return self._allow(
                "rpc", msg, reasons=["tools_list_changed_reverify_required"], rpc_id=msg.get("id")
            )
        result = msg.get("result")
        if isinstance(result, dict):
            if "tools" in result:
                return self.filter_tools_list_response(msg)
            if "protocolVersion" in result:
                return self.filter_initialize_response(msg)
        return self._allow("rpc", msg, rpc_id=msg.get("id"))


def serialize_json_line(obj: Mapping[str, Any]) -> str:
    """Serialize a deterministic single-line JSON record refusing NaN/Infinity."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False)
