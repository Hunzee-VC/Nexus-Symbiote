"""Tests for MCP contract lockfile (Item 27) and opt-in contract-pinning proxy (Item 33)."""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.attestation import build_statement, sign_statement
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.mcp_contract_lock import (
    SUPPORTED_MCP_PROTOCOLS,
    MCPContractLockError,
    build_server_contract,
    create_lockfile_from_aibom,
    create_lockfile_from_servers,
    load_mcp_lockfile,
    parse_snapshot_servers,
    verify_contracts,
)
from nexus_symbiote.mcp_proxy import (
    CONTRACT_VIOLATION_CODE,
    ContractPinningProxy,
    MCPProxyError,
    load_signing_key,
    verify_decision_record,
)
from nexus_symbiote.runtime import key_id


def _write_keypair(directory: Path, prefix: str = "proxy") -> tuple[Ed25519PrivateKey, Path, Path]:
    private = Ed25519PrivateKey.generate()
    priv_path = directory / f"{prefix}.key"
    pub_path = directory / f"{prefix}.pub"
    priv_bytes = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path.write_bytes(priv_bytes)
    os.chmod(priv_path, 0o600)
    pub_path.write_bytes(pub_bytes)
    return private, priv_path, pub_path


def _sample_snapshot(protocol_version: str = "2026-07-28") -> dict:
    return {
        "servers": [
            {
                "server_ref": "mcp:docs-server",
                "server_name": "docs-server",
                "protocol_version": protocol_version,
                "transport": "stdio",
                "tools": [
                    {
                        "name": "lookup_ticket",
                        "description": "Look up a support ticket by numeric ID.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"ticket_id": {"type": "integer"}},
                            "required": ["ticket_id"],
                        },
                        "annotations": {"readOnlyHint": True, "destructiveHint": False},
                    },
                    {
                        "name": "list_projects",
                        "description": "List active projects in the workspace.",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                ],
            }
        ]
    }


@pytest.mark.parametrize("protocol_version", SUPPORTED_MCP_PROTOCOLS)
def test_mcp_lockfile_catches_one_char_desc_new_tool_and_removed_tool_all_revisions(
    tmp_path, protocol_version
):
    """Exact Item 27 Done-when: 1-char description change, new tool, and removed tool each fail CI on all 3 MCP revisions."""
    op_dir = tmp_path / "operator"
    cand_dir = tmp_path / "candidate"
    op_dir.mkdir()
    cand_dir.mkdir()

    base = _sample_snapshot(protocol_version)
    base_snap = cand_dir / "base.json"
    base_snap.write_text(json.dumps(base), encoding="utf-8")

    lock_path = op_dir / f"mcp-{protocol_version}.lock.json"
    runner = CliRunner()
    res_create = runner.invoke(
        main, ["mcp-lock", "--snapshot", str(base_snap), "-o", str(lock_path)]
    )
    assert res_create.exit_code == 0, res_create.output

    # D7: unsigned lockfile is refused by default until --allow-unsigned-lockfile or DSSE attestation is supplied.
    res_unsigned_blocked = runner.invoke(
        main, ["mcp-lock", "--snapshot", str(base_snap), "--verify", str(lock_path)]
    )
    assert res_unsigned_blocked.exit_code != 0
    assert "lockfile-attestation" in res_unsigned_blocked.output

    # Benign twin: identical snapshot passes with exit 0 when opt-out or attestation is provided.
    res_clean = runner.invoke(
        main,
        [
            "mcp-lock",
            "--snapshot",
            str(base_snap),
            "--verify",
            str(lock_path),
            "--allow-unsigned-lockfile",
        ],
    )
    assert res_clean.exit_code == 0, res_clean.output
    clean_rep = json.loads(res_clean.output)
    assert clean_rep["passed"] is True
    assert clean_rep["finding_count"] == 0

    # 1. One-character description change (trailing period -> exclamation mark) fails CI.
    desc_drift = _sample_snapshot(protocol_version)
    desc_drift["servers"][0]["tools"][0]["description"] = "Look up a support ticket by numeric ID!"
    desc_snap = cand_dir / "desc-drift.json"
    desc_snap.write_text(json.dumps(desc_drift), encoding="utf-8")
    res_desc = runner.invoke(
        main,
        [
            "mcp-lock",
            "--snapshot",
            str(desc_snap),
            "--verify",
            str(lock_path),
            "--allow-unsigned-lockfile",
        ],
    )
    assert res_desc.exit_code == 1
    rep_desc = json.loads(res_desc.output)
    assert rep_desc["passed"] is False
    assert any(
        f["code"] == "tool_description_changed" and f["severity"] == "critical"
        for f in rep_desc["findings"]
    )

    # 2. Invisible zero-width space 1-char injection also caught verbatim.
    zws_drift = _sample_snapshot(protocol_version)
    zws_drift["servers"][0]["tools"][0]["description"] += "\u200b"
    zws_snap = cand_dir / "zws-drift.json"
    zws_snap.write_text(json.dumps(zws_drift), encoding="utf-8")
    res_zws = runner.invoke(
        main,
        [
            "mcp-lock",
            "--snapshot",
            str(zws_snap),
            "--verify",
            str(lock_path),
            "--allow-unsigned-lockfile",
        ],
    )
    assert res_zws.exit_code == 1
    assert any(
        f["code"] == "tool_description_changed" for f in json.loads(res_zws.output)["findings"]
    )

    # 3. Added tool fails CI.
    added = _sample_snapshot(protocol_version)
    added["servers"][0]["tools"].append(
        {"name": "exfiltrate_env", "description": "Helper", "inputSchema": {}}
    )
    added_snap = cand_dir / "added.json"
    added_snap.write_text(json.dumps(added), encoding="utf-8")
    res_add = runner.invoke(
        main,
        [
            "mcp-lock",
            "--snapshot",
            str(added_snap),
            "--verify",
            str(lock_path),
            "--allow-unsigned-lockfile",
        ],
    )
    assert res_add.exit_code == 1
    assert any(
        f["code"] == "tool_added" and f["tool_name"] == "exfiltrate_env"
        for f in json.loads(res_add.output)["findings"]
    )

    # 4. Removed tool fails CI.
    removed = _sample_snapshot(protocol_version)
    removed["servers"][0]["tools"] = [removed["servers"][0]["tools"][0]]
    rem_snap = cand_dir / "removed.json"
    rem_snap.write_text(json.dumps(removed), encoding="utf-8")
    res_rem = runner.invoke(
        main,
        [
            "mcp-lock",
            "--snapshot",
            str(rem_snap),
            "--verify",
            str(lock_path),
            "--allow-unsigned-lockfile",
        ],
    )
    assert res_rem.exit_code == 1
    assert any(
        f["code"] == "tool_removed" and f["tool_name"] == "list_projects"
        for f in json.loads(res_rem.output)["findings"]
    )

    # 5. Schema, _meta, title, and annotation mutations fail CI.
    mut = _sample_snapshot(protocol_version)
    mut["servers"][0]["tools"][0]["title"] = "Injected Title"
    mut["servers"][0]["tools"][0]["_meta"] = {"hidden": "instruction"}
    mut["servers"][0]["tools"][0]["annotations"]["readOnlyHint"] = False
    mut["servers"][0]["tools"][0]["inputSchema"]["properties"]["extra"] = {"type": "string"}
    mut_snap = cand_dir / "mut.json"
    mut_snap.write_text(json.dumps(mut), encoding="utf-8")
    res_mut = runner.invoke(
        main,
        [
            "mcp-lock",
            "--snapshot",
            str(mut_snap),
            "--verify",
            str(lock_path),
            "--allow-unsigned-lockfile",
        ],
    )
    assert res_mut.exit_code == 1
    codes = {f["code"] for f in json.loads(res_mut.output)["findings"]}
    assert {"tool_description_changed", "tool_schema_changed", "tool_annotations_changed"} <= codes


def test_mcp_lockfile_rejects_unsupported_protocol_in_repo_and_tampered_attestation(tmp_path):
    # Unsupported protocol revision refused fail-closed.
    with pytest.raises(MCPContractLockError, match="Unsupported MCP protocol_version"):
        build_server_contract(
            server_ref="mcp:bad",
            server_name="bad",
            protocol_version="2024-11-05",
            tools=[],
        )

    # Lockfile inside repo refused even without --project-root.
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    bom = AIBOM(
        components=[
            MCPServerComponent(bom_ref="mcp:s1", name="s1", transport="stdio"),
            ToolComponent(
                bom_ref="tool:s1:ping",
                name="ping",
                mcp_server_ref="mcp:s1",
                description_text="Ping server.",
            ),
        ]
    )
    bom_path = repo / "aibom.json"
    bom.save(bom_path)
    lock = create_lockfile_from_aibom(bom, protocol_version="2026-07-28")
    in_repo_lock = repo / "mcp.lock.json"
    in_repo_lock.write_text(json.dumps(lock.model_dump(mode="json")), encoding="utf-8")
    with pytest.raises(MCPContractLockError, match="outside the scanned project"):
        load_mcp_lockfile(in_repo_lock, inventory_path=bom_path, allow_unsigned=True)

    # DSSE reviewed attestation works when valid and fails when tampered.
    op_dir = tmp_path / "op"
    op_dir.mkdir()
    out_lock = op_dir / "mcp.lock.json"
    lock_bytes = json.dumps(lock.model_dump(mode="json"), indent=2, sort_keys=True).encode("utf-8")
    out_lock.write_bytes(lock_bytes)
    private, _, pub_path = _write_keypair(op_dir, "reviewer")
    stmt = build_statement(
        lock_bytes,
        name=out_lock.name,
        purpose="reviewed",
        signed_at=datetime.now(UTC).replace(microsecond=0),
    )
    env = sign_statement(stmt, [private])
    att_path = op_dir / "mcp.lock.att.json"
    att_path.write_text(
        json.dumps(env.model_dump(mode="json", by_alias=True), indent=2) + "\n", encoding="utf-8"
    )
    loaded, _, attested = load_mcp_lockfile(
        out_lock, project_root=repo, attestation_path=att_path, trusted_key_paths=(pub_path,)
    )
    assert attested is True
    assert loaded.servers[0].tools[0].effective_annotations["destructiveHint"] is True

    # Tampering a single tool digest field without changing top-level hash is rejected on load.
    tampered_doc = lock.model_dump(mode="json")
    tampered_doc["servers"][0]["tools"][0]["description_sha256"] = "sha256:" + "0" * 64
    tampered_lock = op_dir / "tampered.lock.json"
    tampered_lock.write_text(json.dumps(tampered_doc), encoding="utf-8")
    with pytest.raises(MCPContractLockError, match="internal digest or metadata mismatch"):
        load_mcp_lockfile(tampered_lock, project_root=repo, allow_unsigned=True)

    # Tampering a single byte fails attestation verification.
    out_lock.write_bytes(lock_bytes + b" ")
    with pytest.raises(MCPContractLockError, match="attestation verification failed"):
        load_mcp_lockfile(
            out_lock, project_root=repo, attestation_path=att_path, trusted_key_paths=(pub_path,)
        )


def test_mcp_proxy_blocks_one_char_drift_before_model_and_signs_benign_calls(tmp_path):
    """Exact Item 33 Done-when: 1-char description drift blocked before model sees it; benign call passes with Ed25519-signed record."""
    op_dir = tmp_path / "operator"
    op_dir.mkdir()
    private, priv_path, pub_path = _write_keypair(op_dir, "proxy")
    trusted = {key_id(private.public_key()): private.public_key()}

    servers = parse_snapshot_servers(_sample_snapshot("2026-07-28"))
    lock = create_lockfile_from_servers(servers)
    lock_path = op_dir / "mcp.lock.json"
    lock_bytes = json.dumps(lock.model_dump(mode="json"), indent=2, sort_keys=True).encode("utf-8")
    lock_path.write_bytes(lock_bytes)
    stmt = build_statement(
        lock_bytes,
        name=lock_path.name,
        purpose="reviewed",
        signed_at=datetime.now(UTC).replace(microsecond=0),
    )
    att_path = op_dir / "mcp.lock.att.json"
    att_path.write_text(
        json.dumps(sign_statement(stmt, [private]).model_dump(mode="json", by_alias=True), indent=2)
        + "\n",
        encoding="utf-8",
    )
    loaded_lock, lock_sha, _ = load_mcp_lockfile(
        lock_path, attestation_path=att_path, trusted_key_paths=(pub_path,)
    )

    # Benign session: clean initialize + tools/list + pinned tools/call with private argument value.
    proxy = ContractPinningProxy(loaded_lock.servers[0], lockfile_sha256=lock_sha, signer=private)
    init_ok = proxy.process_rpc_line(
        json.dumps({"jsonrpc": "2.0", "id": 0, "result": {"protocolVersion": "2026-07-28"}})
    )
    assert init_ok.allowed is True

    clean_list = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"tools": _sample_snapshot("2026-07-28")["servers"][0]["tools"]},
    }
    res_list = proxy.filter_tools_list_response(clean_list)
    assert res_list.allowed is True
    assert res_list.message["result"]["tools"][0]["name"] == "lookup_ticket"
    verified_list = verify_decision_record(res_list.decision_record, trusted)
    assert verified_list["verdict"] == "allow"

    canary_arg = "canary-private-arg-value-99999"
    benign_call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "lookup_ticket", "arguments": {"ticket_id": 42, "note": canary_arg}},
    }
    res_call = proxy.filter_tool_call_request(benign_call)
    assert res_call.allowed is True
    verified_call = verify_decision_record(res_call.decision_record, trusted)
    assert verified_call["verdict"] == "allow"
    assert verified_call["tool_name"] == "lookup_ticket"
    assert verified_call["arguments_sha256"].startswith("sha256:")
    # Invariant 6: raw argument values must NEVER appear in the signed decision record!
    assert canary_arg not in json.dumps(res_call.decision_record)

    # notifications/tools/list_changed requires fresh tools/list verification before next call.
    notice = proxy.process_rpc_line(
        json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
    )
    assert notice.allowed is True
    blocked_reverify = proxy.filter_tool_call_request(benign_call)
    assert blocked_reverify.allowed is False
    assert "reverification_required_after_list_changed" in blocked_reverify.reasons
    assert proxy.filter_tools_list_response(clean_list).allowed is True
    assert proxy.filter_tool_call_request(benign_call).allowed is True

    # Hostile session: 1-character description change in upstream tools/list is BLOCKED before the model sees it!
    bad_tools = _sample_snapshot("2026-07-28")["servers"][0]["tools"]
    bad_tools[0]["description"] = "Look up a support ticket by numeric ID!"  # 1-char change
    poisoned_resp = {"jsonrpc": "2.0", "id": 3, "result": {"tools": bad_tools}}
    blocked = proxy.filter_tools_list_response(poisoned_resp)
    assert blocked.allowed is False
    assert "result" not in blocked.message  # Model NEVER receives the poisoned tool list!
    assert blocked.message["error"]["code"] == CONTRACT_VIOLATION_CODE
    assert "tool_description_changed:lookup_ticket" in blocked.reasons
    assert proxy.drift_latched is True
    verified_deny = verify_decision_record(blocked.decision_record, trusted)
    assert verified_deny["verdict"] == "deny"

    # Once drift is latched, ALL subsequent RPC traffic is denied fail-closed.
    post_drift = proxy.process_rpc_line(json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"}))
    assert post_drift.allowed is False
    assert "session_drift_latched" in post_drift.reasons

    # Adversarial checks on fresh proxies: pagination smuggling, protocol downgrade, unpinned tool, batch array.
    fresh = ContractPinningProxy(loaded_lock.servers[0], lockfile_sha256=lock_sha, signer=private)
    unpinned = fresh.filter_tool_call_request(
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "exec_shell"}}
    )
    assert unpinned.allowed is False
    assert "unpinned_tool:exec_shell" in unpinned.reasons

    batch = fresh.process_rpc_line(json.dumps([benign_call]))
    assert batch.allowed is False
    assert "jsonrpc_batch_or_non_object_refused" in batch.reasons

    paginated = fresh.filter_tools_list_response(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "result": {"tools": clean_list["result"]["tools"], "nextCursor": "p2"},
        }
    )
    assert paginated.allowed is False
    assert "paginated_tools_list_refused" in paginated.reasons

    downgrade_proxy = ContractPinningProxy(
        loaded_lock.servers[0], lockfile_sha256=lock_sha, signer=private
    )
    downgrade = downgrade_proxy.process_rpc_line(
        json.dumps({"jsonrpc": "2.0", "id": 6, "result": {"protocolVersion": "2025-06-18"}})
    )
    assert downgrade.allowed is False
    assert "protocol_version_mismatch" in downgrade.reasons

    # CLI end-to-end test: unsigned refused by default (D7), attested passes & writes signed decision log.
    stream_file = tmp_path / "rpc.ndjson"
    stream_file.write_text(
        json.dumps(clean_list) + "\n" + json.dumps(benign_call) + "\n", encoding="utf-8"
    )
    decision_log = tmp_path / "decisions.ndjson"
    runner = CliRunner()
    refused_cli = runner.invoke(
        main,
        [
            "mcp-proxy",
            "--lockfile",
            str(lock_path),
            "--server",
            "mcp:docs-server",
            "--signing-key",
            str(priv_path),
            "--input",
            str(stream_file),
        ],
    )
    assert refused_cli.exit_code != 0
    assert "lockfile-attestation" in refused_cli.output

    cli_res = runner.invoke(
        main,
        [
            "mcp-proxy",
            "--lockfile",
            str(lock_path),
            "--lockfile-attestation",
            str(att_path),
            "--trusted-key",
            str(pub_path),
            "--server",
            "mcp:docs-server",
            "--signing-key",
            str(priv_path),
            "--input",
            str(stream_file),
            "--decision-log",
            str(decision_log),
        ],
    )
    assert cli_res.exit_code == 0, cli_res.output
    log_records = [
        json.loads(line) for line in decision_log.read_text(encoding="utf-8").splitlines()
    ]
    assert len(log_records) == 2
    for rec in log_records:
        verify_decision_record(rec, trusted)

    # World-readable signing key (0644) must be refused on POSIX.
    if os.name == "posix":
        os.chmod(priv_path, 0o644)
        with pytest.raises(MCPProxyError, match="0600"):
            load_signing_key(priv_path)


def test_mcp_lockfile_linear_scaling_2000_tools():
    """Verify O(T) verification time across 2,000 pinned tools."""
    tools = [
        {"name": f"tool_{i:04d}", "description": f"Deterministic tool {i}", "inputSchema": {}}
        for i in range(2_000)
    ]
    srv = build_server_contract(
        server_ref="mcp:scale",
        server_name="scale",
        protocol_version="2026-07-28",
        tools=tools,
    )
    lock = create_lockfile_from_servers([srv])
    t0 = time.monotonic()
    rep = verify_contracts(lock, [srv], lockfile_sha256="sha256:" + "a" * 64)
    elapsed = time.monotonic() - t0
    assert rep.passed is True
    assert rep.tools_checked == 2_000
    assert elapsed < 2.0, f"expected linear verification (<2s), got {elapsed:.2f}s"
