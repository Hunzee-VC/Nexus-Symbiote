"""CLI commands for MCP contract lockfiles (Item 27) and opt-in contract-pinning proxy (Item 33)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from nexus_symbiote.core.aibom import AIBOM, NativeFormatError
from nexus_symbiote.core.hashing import hash_bytes, open_regular_file, parse_json_strict
from nexus_symbiote.mcp_contract_lock import (
    DEFAULT_MCP_PROTOCOL,
    MAX_LOCKFILE_BYTES,
    SUPPORTED_MCP_PROTOCOLS,
    MCPContractLockError,
    PinnedServerContract,
    create_lockfile_from_aibom,
    create_lockfile_from_servers,
    ensure_outside_project,
    load_mcp_lockfile,
    parse_snapshot_servers,
    verify_contracts,
)
from nexus_symbiote.mcp_proxy import (
    ContractPinningProxy,
    MCPProxyError,
    load_signing_key,
    serialize_json_line,
)
from nexus_symbiote.utils.terminal import (
    json_text,
    neutralize,
    refuse_dash_output,
    write_cli_output,
)

_EXISTING_FILE = click.Path(exists=True, dir_okay=False, path_type=Path)
_EXISTING_DIR = click.Path(exists=True, file_okay=False, path_type=Path)


def _load_candidate_servers(
    *, aibom_path: Path | None, snapshot_path: Path | None, protocol_version: str
) -> tuple[list[PinnedServerContract], str | None]:
    if (aibom_path is None) == (snapshot_path is None):
        raise click.UsageError("Provide exactly one of --aibom or --snapshot")
    if aibom_path is not None:
        try:
            bom, raw = AIBOM.load_with_bytes(aibom_path)
        except (NativeFormatError, OSError, ValueError, TypeError, RecursionError) as exc:
            raise click.ClickException(f"Invalid native AIBOM file: {neutralize(exc)}") from exc
        lock = create_lockfile_from_aibom(
            bom, protocol_version=protocol_version, inventory_sha256=hash_bytes(raw)
        )
        return lock.servers, hash_bytes(raw)
    assert snapshot_path is not None
    try:
        with open_regular_file(snapshot_path) as handle:
            raw = handle.read(MAX_LOCKFILE_BYTES + 1)
        if len(raw) > MAX_LOCKFILE_BYTES:
            raise MCPContractLockError("MCP snapshot exceeds maximum byte size")
        payload = parse_json_strict(raw.decode("utf-8"), max_bytes=MAX_LOCKFILE_BYTES)
        if not isinstance(payload, dict):
            raise MCPContractLockError("MCP snapshot must be a JSON object")
        return parse_snapshot_servers(payload), None
    except (OSError, ValueError) as exc:
        raise click.ClickException(neutralize(exc)) from exc


def _emit_json(text: str, output: Path | None) -> None:
    if output:
        refuse_dash_output(output)
        write_cli_output(output, text + "\n")
    else:
        click.echo(json_text(text))


def register_mcp_lock_commands(main: click.Group) -> None:
    @main.command("mcp-lock")
    @click.option("--aibom", "aibom_path", type=_EXISTING_FILE, help="Native AgentBOM JSON.")
    @click.option("--snapshot", "snapshot_path", type=_EXISTING_FILE, help="MCP snapshot JSON.")
    @click.option("--verify", "verify_lockfile", type=_EXISTING_FILE, help="Lockfile to verify.")
    @click.option("--project-root", type=_EXISTING_DIR, help="Scanned project root.")
    @click.option(
        "--protocol-version",
        type=click.Choice(SUPPORTED_MCP_PROTOCOLS),
        default=DEFAULT_MCP_PROTOCOL,
        show_default=True,
        help="Default MCP protocol revision when pinning from an AgentBOM.",
    )
    @click.option("--lockfile-attestation", type=_EXISTING_FILE, help="Reviewed DSSE attestation.")
    @click.option(
        "--trusted-key",
        "trusted_keys",
        multiple=True,
        type=_EXISTING_FILE,
        help="Ed25519 pubkey PEM.",
    )
    @click.option(
        "--allow-unsigned-lockfile", is_flag=True, default=False, help="Allow unattested lockfile."
    )
    @click.option(
        "-o", "--output", type=click.Path(path_type=Path), help="Write JSON output to file."
    )
    def mcp_lock(
        aibom_path: Path | None,
        snapshot_path: Path | None,
        verify_lockfile: Path | None,
        project_root: Path | None,
        protocol_version: str,
        lockfile_attestation: Path | None,
        trusted_keys: tuple[Path, ...],
        allow_unsigned_lockfile: bool,
        output: Path | None,
    ) -> None:
        """Create or verify deterministic MCP contract lockfiles offline.

        Pins MCP 2026-07-28, 2025-11-25, and 2025-06-18 tool descriptions, titles,
        schemas, _meta, and annotations. With --verify, requires Ed25519 DSSE attestation
        unless --allow-unsigned-lockfile is passed, and exits 1 on any contract drift.
        """
        if (
            lockfile_attestation is not None or trusted_keys or allow_unsigned_lockfile
        ) and verify_lockfile is None:
            raise click.UsageError(
                "--lockfile-attestation, --trusted-key, and --allow-unsigned-lockfile require --verify"
            )
        servers, inv_sha = _load_candidate_servers(
            aibom_path=aibom_path, snapshot_path=snapshot_path, protocol_version=protocol_version
        )
        if verify_lockfile is None:
            lock = create_lockfile_from_servers(servers, inventory_sha256=inv_sha)
            _emit_json(
                json.dumps(lock.model_dump(mode="json"), indent=2, sort_keys=True, allow_nan=False),
                output,
            )
            return

        try:
            lock, lock_sha, attested = load_mcp_lockfile(
                verify_lockfile,
                project_root=project_root,
                inventory_path=aibom_path,
                attestation_path=lockfile_attestation,
                trusted_key_paths=trusted_keys,
                allow_unsigned=allow_unsigned_lockfile,
            )
            report = verify_contracts(lock, servers, lockfile_sha256=lock_sha, attested=attested)
        except (MCPContractLockError, OSError, ValueError) as exc:
            raise click.ClickException(neutralize(exc)) from exc
        _emit_json(json.dumps(report.to_dict(), indent=2, sort_keys=True, allow_nan=False), output)
        if not report.passed:
            raise click.exceptions.Exit(1)

    @main.command("mcp-proxy")
    @click.option("--lockfile", required=True, type=_EXISTING_FILE, help="Pinned MCP lockfile.")
    @click.option("--server", "server_ref", required=True, help="Pinned server_ref to enforce.")
    @click.option(
        "--signing-key", required=True, type=_EXISTING_FILE, help="Mode-0600 Ed25519 key."
    )
    @click.option("--project-root", type=_EXISTING_DIR, help="Scanned project root.")
    @click.option("--lockfile-attestation", type=_EXISTING_FILE, help="Reviewed DSSE attestation.")
    @click.option(
        "--trusted-key",
        "trusted_keys",
        multiple=True,
        type=_EXISTING_FILE,
        help="Ed25519 pubkey PEM.",
    )
    @click.option(
        "--allow-unsigned-lockfile", is_flag=True, default=False, help="Allow unattested lockfile."
    )
    @click.option("--input", "input_path", type=_EXISTING_FILE, help="NDJSON JSON-RPC input file.")
    @click.option(
        "--decision-log", type=click.Path(path_type=Path), help="Signed NDJSON decision log."
    )
    def mcp_proxy(
        lockfile: Path,
        server_ref: str,
        signing_key: Path,
        project_root: Path | None,
        lockfile_attestation: Path | None,
        trusted_keys: tuple[Path, ...],
        allow_unsigned_lockfile: bool,
        input_path: Path | None,
        decision_log: Path | None,
    ) -> None:
        """Opt-in offline JSON-RPC 2.0 contract-pinning proxy filter.

        Blocks any upstream tools/list drift (including one-character description changes)
        before it reaches the model, blocks protocol downgrades and unpinned tools/call
        invocations, and signs every decision record with Ed25519. Exits 1 on any denial.
        """
        try:
            lock, lock_sha, _ = load_mcp_lockfile(
                lockfile,
                project_root=project_root,
                attestation_path=lockfile_attestation,
                trusted_key_paths=trusted_keys,
                allow_unsigned=allow_unsigned_lockfile,
            )
            srv = lock.server_map().get(server_ref)
            if srv is None:
                raise MCPContractLockError(f"Server {server_ref!r} not found in lockfile")
            ensure_outside_project(signing_key, project_root, label="Signing key")
            signer = load_signing_key(signing_key)
        except (MCPContractLockError, MCPProxyError, OSError, ValueError) as exc:
            raise click.ClickException(neutralize(exc)) from exc

        proxy = ContractPinningProxy(srv, lockfile_sha256=lock_sha, signer=signer)
        if input_path is not None:
            try:
                with open_regular_file(input_path) as handle:
                    raw = handle.read(MAX_LOCKFILE_BYTES + 1)
                if len(raw) > MAX_LOCKFILE_BYTES:
                    raise MCPProxyError("Proxy input stream exceeds maximum byte size")
                lines = raw.decode("utf-8").splitlines()
            except (MCPProxyError, OSError, UnicodeDecodeError) as exc:
                raise click.ClickException(neutralize(exc)) from exc
        else:
            raw_text = sys.stdin.read(MAX_LOCKFILE_BYTES + 1)
            if len(raw_text.encode("utf-8")) > MAX_LOCKFILE_BYTES:
                raise click.ClickException("Proxy stdin stream exceeds maximum byte size")
            lines = raw_text.splitlines()

        out_messages: list[str] = []
        decision_lines: list[str] = []
        any_denied = False
        for line in lines:
            if not line.strip():
                continue
            outcome = proxy.process_rpc_line(line)
            out_messages.append(serialize_json_line(outcome.message))
            decision_lines.append(serialize_json_line(outcome.decision_record))
            if not outcome.allowed:
                any_denied = True

        if decision_log is not None:
            refuse_dash_output(decision_log)
            write_cli_output(
                decision_log, "\n".join(decision_lines) + ("\n" if decision_lines else "")
            )
        for msg_line in out_messages:
            click.echo(json_text(msg_line))
        if any_denied:
            raise click.exceptions.Exit(1)
