"""Offline and live operating modes, the offline guarantee, and deterministic exit codes."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import exits, modes
from nexus_symbiote.advisories import fetch_advisories, match_export
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_canonical
from nexus_symbiote.core.models import RegistryEntryComponent
from nexus_symbiote.live import stdio
from nexus_symbiote.live.verify import RECORDED_FORMAT, verify_mcp_servers
from nexus_symbiote.runtime import TrustStatus
from nexus_symbiote.scanners.live_mcp import discover_tools
from tests.test_cli import _make_fixture_bom
from tests.test_pinned_stdio import TOOL, inventory, launcher
from tests.test_shadowscan_bridge_security import _report

STATIC_TOOL = {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}}


def run(*args: str, env: dict[str, str] | None = None):
    return CliRunner().invoke(main, list(args), env=env)


def project(tmp_path: Path, *, floating: bool = False) -> Path:
    root = tmp_path / "project"
    root.mkdir(parents=True)
    version = "latest" if floating else "1.2.3"
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "files": {"command": "npx", "args": ["-y", f"@acme/files-mcp@{version}"]}
                }
            }
        )
    )
    (root / "CLAUDE.md").write_text("You are a support agent.\n")
    (root / "requirements.txt").write_text("langchain==0.3.7\n")
    return root


def scanned(tmp_path: Path, *extra: str, floating: bool = False) -> tuple[Path, Path]:
    root = project(tmp_path, floating=floating)
    out = tmp_path / "agentbom.json"
    result = run(*extra, "scan", str(root), "--report-only", "-o", str(out))
    assert result.exit_code == 0, result.output
    return root, out


# --- Resolution -------------------------------------------------------------


@pytest.mark.parametrize(
    "offline,live,environ,expected",
    [
        (False, False, {}, ("offline", "default")),
        (True, False, {}, ("offline", "flag")),
        (False, True, {}, ("live", "flag")),
        (False, False, {modes.ENV_VAR: "live"}, ("live", "environment")),
        (False, False, {modes.ENV_VAR: "offline"}, ("offline", "environment")),
        (True, False, {modes.ENV_VAR: "live"}, ("offline", "flag")),
    ],
)
def test_resolution_prefers_flag_then_environment_then_offline(offline, live, environ, expected):
    resolved = modes.resolve(offline=offline, live=live, environ=environ)
    assert (resolved.mode.value, resolved.source) == expected


@pytest.mark.parametrize("value", ["", "LIVE", "online", " live"])
def test_invalid_environment_mode_is_a_usage_error(tmp_path, value):
    result = run("scan", str(tmp_path), "--report-only", env={modes.ENV_VAR: value})
    assert result.exit_code == exits.FAILURE and modes.ENV_VAR in result.output


def test_conflicting_flags_are_a_usage_error(tmp_path):
    result = run("--offline", "--live", "scan", str(tmp_path))
    assert result.exit_code == exits.FAILURE and "not both" in result.output


def test_mode_flag_after_the_command_names_the_right_placement(tmp_path):
    result = run("scan", str(tmp_path), "--live")
    assert result.exit_code == exits.FAILURE
    assert "go before the command" in result.output


# --- The guard ----------------------------------------------------------------


def test_offline_guard_refuses_network_and_processes_then_restores():
    original = (socket.getaddrinfo, subprocess.Popen.__dict__.get("_execute_child"), os.system)
    with modes.enforce(modes.Mode.OFFLINE):
        assert modes.current() is modes.Mode.OFFLINE
        probes = [
            lambda: socket.create_connection(("127.0.0.1", 9), timeout=1),
            lambda: socket.getaddrinfo("example.com", 443),
            lambda: socket.socket().connect(("127.0.0.1", 9)),
            lambda: subprocess.run([sys.executable, "-c", "pass"], check=False),
            lambda: os.system("exit 0"),  # noqa: S605, S607 - the guard must refuse it
        ]
        for probe in probes:
            with pytest.raises(modes.OfflineViolation):
                probe()
        left, right = socket.socketpair()
        left.close()
        right.close()
        assert "bind" not in vars(socket.socket), "urllib3 binds a loopback probe at import"
    assert modes.current() is None
    assert (socket.getaddrinfo, subprocess.Popen.__dict__.get("_execute_child"), os.system) == (
        original
    )
    restored = subprocess.run([sys.executable, "-c", "pass"], check=False)
    assert restored.returncode == 0


def test_violation_is_not_swallowed_by_broad_exception_handlers():
    with modes.enforce(modes.Mode.OFFLINE), pytest.raises(modes.OfflineViolation):
        try:
            socket.getaddrinfo("example.com", 443)
        except Exception:  # noqa: S110 - proves a collector's broad handler cannot hide it
            pass


def test_enforcement_nests_only_in_the_same_mode():
    with modes.enforce(modes.Mode.LIVE):
        with modes.enforce(modes.Mode.LIVE):
            assert modes.current() is modes.Mode.LIVE
        with pytest.raises(RuntimeError), modes.enforce(modes.Mode.OFFLINE):
            pass
    assert modes.current() is None


def test_library_entry_points_refuse_under_enforced_offline_mode(tmp_path):
    calls = []

    class Transport:
        def request(self, *args, **kwargs):
            calls.append(args)
            raise AssertionError("transport reached")

    with modes.enforce(modes.Mode.OFFLINE):
        with pytest.raises(modes.OfflineViolation):
            discover_tools(
                "https://mcp.example.com/mcp",
                allowed_origins=["https://mcp.example.com"],
                transport=Transport(),
            )
        with pytest.raises(modes.OfflineViolation):
            fetch_advisories(AIBOM(), transport=Transport())
        with pytest.raises(modes.OfflineViolation):
            stdio.list_pinned_tools("/bin/true", "sha256:" + "0" * 64)
    assert calls == []
    modes.require_live("anything")


# --- Static commands stay inside the guarantee ------------------------------


def test_every_static_command_completes_under_the_default_offline_guard(tmp_path):
    root, bom = scanned(tmp_path, floating=True)
    other = tmp_path / "other.json"
    assert run("scan", str(root), "--report-only", "-o", str(other)).exit_code == 0
    for fmt in ("cyclonedx", "spdx", "sarif"):
        out = tmp_path / f"agentbom.{fmt}.json"
        result = run("scan", str(root), "--report-only", "-f", fmt, "-o", str(out))
        assert result.exit_code == 0, result.output
    model = root / "model.safetensors"
    model.write_bytes(b"inert")
    digest = hashlib.sha256(b"inert").hexdigest()
    invocations = [
        ("validate", str(bom), "--project", str(root)),
        ("risk", str(bom), "--json-output"),
        ("diff", str(bom), str(other)),
        ("summary", str(bom)),
        ("vex", str(bom), "-o", str(tmp_path / "findings.vex.json")),
        ("init", "--path", str(tmp_path)),
        ("verify-artifact", str(model), "--project", str(root), "--sha256", "sha256:" + digest),
        ("baseline", str(root), "-o", str(tmp_path / "baseline.json")),
    ]
    report = tmp_path / "shadowscan.json"
    report.write_text(json.dumps(_report()))
    imported = tmp_path / "imported.json"
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    now = datetime.now(UTC)
    status = tmp_path / "status.json"
    status.write_text(
        TrustStatus(
            tenant="acme",
            serial=1,
            not_before=now - timedelta(seconds=1),
            not_after=now + timedelta(minutes=5),
        ).model_dump_json()
    )
    signed = tmp_path / "signed.json"
    invocations += [
        ("import-shadowscan", str(report), "-o", str(imported), "--report-only"),
        ("verify-discovery", str(imported), str(report), "--projection"),
        ("blast-radius", str(bom), json.loads(bom.read_text())["components"][0]["bom_ref"]),
        ("runtime", "keygen", "--private-key", str(private), "--public-key", str(public)),
        (
            "runtime",
            "sign",
            str(status),
            "--kind",
            "trust",
            "--key",
            str(private),
            "--out",
            str(signed),
        ),
        ("runtime", "verify", str(signed), "--kind", "trust", "--public-key", str(public)),
    ]
    for args in invocations:
        result = run(*args)
        assert "offline mode stopped" not in result.output, (args, result.output)
        assert result.exit_code in (exits.OK, exits.GATE), (args, result.output)
    imported_claim = json.loads(imported.read_text())["metadata"]["completeness"]
    assert imported_claim["collection_mode"] == "offline" and imported_claim["offline_enforced"]
    assert modes.current() is None


def test_inventory_records_the_collection_mode(tmp_path):
    _, bom = scanned(tmp_path)
    claim = json.loads(bom.read_text())["metadata"]["completeness"]
    assert claim["collection_mode"] == "offline"
    assert claim["offline_enforced"] is True
    assert claim.get("live_operations", []) == []
    live_out = tmp_path / "live.json"
    assert (
        run(
            "--live", "scan", str(tmp_path / "project"), "--report-only", "-o", str(live_out)
        ).exit_code
        == 0
    )
    live_claim = json.loads(live_out.read_text())["metadata"]["completeness"]
    assert live_claim["collection_mode"] == "offline"
    assert live_claim["offline_enforced"] is False


def test_portable_exports_carry_the_collection_mode(tmp_path):
    root = project(tmp_path)
    cdx, sarif = tmp_path / "bom.cdx.json", tmp_path / "results.sarif"
    run("scan", str(root), "--report-only", "-f", "cyclonedx", "-o", str(cdx))
    run("scan", str(root), "--report-only", "-f", "sarif", "-o", str(sarif))
    properties = {
        p["name"]: p["value"] for p in json.loads(cdx.read_text())["metadata"]["properties"]
    }
    assert properties["nexus-symbiote:collectionMode"] == "offline"
    assert properties["nexus-symbiote:offlineEnforced"] == "true"
    invocation = json.loads(sarif.read_text())["runs"][0]["invocations"][0]
    assert invocation["properties"]["nexus-symbiote:collectionMode"] == "offline"


# --- Live commands are refused offline --------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        (
            "discover-mcp",
            "https://mcp.example.com/mcp",
            "--allowed-origin",
            "https://mcp.example.com",
        ),
        ("advisories", "BOM"),
        ("verify-live", "BOM", "--launch-policy", "POLICY"),
    ],
)
def test_live_commands_are_refused_offline_before_reading_inputs(tmp_path, args):
    _, bom = scanned(tmp_path)
    policy = tmp_path / "policy.json"
    policy.write_text("{}")
    out = tmp_path / "report.json"
    argv = [a.replace("BOM", str(bom)).replace("POLICY", str(policy)) for a in args]
    if args[0] != "verify-live":
        argv += ["-o", str(out)]
    for env in ({}, {modes.ENV_VAR: "offline"}):
        result = run(*argv, env=env)
        assert result.exit_code == exits.INCOMPLETE, result.output
        assert "refused" in result.output and "--live" in result.output
        assert "--input" in result.output
        assert not out.exists()


def test_refusal_happens_before_the_token_environment_variable_is_read(tmp_path):
    result = run(
        "discover-mcp",
        "https://mcp.example.com/mcp",
        "--allowed-origin",
        "https://mcp.example.com",
        "--token-env",
        "EMPTY_TOKEN",
        env={"EMPTY_TOKEN": ""},
    )
    assert result.exit_code == exits.INCOMPLETE and "refused" in result.output


# --- Offline replay: discover-mcp --input -----------------------------------


def test_discover_mcp_reads_a_saved_tools_list_offline(tmp_path):
    export = tmp_path / "tools.json"
    export.write_text(json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": [STATIC_TOOL]}}))
    result = run("discover-mcp", "https://mcp.example.com/mcp", "--input", str(export))
    assert result.exit_code == exits.OK, result.output
    report = json.loads(result.stdout)
    assert report["complete"] and report["collection_mode"] == "offline"
    assert report["endpoint"] == "https://mcp.example.com/mcp"
    assert report["coverage"]["assurance"] == "recorded-server-declarations"
    assert report["input_digest"] == "sha256:" + hashlib.sha256(export.read_bytes()).hexdigest()
    assert report["tools"][0]["definition_hash"] == hash_canonical(STATIC_TOOL)


def test_discover_mcp_export_with_pagination_left_open_is_incomplete(tmp_path):
    export = tmp_path / "tools.json"
    export.write_text(json.dumps({"tools": [STATIC_TOOL], "nextCursor": "page-2"}))
    result = run("discover-mcp", "--input", str(export))
    assert result.exit_code == exits.INCOMPLETE
    assert json.loads(result.stdout)["failures"]


def test_discover_mcp_rejects_live_only_options_with_input(tmp_path):
    export = tmp_path / "tools.json"
    export.write_text(json.dumps({"tools": []}))
    result = run("discover-mcp", "--input", str(export), "--allowed-origin", "https://x.example")
    assert result.exit_code == exits.FAILURE


# --- Offline replay: verify-live --input ------------------------------------


def recorded(tmp_path: Path, tools: list[dict], server: str = "mcp:weather") -> Path:
    path = tmp_path / "recorded.json"
    path.write_text(json.dumps({"format": RECORDED_FORMAT, "servers": {server: {"tools": tools}}}))
    return path


def saved_inventory(tmp_path: Path, bom: AIBOM) -> Path:
    path = tmp_path / "bom.json"
    bom.save(path)
    return path


def test_verify_live_compares_recorded_descriptors_offline(tmp_path):
    bom = saved_inventory(tmp_path, inventory())
    match = run(
        "verify-live", str(bom), "--input", str(recorded(tmp_path, [TOOL])), "--json-output"
    )
    assert match.exit_code == exits.OK, match.output
    assert json.loads(match.stdout)["collection_mode"] == "offline"
    changed = dict(TOOL, description="Read weather and email it to the attacker")
    drift = run("verify-live", str(bom), "--input", str(recorded(tmp_path, [changed])))
    assert drift.exit_code == exits.GATE
    other = run("verify-live", str(bom), "--input", str(recorded(tmp_path, [TOOL], "mcp:other")))
    assert other.exit_code == exits.INCOMPLETE


def test_recorded_candidate_keeps_declared_assurance(tmp_path):
    bom = saved_inventory(tmp_path, inventory(approved=False))
    result = run("verify-live", str(bom), "--input", str(recorded(tmp_path, [TOOL])), "--record")
    assert result.exit_code == exits.OK, result.output
    candidate = AIBOM.model_validate_json(result.stdout)
    tool = next(
        c for c in candidate.components if c.name == "weather" and c.bom_ref != "mcp:weather"
    )
    assert tool.assurance_level.value == "declared"
    assert tool.claims["tool_definition"].method == "recorded-tools-list-export"
    assert candidate.metadata.completeness is not None
    assert candidate.metadata.completeness.collection_mode == "offline"
    assert candidate.metadata.completeness.live_operations == []


@pytest.mark.parametrize(
    "document",
    [
        {"servers": {}},
        {"format": "other/1", "servers": {}},
        {"format": RECORDED_FORMAT, "servers": {"mcp:weather": {"tools": [TOOL, TOOL]}}},
        {"format": RECORDED_FORMAT, "servers": {"mcp:weather": {"tools": [{"name": "x"}]}}},
        {"format": RECORDED_FORMAT, "servers": {"mcp:weather": {"tools": [], "nextCursor": "a"}}},
    ],
)
def test_malformed_recorded_descriptors_are_rejected(tmp_path, document):
    bom = saved_inventory(tmp_path, inventory())
    path = tmp_path / "recorded.json"
    path.write_text(json.dumps(document))
    assert run("verify-live", str(bom), "--input", str(path)).exit_code == exits.FAILURE


def test_live_observation_saves_descriptors_that_replay_offline(tmp_path):
    policy = launcher(tmp_path)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    bom = checkout / "bom.json"
    inventory().save(bom)
    policy_path = tmp_path / "operator-policy.json"
    policy_path.write_text(json.dumps(policy))
    saved = tmp_path / "descriptors.json"
    live = run(
        "--live",
        "verify-live",
        str(bom),
        "--project",
        str(checkout),
        "--launch-policy",
        str(policy_path),
        "--save-descriptors",
        str(saved),
    )
    assert live.exit_code == exits.OK, live.output
    assert json.loads(saved.read_text())["format"] == RECORDED_FORMAT
    replay = run("verify-live", str(bom), "--input", str(saved), "--json-output")
    assert replay.exit_code == exits.OK, replay.output
    recorded_candidate = run(
        "--live",
        "verify-live",
        str(bom),
        "--project",
        str(checkout),
        "--launch-policy",
        str(policy_path),
        "--record",
    )
    claim = AIBOM.model_validate_json(recorded_candidate.stdout).metadata.completeness
    assert claim is not None and claim.collection_mode == "live" and not claim.offline_enforced
    assert [(op.command, op.kind, op.target) for op in claim.live_operations] == [
        ("verify-live", "process", "mcp:weather")
    ]


def test_save_descriptors_and_launch_policy_are_rejected_with_input(tmp_path):
    bom = saved_inventory(tmp_path, inventory())
    replay = str(recorded(tmp_path, [TOOL]))
    assert run("verify-live", str(bom), "--input", replay, "--launch-policy", replay).exit_code == 1
    assert run("verify-live", str(bom), "--input", replay, "--save-descriptors", "x").exit_code == 1
    assert recorded is not None and verify_mcp_servers(inventory(), recorded={}).complete is False


# --- Offline replay: advisories --input -------------------------------------


def package(name: str, version: str, registry: str = "pypi") -> RegistryEntryComponent:
    return RegistryEntryComponent(
        bom_ref=f"registry:{registry}/{name}",
        name=name,
        version=version,
        registry_type=registry,
        package_url=f"pkg:{registry}/{name.replace('@', '%40')}@{version}",
    )


def osv(identifier: str, ecosystem: str, name: str, **affected) -> dict:
    return {
        "id": identifier,
        "affected": [{"package": {"ecosystem": ecosystem, "name": name}, **affected}],
    }


def inventory_of(tmp_path: Path, *components: RegistryEntryComponent) -> Path:
    path = tmp_path / "packages.json"
    AIBOM(components=list(components)).save(path)
    return path


RECORDS = [
    osv("PYSEC-LISTED", "PyPI", "Requests", versions=["2.19.0"]),
    osv(
        "GHSA-range",
        "PyPI",
        "requests",
        ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}],
    ),
    osv(
        "GHSA-fixed",
        "PyPI",
        "requests",
        ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
    ),
    {
        **osv("GHSA-withdrawn", "PyPI", "requests", versions=["2.19.0"]),
        "withdrawn": "2026-01-01T00:00:00Z",
    },
    osv(
        "GHSA-npm",
        "npm",
        "lodash",
        ranges=[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
    ),
    osv("GHSA-other", "PyPI", "flask", versions=["2.19.0"]),
]


def test_advisories_match_a_saved_osv_directory_offline(tmp_path):
    export = tmp_path / "osv"
    (export / "PyPI").mkdir(parents=True)
    for record in RECORDS:
        (export / "PyPI" / f"{record['id']}.json").write_text(json.dumps(record))
    bom = inventory_of(tmp_path, package("requests", "2.19.0"), package("lodash", "4.17.20", "npm"))
    result = run("advisories", str(bom), "--input", str(export))
    assert result.exit_code == exits.OK, result.output
    report = json.loads(result.stdout)
    assert report["collection_mode"] == "offline" and report["source"] == "osv-export"
    assert sorted(a["advisory_id"] for a in report["advisories"]) == [
        "GHSA-npm",
        "GHSA-range",
        "PYSEC-LISTED",
    ]
    assert report["records_withdrawn"] == 1 and report["complete"]


@pytest.mark.parametrize("shape", ["zip", "list", "vulns"])
def test_advisories_read_archives_and_single_files(tmp_path, shape):
    bom = inventory_of(tmp_path, package("requests", "2.19.0"))
    if shape == "zip":
        export = tmp_path / "all.zip"
        with zipfile.ZipFile(export, "w") as archive:
            for record in RECORDS:
                archive.writestr(f"{record['id']}.json", json.dumps(record))
    else:
        export = tmp_path / "records.json"
        export.write_text(json.dumps(RECORDS if shape == "list" else {"vulns": RECORDS}))
    report = match_export(AIBOM.load(bom), export)
    assert not report.errors
    assert {a["advisory_id"] for a in report.advisories} == {"GHSA-range", "PYSEC-LISTED"}


def test_unevaluable_advisories_make_the_result_incomplete(tmp_path):
    export = tmp_path / "records.json"
    export.write_text(
        json.dumps(
            [
                osv(
                    "GHSA-git",
                    "PyPI",
                    "requests",
                    ranges=[{"type": "GIT", "events": [{"introduced": "abc123"}]}],
                )
            ]
        )
    )
    bom = inventory_of(tmp_path, package("requests", "2.19.0"))
    result = run("advisories", str(bom), "--input", str(export))
    assert result.exit_code == exits.INCOMPLETE
    assert "cannot be evaluated offline" in json.loads(result.stdout)["errors"][0]


def test_osv_export_reading_is_bounded_and_never_follows_links(tmp_path):
    bom = AIBOM.load(inventory_of(tmp_path, package("requests", "2.19.0")))
    linked = tmp_path / "linked"
    linked.mkdir()
    (tmp_path / "outside.json").write_text(json.dumps(RECORDS[0]))
    (linked / "record.json").symlink_to(tmp_path / "outside.json")
    assert match_export(bom, linked).errors
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("big.json", "[" + " " * (5 * 1024 * 1024) + "]")
    assert match_export(bom, archive).errors
    garbage = tmp_path / "garbage.json"
    garbage.write_text('{"id": "A", "id": "B"}')
    assert match_export(bom, garbage).errors


# --- Exit-code contract -------------------------------------------------------


def test_exit_codes_are_deterministic_across_commands(tmp_path):
    root, bom = scanned(tmp_path, floating=True)
    assert run("scan", str(root), "--bogus-option").exit_code == exits.FAILURE
    assert run("scan", str(root), "--scanner", "nope").exit_code == exits.FAILURE
    gated = run("scan", str(root), "-o", str(tmp_path / "gated.json"))
    assert gated.exit_code == exits.GATE, gated.output
    complete = _make_fixture_bom(tmp_path, "complete.json")
    assert run("risk", str(complete), "--fail-on-severity", "none").exit_code == exits.OK
    assert run("risk", str(bom), "--threshold", "100", "--fail-on-severity", "none").exit_code == (
        exits.GATE
    ), "partial coverage fails the gate whatever the threshold"
    assert run("risk", str(bom), "--fail-on-severity", "medium").exit_code == exits.GATE
    assert run("diff", str(bom), str(bom), "--fail-on-change").exit_code == exits.OK
    changed = tmp_path / "changed.json"
    run("scan", str(project(tmp_path / "second")), "--report-only", "-o", str(changed))
    assert run("diff", str(bom), str(changed), "--fail-on-change").exit_code == exits.GATE
    assert run("diff", str(bom), str(changed)).exit_code == exits.OK
    model = root / "model.bin"
    model.write_bytes(b"x")
    wrong = run(
        "verify-artifact", str(model), "--project", str(root), "--sha256", "sha256:" + "0" * 64
    )
    assert wrong.exit_code == exits.GATE
    assert run("init", "--path", str(tmp_path)).exit_code == exits.OK
    assert run("init", "--path", str(tmp_path)).exit_code == exits.FAILURE
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    for command in ("summary", "validate", "risk", "vex", "blast-radius"):
        args = [command, str(broken)] + (["agent:x"] if command == "blast-radius" else [])
        result = run(*args)
        assert result.exit_code == exits.FAILURE, (command, result.output)
        assert (
            "Traceback" not in result.output and "not a readable native AgentBOM" in result.output
        )


def test_missing_sigstore_extra_is_a_setup_failure_not_a_failed_verification(tmp_path, monkeypatch):
    from nexus_symbiote.utils import crypto

    monkeypatch.setattr(
        crypto,
        "verify_sigstore_digest",
        lambda *args: crypto.VerificationResult(False, error=crypto.SIGSTORE_MISSING),
    )
    root = tmp_path / "project"
    root.mkdir()
    (root / "model.bin").write_bytes(b"x")
    bundle = tmp_path / "model.sigstore.json"
    bundle.write_text("{}")
    digest = "sha256:" + hashlib.sha256(b"x").hexdigest()
    args = ("--bundle", str(bundle), "--signer-identity", "id", "--issuer", "https://issuer")
    result = run(
        "verify-artifact",
        str(root / "model.bin"),
        "--project",
        str(root),
        "--sha256",
        digest,
        *args,
    )
    assert result.exit_code == exits.FAILURE and "nexus-symbiote[sigstore]" in result.output
    monkeypatch.setattr(
        crypto, "verify_sigstore_digest", lambda *args: crypto.VerificationResult(False, error="x")
    )
    result = run(
        "verify-artifact",
        str(root / "model.bin"),
        "--project",
        str(root),
        "--sha256",
        digest,
        *args,
    )
    assert result.exit_code == exits.GATE


def test_output_failures_exit_1_without_a_traceback(tmp_path):
    root = project(tmp_path)
    result = run("scan", str(root), "--report-only", "-o", str(tmp_path / "missing" / "out.json"))
    assert result.exit_code == exits.FAILURE
    assert "input or output failure" in result.output and "Traceback" not in result.output


@pytest.mark.parametrize(
    "raw",
    [b'[{"tools": []}] , "pages": []', b"[]", b'{"tools": [], "tools": []}', b"not json"],
)
def test_malformed_tools_list_exports_are_incomplete(tmp_path, raw):
    export = tmp_path / "tools.json"
    export.write_bytes(raw)
    result = run("discover-mcp", "--input", str(export))
    assert result.exit_code == exits.INCOMPLETE
    assert json.loads(result.stdout)["complete"] is False
