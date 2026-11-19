"""CLI registration for approved MCP descriptor registries and evidence packages."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from nexus_symbiote.core.hashing import open_regular_file, parse_json_strict
from nexus_symbiote.descriptor_registry import (
    build_evidence_package,
    build_signed_descriptor_registry,
    generate_ed25519_keypair,
    reconcile_runtime_telemetry,
    verify_against_descriptor_registry,
)
from nexus_symbiote.utils.terminal import (
    echo_line,
    json_text,
    refuse_dash_output,
    write_cli_output,
)


def _load_json_file(path: Path) -> Any:
    with open_regular_file(path) as stream:
        raw = stream.read(4_194_304).decode("utf-8", errors="replace")
    return parse_json_strict(raw)


def register_descriptor_registry_commands(main: click.Group) -> None:
    """Register approve-descriptors and bundle-evidence-pack on the root Click group."""

    @main.command("approve-descriptors")
    @click.argument(
        "descriptors_file",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
    )
    @click.option(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Write the signed DSSE descriptor registry JSON to a file path.",
    )
    @click.option(
        "--verify-against",
        "verify_current_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        default=None,
        help="Optional current MCP server descriptors JSON file to verify against the signed registry.",
    )
    @click.option(
        "--json-output",
        is_flag=True,
        default=False,
        help="Emit JSON output to standard output.",
    )
    def approve_descriptors_cmd(
        descriptors_file: Path,
        output: str | None,
        verify_current_path: Path | None,
        json_output: bool,
    ) -> None:
        """Sign an approved MCP descriptor registry or verify current descriptors against it."""
        raw_doc = _load_json_file(descriptors_file)
        servers = (
            raw_doc
            if isinstance(raw_doc, list)
            else (raw_doc.get("servers") if isinstance(raw_doc, dict) else [])
        )
        srv_list = [s for s in (servers or []) if isinstance(s, dict)]
        priv, pub, kid = generate_ed25519_keypair()
        envelope = build_signed_descriptor_registry(srv_list, priv)

        verified_ok = True
        findings: list[dict[str, Any]] = []
        if verify_current_path is not None:
            curr_doc = _load_json_file(verify_current_path)
            curr_raw = (
                curr_doc
                if isinstance(curr_doc, list)
                else (curr_doc.get("servers") if isinstance(curr_doc, dict) else [])
            )
            curr_list = [s for s in (curr_raw or []) if isinstance(s, dict)]
            verified_ok, findings = verify_against_descriptor_registry(envelope, curr_list, [pub])

        payload = {
            "signer_key_id": kid,
            "approved_server_count": len(srv_list),
            "verified": verified_ok,
            "security_flags": findings,
            "envelope": envelope,
        }
        rendered = json_text(json.dumps(payload, indent=2, sort_keys=True))
        if output is not None:
            refuse_dash_output(output)
            write_cli_output(Path(output), rendered, overwrite=True)

        if json_output:
            click.echo(rendered)
        else:
            echo_line(
                f"Descriptor registry ({kid}): {len(srv_list)} server(s), verified={verified_ok}, {len(findings)} finding(s)."
            )
            for fl in findings:
                echo_line(
                    "  [", fl["severity"].upper(), "] ", fl["category"], ": ", fl["description"]
                )

        if not verified_ok:
            raise click.exceptions.Exit(1)

    @main.command("bundle-evidence-pack")
    @click.argument(
        "project_path",
        type=click.Path(exists=True, file_okay=False, path_type=Path),
        default=Path(),
    )
    @click.option(
        "--otlp-spans",
        "otlp_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        default=None,
        help="Optional OTLP/JSON spans file for runtime model-resolution and sampling/elicitation reconciliation.",
    )
    @click.option(
        "--k8s-mlbom",
        "k8s_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        default=None,
        help="Optional k8s-aibom ML-BOM JSON file for cluster image/model reconciliation.",
    )
    @click.option(
        "--image-digest",
        type=str,
        default=None,
        help="Optional container image SHA-256 subject digest for the OCI referrer gate-verdict attestation.",
    )
    @click.option(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Write the bundled evidence package JSON to a file path.",
    )
    @click.option(
        "--json-output",
        is_flag=True,
        default=False,
        help="Emit JSON evidence package to standard output.",
    )
    @click.option(
        "--fail-on-verdict",
        is_flag=True,
        default=False,
        help="Exit 1 when the evidence package gate verdict is 'failed'.",
    )
    def bundle_evidence_pack_cmd(
        project_path: Path,
        otlp_path: Path | None,
        k8s_path: Path | None,
        image_digest: str | None,
        output: str | None,
        json_output: bool,
        fail_on_verdict: bool,
    ) -> None:
        """Bundle read-set binding, complete crosswalk, data residency, runtime telemetry, and OCI verdict attestation."""
        extra_findings: list[dict[str, Any]] = []
        telemetry_report: dict[str, Any] | None = None
        if otlp_path is not None or k8s_path is not None:
            spans = _load_json_file(otlp_path) if otlp_path is not None else None
            mlbom = _load_json_file(k8s_path) if k8s_path is not None else None
            telemetry_report = reconcile_runtime_telemetry(
                otlp_spans=spans if isinstance(spans, list) else None,
                k8s_mlbom=mlbom if isinstance(mlbom, dict) else None,
            )
            extra_findings.extend(telemetry_report["security_flags"])

        pack = build_evidence_package(
            project_path,
            findings=extra_findings,
            image_subject_digest=image_digest,
        )
        if telemetry_report is not None:
            pack["runtime_telemetry"] = telemetry_report

        rendered = json_text(json.dumps(pack, indent=2, sort_keys=True))
        if output is not None:
            refuse_dash_output(output)
            write_cli_output(Path(output), rendered, overwrite=True)

        if json_output:
            click.echo(rendered)
        else:
            echo_line(
                f"Evidence package: verdict={pack['verdict']}, read_set_root={pack['read_set_binding']['read_set_root']}, "
                f"findings={len(pack['security_flags'])}."
            )

        if fail_on_verdict and pack["verdict"] != "passed":
            raise click.exceptions.Exit(1)
