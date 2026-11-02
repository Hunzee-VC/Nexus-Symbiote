"""``symbiote shadowscan …``: the Nexus ShadowScan integration commands (``spec/cli.md``, ``spec/shadowscan-mapping.md``)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console

from symbiote.cli import exit_codes
from symbiote.cli._render import safe_markup

shadowscan_app = typer.Typer(
    help=(
        "Nexus ShadowScan integration: import discovery reports as observed snapshots, export the AgentBOM as "
        "the ShadowScan inventory, and reconcile what was declared with what was found."
    ),
    no_args_is_help=True,
)
console = Console(stderr=True)
JsonFlag = Annotated[bool, typer.Option("--json", help="Machine-readable JSON on stdout.")]


def _emit(data: Any, as_json: bool, human: str) -> None:
    if as_json:
        sys.stdout.write(json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n")
    else:
        console.print(safe_markup(human))


def _read(path: Path) -> Any:
    from symbiote.shadowscan.report import ReportError, read_report

    try:
        return read_report(path)
    except (OSError, ReportError) as exc:
        console.print(f"[red]cannot read ShadowScan report[/red] {path}: {exc}")
        raise typer.Exit(exit_codes.IO if isinstance(exc, OSError) else exit_codes.SCHEMA) from None


@shadowscan_app.command("levels")
def levels(as_json: JsonFlag = False) -> None:
    """Show the ShadowScan L0-L5 autonomy scale and its ISO/IEC 22989 (SPDX 3.1 isoAutomationLevel) projection."""
    from symbiote.shadowscan.autonomy import table

    rows = table()
    lines = [f"{r['level']:3s} {r['label']:36s} → {r['iso22989']:22s} {r['meaning']}" for r in rows]
    lines.append(
        "L5 is 'not ruled out' as a ceiling; ISO 'autonomous' has no ShadowScan counterpart (narrowed to L5 with a recorded loss)."
    )
    _emit(rows, as_json, "\n".join(lines))


@shadowscan_app.command("import")
def import_cmd(
    report: Annotated[
        Path,
        typer.Argument(
            help="ShadowScan JSON report (--format json) or CycloneDX output (--format cyclonedx)."
        ),
    ],
    out: Annotated[Path, typer.Option("-o", "--out", help="Output directory.")] = Path("."),
    name: Annotated[
        str | None,
        typer.Option(
            "--name", help="Root agent name (default: the scanned directory's name, or 'shadowscan-estate')."
        ),
    ] = None,
    fmt: Annotated[str, typer.Option("--format", help="companion | cyclonedx | spdx | all")] = "all",
    scope: Annotated[
        str,
        typer.Option(
            "--scope", help="estate (every finding) | root (only findings about the scanned repository)"
        ),
    ] = "estate",
    scan_root: Annotated[
        str | None,
        typer.Option(
            "--scan-root", help="Override the scan root recorded in the report (reports produced elsewhere)."
        ),
    ] = None,
    deterministic: Annotated[
        bool,
        typer.Option(
            "--deterministic", help="Pin timestamps and the Merkle nonce for byte-identical output."
        ),
    ] = False,
    no_policy: Annotated[bool, typer.Option("--no-policy", help="Skip the built-in policy checks.")] = False,
    as_json: JsonFlag = False,
) -> None:
    """Import a ShadowScan report as an OBSERVED AgentBOM snapshot (companion, CycloneDX 1.7, SPDX 3.0.1)."""
    from symbiote.digest import bytes_digest
    from symbiote.export.companion import companion_bytes
    from symbiote.shadowscan.mapping import import_report

    if fmt not in ("companion", "cyclonedx", "spdx", "all"):
        console.print(f"[red]unknown format {fmt!r}[/red]")
        raise typer.Exit(exit_codes.USAGE)
    if scope not in ("estate", "root"):
        console.print("[red]--scope must be estate or root[/red]")
        raise typer.Exit(exit_codes.USAGE)
    rep = _read(report)
    bom = import_report(
        rep,
        agent_name=name,
        deterministic=deterministic,
        scope=scope,
        scan_root=scan_root,
        policy=not no_policy,
    )
    out.mkdir(parents=True, exist_ok=True)
    companion = companion_bytes(bom)
    companion_path = out / "agentbom.observed.json"
    companion_path.write_bytes(companion)
    written = {"companion": str(companion_path)}
    errors: dict[str, list[str]] = {}
    digest = bytes_digest(companion)
    if fmt in ("cyclonedx", "all"):
        from symbiote.export.cdx import export_cyclonedx, validate_cyclonedx

        doc, loss = export_cyclonedx(bom, companion_digest=digest, companion_ref=companion_path.name)
        errors["cyclonedx"] = validate_cyclonedx(doc)
        (out / "agentbom.observed.cdx.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        (out / "agentbom.observed.cdx.loss.json").write_text(
            json.dumps(loss.to_json_dict(), indent=2) + "\n", encoding="utf-8"
        )
        written["cyclonedx"] = str(out / "agentbom.observed.cdx.json")
    if fmt in ("spdx", "all"):
        from symbiote.export.spdx import export_spdx, validate_spdx

        sdoc, sloss = export_spdx(bom, companion_digest=digest, companion_ref=companion_path.name)
        from symbiote.export.spdx.validate import SCHEMA_ELEMENT_BUDGET

        errors["spdx"] = validate_spdx(sdoc)
        if len(sdoc.get("@graph", [])) > SCHEMA_ELEMENT_BUDGET:
            rep.warnings.append(
                f"SPDX: {len(sdoc['@graph'])} elements exceed the schema-validation budget ({SCHEMA_ELEMENT_BUDGET}); "
                "only the spdx-python-model round trip was checked"
            )
        (out / "agentbom.observed.spdx.json").write_text(json.dumps(sdoc, indent=2) + "\n", encoding="utf-8")
        (out / "agentbom.observed.spdx.loss.json").write_text(
            json.dumps(sloss.to_json_dict(), indent=2) + "\n", encoding="utf-8"
        )
        written["spdx"] = str(out / "agentbom.observed.spdx.json")
    root = bom.root_agent
    counts = {
        k: len(getattr(bom, k))
        for k in (
            "agents",
            "deployments",
            "tool_servers",
            "tools",
            "models",
            "identities",
            "credential_bindings",
            "grants",
            "evidence",
        )
        if getattr(bom, k)
    }
    assessment = root.autonomy_assessment
    summary = {
        "agent": bom.subject,
        "snapshot": bom.snapshot.digest,
        "kind": bom.snapshot.kind.value,
        "shadowscan": {
            "version": rep.version,
            "format": rep.source_format,
            "complete": rep.complete,
            "findings": len(rep.findings),
            "byKind": rep.by_kind(),
            "scanRoots": rep.scan_roots,
        },
        "entities": counts,
        "edges": len(bom.edges),
        "autonomy": assessment.to_json_dict() if assessment else None,
        "coverage": {s.value: c.status.value for s, c in bom.coverage.surfaces.items()},
        "flags": sorted(
            {f"{f.flag.value}={f.value.value}" for f in bom.derived.flags if f.value.value != "false"}
        ),
        "findings": {
            "fail": sum(1 for f in bom.derived.findings if f.state.value == "fail"),
            "indeterminate": sum(1 for f in bom.derived.findings if f.state.value == "indeterminate"),
        },
        "loss": [i.to_json_dict() for i in (bom.loss_report.items if bom.loss_report else [])][:20],
        "warnings": rep.warnings + rep.losses,
        "written": written,
        "cyclonedxValid": not errors.get("cyclonedx"),
        "spdxValid": not errors.get("spdx"),
        "cyclonedxErrors": errors.get("cyclonedx", [])[:10],
        "spdxErrors": errors.get("spdx", [])[:10],
    }
    lines = [
        f"[bold]{bom.subject}[/bold]  observed snapshot {bom.snapshot.digest[:23]}…  from ShadowScan {rep.version} ({rep.source_format}, {'complete' if rep.complete else 'INCOMPLETE'}, {len(rep.findings)} findings)",
        "entities: " + ", ".join(f"{k}={v}" for k, v in counts.items()),
    ]
    if assessment:
        lines.append(
            f"autonomy: floor L{assessment.floor} ({assessment.floor_level.value}) · ceiling L{assessment.ceiling} ({assessment.ceiling_level.value}) · oversight {assessment.oversight.value} · initiation {assessment.initiation.value}"
        )
    lines.append(
        "coverage: " + ", ".join(f"{k}={v}" for k, v in summary["coverage"].items() if v != "not-attempted")
    )
    fails = [f for f in bom.derived.findings if f.state.value == "fail"]
    lines.append(
        f"policy: {len(fails)} failing finding(s), {summary['findings']['indeterminate']} indeterminate"
    )
    for f in fails[:8]:
        lines.append(
            f"  [red]{f.severity.value:8s}[/red] {f.check_id}  {', '.join(f.subject_refs[:2])}  {f.message[:90]}"
        )
    for w in (rep.warnings + rep.losses)[:6]:
        lines.append(f"[yellow]note[/yellow] {w}")
    lines.extend(f"written: {v}" for v in written.values())
    for label, key in (("CycloneDX 1.7", "cyclonedx"), ("SPDX 3.0.1", "spdx")):
        if key in errors:
            lines.append(
                f"[green]{label} validates against the official schema[/green]"
                if not errors[key]
                else f"[red]{label} validation errors[/red]: " + "; ".join(errors[key][:3])
            )
    _emit(summary, as_json, "\n".join(lines))
    if any(errors.values()):
        raise typer.Exit(exit_codes.SCHEMA)


@shadowscan_app.command("inventory")
def inventory_cmd(
    companion: Annotated[
        Path, typer.Argument(help="AgentBOM companion document (declared or approved snapshot).")
    ],
    out: Annotated[
        Path, typer.Option("-o", "--out", help="Output directory (cards) or file (agents.yaml / agents.csv).")
    ] = Path("inventory"),
    fmt: Annotated[str, typer.Option("--format", help="cards | agents | csv")] = "cards",
    resource: Annotated[
        list[str] | None,
        typer.Option(
            "--resource", help="Additional discovery.resources pattern for the root agent (repeatable)."
        ),
    ] = None,
    scan_root: Annotated[
        str | None,
        typer.Option(
            "--scan-root", help="Bind the repository path ShadowScan scans (adds '<root>' and '<root>/*')."
        ),
    ] = None,
    include_external: Annotated[
        bool, typer.Option("--include-external", help="Also write entries for external agents (A2A peers).")
    ] = False,
    classification: Annotated[
        str | None, typer.Option("--classification", help="metadata.classification for every card.")
    ] = None,
    as_json: JsonFlag = False,
) -> None:
    """Export the AgentBOM as a ShadowScan inventory so 'shadow' means 'not in the AgentBOM'."""
    from symbiote.export.companion import load_companion
    from symbiote.shadowscan.inventory import InventoryFormat, export_inventory

    if fmt not in ("cards", "agents", "csv"):
        console.print("[red]--format must be cards, agents or csv[/red]")
        raise typer.Exit(exit_codes.USAGE)
    bom = load_companion(companion)
    files = export_inventory(
        bom,
        InventoryFormat(fmt),
        include_external=include_external,
        resources=resource or [],
        scan_root=scan_root,
        classification=classification,
    )
    written: list[str] = []
    if fmt == "cards" or out.suffix == "" or out.is_dir():
        out.mkdir(parents=True, exist_ok=True)
        for fname, text in files.items():
            target = out / fname
            target.write_text(text, encoding="utf-8")
            written.append(str(target))
    else:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(next(iter(files.values())), encoding="utf-8")
        written.append(str(out))
    unbound = [
        n for n, t in files.items() if "resources: []" in t or ("resources:\n" not in t and fmt != "csv")
    ]
    summary = {
        "agent": bom.subject,
        "format": fmt,
        "written": written,
        "entries": len(files) if fmt == "cards" else sum(1 for _ in bom.agents),
        "note": "Resource bindings are approvals; review every pattern before passing the files to shadowscan --inventory.",
    }
    lines = [
        f"wrote {len(written)} file(s) for {bom.subject} ({fmt})",
        *written,
        "[yellow]review[/yellow] resource bindings are approvals; a card without resources only produces review suggestions",
    ]
    if unbound and fmt == "cards":
        lines.append(
            f"[yellow]{len(unbound)} card(s) have no resource binding; pass --scan-root or --resource[/yellow]"
        )
    _emit(summary, as_json, "\n".join(lines))


@shadowscan_app.command("reconcile")
def reconcile_cmd(
    companion: Annotated[Path, typer.Argument(help="Declared or approved AgentBOM companion document.")],
    report: Annotated[
        Path, typer.Argument(help="ShadowScan JSON report (or CycloneDX output) over the same agent.")
    ],
    scan_root: Annotated[
        str | None, typer.Option("--scan-root", help="Override the scan root recorded in the report.")
    ] = None,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Exit 1 when a failing finding has at least this severity: critical|high|medium|low|info|none",
        ),
    ] = "high",
    out: Annotated[
        Path | None, typer.Option("-o", "--out", help="Write the reconciliation JSON here.")
    ] = None,
    sarif: Annotated[
        Path | None, typer.Option("--sarif", help="Write the findings as SARIF 2.1.0 here.")
    ] = None,
    deterministic: Annotated[
        bool, typer.Option("--deterministic", help="Pin timestamps for reproducible output.")
    ] = False,
    as_json: JsonFlag = False,
) -> None:
    """Compare what the AgentBOM declares with what ShadowScan observed: shadow servers, stale declarations, autonomy."""
    from symbiote.export.companion import load_companion
    from symbiote.model.enums import Severity
    from symbiote.shadowscan.reconcile import reconcile

    bom = load_companion(companion)
    rep = _read(report)
    rec = reconcile(bom, rep, scan_root=scan_root, deterministic=deterministic)
    data = rec.summary()
    if out:
        out.write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")
    if sarif:
        from symbiote.policy import to_sarif

        sarif.write_text(json.dumps(to_sarif(rec.findings), indent=2) + "\n", encoding="utf-8")
    auto = rec.autonomy
    lines = [
        f"[bold]{rec.subject}[/bold] vs ShadowScan {rec.report_version} ({'complete' if rec.report_complete else 'INCOMPLETE'} scan, root {rec.scan_root or 'n/a'})",
        f"tool servers: {len(rec.matched)} matched · {len(rec.observed_not_declared)} observed-not-declared · {len(rec.declared_not_observed)} declared-not-observed ({rec.declared_not_observed_state})",
    ]
    for m in rec.matched[:12]:
        lines.append(f"  [green]match[/green] {m.declared_id} ({m.how})")
    for oid in rec.observed_not_declared[:12]:
        lines.append(f"  [red]observed, not declared[/red] {oid}")
    for did in rec.declared_not_observed[:12]:
        lines.append(f"  [yellow]declared, not observed[/yellow] {did}")
    if auto:
        lines.append(
            f"autonomy: declared {auto.declared_iso or 'none'}"
            + (f" (L{auto.declared_level})" if auto.declared_level is not None else "")
            + (
                f" · observed floor L{auto.floor} / ceiling L{auto.ceiling} · oversight {auto.oversight} · initiation {auto.initiation}"
                if auto.floor is not None
                else " · no observed assessment"
            )
            + f" → [bold]{auto.verdict}[/bold]"
        )
    if rec.shadow_findings:
        lines.append(f"shadow findings in report: {len(rec.shadow_findings)}")
    if rec.registered:
        lines.append(
            "registered: "
            + ", ".join(
                f"{r['registryMatch']}{'' if r['inAgentBom'] else ' (not an AgentBOM agent)'}"
                for r in rec.registered[:8]
            )
        )
    fails = [f for f in rec.findings if f.state.value == "fail"]
    lines.append(f"findings: {len(fails)} fail, {len(rec.findings) - len(fails)} indeterminate")
    for f in rec.findings[:16]:
        colour = "red" if f.state.value == "fail" else "yellow"
        lines.append(f"  [{colour}]{f.severity.value:8s}[/{colour}] {f.check_id}  {f.message[:100]}")
    if out:
        lines.append(f"written: {out}")
    if sarif:
        lines.append(f"written: {sarif}")
    _emit(data, as_json, "\n".join(lines))
    if fail_on != "none":
        try:
            threshold = Severity(fail_on)
        except ValueError:
            console.print("[red]--fail-on must be critical, high, medium, low, info or none[/red]")
            raise typer.Exit(exit_codes.USAGE) from None
        if rec.failing(threshold):
            raise typer.Exit(exit_codes.FINDINGS)


__all__ = ["shadowscan_app"]
