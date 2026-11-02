"""``symbiote monitor``: risk-tiered continuous assurance (``spec/monitoring.md`` §1, §2, §6).

Exit codes (``spec/cli.md``): 0 nothing new at or above ``fail_on``; 1 new failing findings, drift, vulnerable or
malicious dependencies, or verification failures at or above ``fail_on``; 2 invalid configuration or usage;
6 a cycle could not run or could not complete a check (an advisor or attestation it needed was unavailable), the
monitor lock or state could not be used, or an internal error occurred; 7 a chain conflict (anti-rollback).
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console

from symbiote.cli import exit_codes

__all__ = ["monitor_app", "register"]

monitor_app = typer.Typer(
    help="Continuous assurance: re-scan and re-verify agents on a risk-tiered cadence.",
    no_args_is_help=True,
)
_console = Console(stderr=True)

ConfigOpt = Annotated[
    Path,
    typer.Option("--config", "-c", help="Monitor configuration file."),
]
JsonOpt = Annotated[bool, typer.Option("--json", help="Machine-readable JSON on stdout.")]

_INIT_TEMPLATE = """\
# symbiote-monitor.yaml - see spec/monitoring.md section 5.
# Secrets never go in this file: webhook URLs are read from the environment variables named below.
state_dir: .symbiote/monitor
cadence: {{critical: 10m, high: 1h, medium: 1d, low: 14d}}
deescalate_after: 3
fail_on: high
advisories: true
update_policy: {{cooldown_days: 7, security_cooldown_days: 2, require_provenance_continuity: true}}
notify:
  - {{type: webhook, url_env: SYMBIOTE_WEBHOOK_URL, min_severity: high}}
agents:
  - name: {name_q}
    path: {path_q}
    environment: {environment_q}
    risk: auto            # or critical | high | medium | low (an explicit tier is a floor)
    # baseline: approved/{name}.agentbom.json
    # attestation: {{bundle: approved/{name}.sigstore.json, policy: approved/verify-policy.yaml}}
"""


def _emit(data: Any, as_json: bool, human: str) -> None:
    if as_json:
        sys.stdout.write(json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n")
    else:
        _console.print(human, highlight=False)


def _load(config: Path) -> Any:
    from symbiote.monitor.config import ConfigError, load_config

    try:
        return load_config(config)
    except ConfigError as exc:
        _console.print(f"[red]invalid monitor configuration[/red]: {exc}", highlight=False)
        raise typer.Exit(exit_codes.USAGE) from None


def _internal_error(exc: Exception) -> NoReturn:
    """Map an unexpected exception to exit 6 (a cycle could not run), never Python's default 1 ("findings")."""
    _console.print(f"[red]monitor failed[/red]: {type(exc).__name__}: {str(exc)[:300]}", highlight=False)
    raise typer.Exit(exit_codes.IO) from None


def _record_line(r: Any) -> str:
    colour = {"ok": "green", "findings": "red", "incomplete": "yellow", "error": "yellow"}.get(
        r.status, "white"
    )
    parts = [
        f"[{colour}]{r.status:10s}[/{colour}] {r.agent}",
        f"tier={r.tier}" + (" (escalated)" if r.escalated else ""),
        f"new={len(r.new_findings)} resolved={len(r.resolved_findings)} drift={len(r.drift)}",
        f"deps={r.dependency_coverage}",
        f"next={r.next_due_at}",
    ]
    lines = ["  ".join(parts)]
    lines.extend(f"    [yellow]error[/yellow] {e}" for e in r.errors[:3])
    lines.extend(f"    [yellow]incomplete[/yellow] {e}" for e in r.incomplete[:3])
    lines.extend(f"    escalation: {reason}" for reason in r.escalation_reasons[:5])
    return "\n".join(lines)


@monitor_app.command("tick")
def tick_cmd(config: ConfigOpt = Path("symbiote-monitor.yaml"), as_json: JsonOpt = False) -> None:
    """Run every agent that is due now, then exit (cron, systemd timers, Kubernetes CronJobs, CI)."""
    from symbiote.monitor.runner import tick
    from symbiote.monitor.state import StateError, StateLockedError

    cfg = _load(config)
    try:
        report = tick(cfg)
    except StateLockedError as exc:
        _console.print(f"[yellow]monitor busy[/yellow]: {exc}", highlight=False)
        raise typer.Exit(exit_codes.IO) from None
    except (StateError, OSError) as exc:
        _console.print(f"[red]monitor state unusable[/red]: {exc}", highlight=False)
        raise typer.Exit(exit_codes.IO) from None
    except Exception as exc:  # never let an internal failure exit 1, which means "new findings"
        _internal_error(exc)
    lines = [f"{len(report.records)} agent(s) ran, {len(report.not_due)} not due"]
    lines.extend(_record_line(r) for r in report.records)
    if report.next_wake_at:
        lines.append(f"next due: {report.next_wake_at}")
    _emit(report.to_json(), as_json, "\n".join(lines))
    raise typer.Exit(report.exit_code)


@monitor_app.command("run")
def run_cmd(config: ConfigOpt = Path("symbiote-monitor.yaml"), as_json: JsonOpt = False) -> None:
    """Long-running scheduler: sleep until the next due agent, run, repeat; stops on SIGINT/SIGTERM."""
    from symbiote.monitor.runner import TickReport, run_forever

    cfg = _load(config)

    def on_tick(report: TickReport) -> None:
        if as_json:
            sys.stdout.write(json.dumps(report.to_json(), default=str) + "\n")
            sys.stdout.flush()
        else:
            for r in report.records:
                _console.print(_record_line(r), highlight=False)

    _console.print(f"monitoring {len(cfg.agents)} agent(s); Ctrl-C to stop", highlight=False)
    run_forever(cfg, on_tick=on_tick)
    raise typer.Exit(exit_codes.OK)


@monitor_app.command("plan")
def plan_cmd(config: ConfigOpt = Path("symbiote-monitor.yaml"), as_json: JsonOpt = False) -> None:
    """Show each agent's tier, interval and next due time (nothing is run)."""
    from symbiote.monitor.runner import plan
    from symbiote.monitor.state import StateError

    cfg = _load(config)
    try:
        rows = plan(cfg, now=datetime.now(UTC))
    except StateError as exc:
        _console.print(f"[red]monitor state unusable[/red]: {exc}", highlight=False)
        raise typer.Exit(exit_codes.IO) from None
    except Exception as exc:
        _internal_error(exc)
    lines = [
        f"{row['agent']:24s} tier={row['tier']:8s} interval={row['interval']:>16s} "
        f"next={row['nextDueAt'] or 'now'}"
        + (" [due]" if row["due"] else "")
        + ("" if row["enabled"] else " [disabled]")
        for row in rows
    ]
    _emit({"agents": rows}, as_json, "\n".join(lines))


@monitor_app.command("status")
def status_cmd(config: ConfigOpt = Path("symbiote-monitor.yaml"), as_json: JsonOpt = False) -> None:
    """Show each agent's last cycle result."""
    from symbiote.monitor.runner import open_store
    from symbiote.monitor.state import AgentState, StateError

    cfg = _load(config)
    store = open_store(cfg)
    try:
        states = store.load()
    except StateError as exc:
        _console.print(f"[red]monitor state unusable[/red]: {exc}", highlight=False)
        raise typer.Exit(exit_codes.IO) from None
    except Exception as exc:
        _internal_error(exc)
    rows: list[dict[str, Any]] = []
    for t in cfg.agents:
        st = states.get(t.name, AgentState(name=t.name))
        data = st.to_json()
        data.pop("findings", None)
        data["failingFindings"] = len(st.findings)
        rows.append(data)
    lines = [
        f"{r['name']:24s} {r['lastStatus'] or 'never-run':10s} tier={r['tier'] or '-':8s}"
        f"{' (escalated)' if r['escalated'] else ''} failing={r['failingFindings']} "
        f"errors={r['consecutiveErrors']} last={r['lastRunAt'] or '-'}"
        for r in rows
    ]
    _emit({"agents": rows}, as_json, "\n".join(lines))


@monitor_app.command("init")
def init_cmd(
    config: ConfigOpt = Path("symbiote-monitor.yaml"),
    path: Annotated[str, typer.Option("--path", help="Agent directory, relative to the config file.")] = ".",
    name: Annotated[str | None, typer.Option("--name", help="Agent name (default: directory name).")] = None,
    environment: Annotated[
        str, typer.Option("--environment", help="production | staging | internal | development")
    ] = "development",
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing file.")] = False,
) -> None:
    """Write a starter symbiote-monitor.yaml."""
    import re

    from symbiote.monitor.config import ConfigError, load_config

    if config.exists() and not force:
        _console.print(f"[red]{config} already exists[/red] (use --force to overwrite)", highlight=False)
        raise typer.Exit(exit_codes.USAGE)
    agent_name = name or (Path(path).resolve().name if path not in ("", ".") else Path.cwd().name)
    agent_name = re.sub(r"[^A-Za-z0-9._-]", "-", agent_name).strip("-.") or "agent"
    if not re.fullmatch(r"[A-Za-z0-9._/~-]{1,512}", path) or not re.fullmatch(r"[A-Za-z]{1,32}", environment):
        _console.print("[red]--path or --environment contains unsupported characters[/red]", highlight=False)
        raise typer.Exit(exit_codes.USAGE)
    # JSON strings are YAML scalars that always read back as strings (``null``, ``~``, ``yes``, ``123`` …).
    text = _INIT_TEMPLATE.format(
        name=agent_name,
        name_q=json.dumps(agent_name),
        path_q=json.dumps(path),
        environment_q=json.dumps(environment),
    )
    config.parent.mkdir(parents=True, exist_ok=True)
    # Validate a temporary file next to the target (relative paths resolve the same way), then move it into
    # place: an invalid configuration is never left on disk.
    tmp = config.with_name(f".{config.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        try:
            load_config(tmp)
        except ConfigError as exc:
            _console.print(f"[red]generated configuration is invalid[/red]: {exc}", highlight=False)
            raise typer.Exit(exit_codes.USAGE) from None
        os.replace(tmp, config)
    finally:
        tmp.unlink(missing_ok=True)
    _console.print(f"wrote {config}", highlight=False)


def register(app: typer.Typer) -> None:
    """Add the ``monitor`` command group to ``app``."""
    app.add_typer(monitor_app, name="monitor")
