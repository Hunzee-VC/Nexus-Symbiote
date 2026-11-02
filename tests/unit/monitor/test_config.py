"""symbiote-monitor.yaml loading and validation (spec/monitoring.md §5)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from symbiote.model.enums import Severity
from symbiote.monitor import ConfigError, RiskTier, load_config
from symbiote.monitor.config import MAX_CONFIG_BYTES

REPO = Path(__file__).resolve().parents[3]


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "symbiote-monitor.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_spec_example_loads(tmp_path: Path) -> None:
    cfg = load_config(
        _write(
            tmp_path,
            """
state_dir: .symbiote/monitor
cadence: {critical: 10m, high: 1h, medium: 1d, low: 14d}
deescalate_after: 3
fail_on: high
advisories: true
update_policy: {cooldown_days: 7, security_cooldown_days: 2, require_provenance_continuity: true}
notify:
  - {type: webhook, url_env: SYMBIOTE_WEBHOOK_URL, min_severity: high}
agents:
  - name: triage-agent
    path: examples/triage-agent
    environment: production
    risk: auto
    baseline: approved/triage-agent.agentbom.json
    attestation: {bundle: approved/triage-agent.sigstore.json, policy: approved/verify-policy.yaml}
""",
        )
    )
    base = tmp_path.resolve()
    assert cfg.state_dir == base / ".symbiote/monitor"
    t = cfg.agents[0]
    assert t.path == base / "examples/triage-agent"
    assert t.risk is None
    assert t.baseline == base / "approved/triage-agent.agentbom.json"
    assert t.attestation is not None and t.attestation.policy == base / "approved/verify-policy.yaml"
    assert cfg.fail_on is Severity.HIGH
    assert cfg.update_policy.cooldown_days == 7
    assert cfg.notify[0].url_env == "SYMBIOTE_WEBHOOK_URL"
    assert cfg.cadence[RiskTier.LOW] == timedelta(days=14)
    assert cfg.concurrency == 4


def test_defaults(tmp_path: Path) -> None:
    cfg = load_config(_write(tmp_path, "agents: [{name: a, path: .}]\n"))
    assert cfg.deescalate_after == 3
    assert cfg.advisories is True
    assert cfg.notify == ()
    assert cfg.agents[0].environment == "development"
    assert cfg.cadence[RiskTier.CRITICAL] == timedelta(minutes=10)


def test_shipped_example_is_valid() -> None:
    cfg = load_config(REPO / "examples" / "monitor" / "symbiote-monitor.yaml")
    assert cfg.agents[0].name == "triage-agent"
    assert cfg.agents[0].path.is_dir()


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("agents: []\n", "non-empty"),
        ("agents: [{name: a, path: .}, {name: A, path: x}]\n", "duplicate"),
        ("agents: [{name: a, path: ., colour: red}]\n", "unknown key"),
        ("bogus: 1\nagents: [{name: a, path: .}]\n", "unknown key"),
        ("cadence: {critical: 30s}\nagents: [{name: a, path: .}]\n", "floor"),
        ("cadence: {urgent: 1m}\nagents: [{name: a, path: .}]\n", "unknown key"),
        ("agents: [{name: a, path: ., interval: 10}]\n", "floor"),
        ("agents: [{name: a, path: ., risk: extreme}]\n", "risk"),
        ("agents: [{name: ../evil, path: .}]\n", "name"),
        (
            "notify: [{type: webhook, url: 'https://hooks.example/secret'}]\nagents: [{name: a, path: .}]\n",
            "url_env",
        ),
        (
            "notify: [{type: webhook, url_env: 'https://x'}]\nagents: [{name: a, path: .}]\n",
            "environment variable",
        ),
        ("notify: [{type: email, url_env: X}]\nagents: [{name: a, path: .}]\n", "webhook"),
        ("fail_on: severe\nagents: [{name: a, path: .}]\n", "fail_on"),
        ("concurrency: 0\nagents: [{name: a, path: .}]\n", "concurrency"),
        ("update_policy: {cooldown: 3}\nagents: [{name: a, path: .}]\n", "unknown key"),
        ("- just a list\n", "mapping"),
        ("agents: [{name: a, path: .}]\nfail_on: [unclosed\n", "YAML"),
    ],
)
def test_invalid(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        load_config(_write(tmp_path, text))


def test_missing_and_oversized(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")
    big = _write(tmp_path, "# " + "x" * MAX_CONFIG_BYTES + "\nagents: [{name: a, path: .}]\n")
    with pytest.raises(ConfigError, match="larger"):
        load_config(big)
