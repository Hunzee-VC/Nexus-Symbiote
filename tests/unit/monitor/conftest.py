"""Shared fixtures for the monitor tests: a temporary copy of the triage-agent example and a config for it."""

from __future__ import annotations

import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from symbiote.monitor import MonitorConfig, load_config

REPO = Path(__file__).resolve().parents[3]
TRIAGE = REPO / "examples" / "triage-agent"
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def agent_dir(tmp_path: Path) -> Path:
    """The example agent without its deliberately unsafe model directory.

    ``models-local`` reports the pickle weights and the ``trust_remote_code`` config there as critical
    ``SYM-MODEL-002`` findings, which would pin the agent to the critical tier and make the tier, cadence and escalation tests below vacuous; ``test_critical_finding_tier``
    covers the critical path with the model present.
    """
    dest = tmp_path / "agents" / "triage-agent"
    shutil.copytree(TRIAGE, dest)
    shutil.rmtree(dest / "models", ignore_errors=True)
    return dest


@pytest.fixture
def make_config(tmp_path: Path, agent_dir: Path) -> Callable[..., MonitorConfig]:
    def build(extra: str = "", agent_extra: str = "", *, advisories: bool = False) -> MonitorConfig:
        text = (
            "state_dir: state\n"
            f"advisories: {'true' if advisories else 'false'}\n"
            f"{extra}"
            "agents:\n"
            "  - name: triage-agent\n"
            "    path: agents/triage-agent\n"
            "    environment: production\n"
            f"{agent_extra}"
        )
        path = tmp_path / "symbiote-monitor.yaml"
        path.write_text(text, encoding="utf-8")
        return load_config(path)

    return build
