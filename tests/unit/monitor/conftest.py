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
    dest = tmp_path / "agents" / "triage-agent"
    shutil.copytree(TRIAGE, dest)
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
