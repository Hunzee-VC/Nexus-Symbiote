"""``symbiote-monitor.yaml``: load and validate the monitor configuration (``spec/monitoring.md`` §5).

The file is parsed with ``yaml.safe_load`` behind a size cap, unknown keys are rejected at every level, agent
names are unique, relative paths resolve against the directory holding the config file, and notification
targets name *environment variables* only: secrets never appear in the file.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import yaml

from symbiote.model.enums import Severity
from symbiote.monitor.risk import DEFAULT_CADENCE, RiskTier, parse_interval

if TYPE_CHECKING:
    from symbiote.update.types import UpdatePolicy

__all__ = [
    "DEFAULT_CONFIG_NAME",
    "MAX_CONFIG_BYTES",
    "AttestationConfig",
    "ConfigError",
    "MonitorConfig",
    "NotifyTarget",
    "Target",
    "available_collectors",
    "config_from_mapping",
    "load_config",
]

DEFAULT_CONFIG_NAME = "symbiote-monitor.yaml"
MAX_CONFIG_BYTES = 1024 * 1024
MAX_AGENTS = 1000

_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_ENV_RE = re.compile(r"\A[A-Z_][A-Z0-9_]{0,127}\Z")
_COLLECTOR_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class ConfigError(ValueError):
    """The monitor configuration is missing, unreadable or invalid."""


def available_collectors() -> frozenset[str]:
    """Names of the collectors this installation can run (built-ins whose module is present, and plugins)."""
    from symbiote.collect.base import load_collectors

    return frozenset(c.name for c in load_collectors(warnings=[]))


def _policy_type() -> type[UpdatePolicy]:
    # Imported lazily, and after ``symbiote.advisories``: importing ``symbiote.update`` first currently trips a
    # circular import (update.types -> advisories -> advisories.engine -> update.types).
    import symbiote.advisories  # noqa: F401
    from symbiote.update.types import UpdatePolicy

    return UpdatePolicy


def _default_policy() -> UpdatePolicy:
    return _policy_type()()


@dataclass(frozen=True, slots=True)
class NotifyTarget:
    type: Literal["webhook"]
    #: Name of the environment variable holding the webhook URL (never the URL itself).
    url_env: str
    min_severity: Severity = Severity.HIGH
    timeout: float = 5.0


@dataclass(frozen=True, slots=True)
class AttestationConfig:
    bundle: Path
    policy: Path


@dataclass(frozen=True, slots=True)
class Target:
    name: str
    path: Path
    environment: str = "development"
    #: ``None`` means ``risk: auto``.
    risk: RiskTier | None = None
    interval: timedelta | None = None
    baseline: Path | None = None
    attestation: AttestationConfig | None = None
    #: Restrict the scan to these collectors (default: every static collector).
    collectors: tuple[str, ...] | None = None
    #: Override the agent name recorded in the BOM (default: the agent's own declaration).
    agent_name: str | None = None
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class MonitorConfig:
    config_path: Path | None
    state_dir: Path
    agents: tuple[Target, ...]
    cadence: Mapping[RiskTier, timedelta] = field(default_factory=lambda: dict(DEFAULT_CADENCE))
    deescalate_after: int = 3
    fail_on: Severity = Severity.HIGH
    advisories: bool = True
    update_policy: UpdatePolicy = field(default_factory=_default_policy)
    notify: tuple[NotifyTarget, ...] = ()
    #: Agents run in parallel by one tick.
    concurrency: int = 4
    #: Wall-clock budget for one agent's cycle; enforced between steps.
    agent_budget: timedelta = timedelta(minutes=5)
    #: How long a tick waits for another tick's lock before giving up.
    lock_timeout: timedelta = timedelta(seconds=30)
    #: Kept for compatibility; unused since the lock became an ``fcntl.flock`` (released when the holder exits).
    lock_stale_after: timedelta = timedelta(hours=1)
    #: ``monitor run`` never sleeps longer than this between ticks.
    max_sleep: timedelta = timedelta(minutes=5)
    #: Use only cached advisor answers (no network).
    offline: bool = False

    def target(self, name: str) -> Target:
        for t in self.agents:
            if t.name == name:
                return t
        raise KeyError(name)


# ---------------------------------------------------------------------------------------------- helpers


def _expect_mapping(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise ConfigError(f"{where}: expected a mapping")
    return value


def _reject_unknown(data: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigError(f"{where}: unknown key(s): {', '.join(unknown)}")


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{where}: expected true or false")
    return value


def _int(value: Any, where: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConfigError(f"{where}: expected an integer between {minimum} and {maximum}")
    return value


def _str(value: Any, where: str, *, max_len: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_len:
        raise ConfigError(f"{where}: expected a non-empty string")
    return value


def _interval(value: Any, where: str) -> timedelta:
    if isinstance(value, bool) or not isinstance(value, str | int):
        raise ConfigError(f"{where}: expected an interval such as 10m, 1h, 1d or 2w")
    text = f"{value}s" if isinstance(value, int) else value
    try:
        return parse_interval(text)
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from None


def _duration(value: Any, where: str, *, floor: timedelta = timedelta(seconds=1)) -> timedelta:
    """Like :func:`_interval` but for operational knobs that may be shorter than a minute."""
    if isinstance(value, bool):
        raise ConfigError(f"{where}: expected a duration such as 30s or 5m")
    if isinstance(value, int | float):
        seconds = float(value)
    elif isinstance(value, str):
        m = re.match(r"\A(\d{1,7})([smh])\Z", value.strip().lower())
        if m is None:
            raise ConfigError(f"{where}: expected a duration such as 30s or 5m")
        seconds = float(int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)])
    else:
        raise ConfigError(f"{where}: expected a duration such as 30s or 5m")
    result = timedelta(seconds=seconds)
    if result < floor or result > timedelta(days=7):
        raise ConfigError(f"{where}: out of range")
    return result


def _severity(value: Any, where: str) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        raise ConfigError(f"{where}: expected one of critical, high, medium, low, info") from None


def _path(value: Any, base_dir: Path, where: str) -> Path:
    text = _str(value, where)
    if "\x00" in text:
        raise ConfigError(f"{where}: invalid path")
    p = Path(text).expanduser()
    return p if p.is_absolute() else (base_dir / p)


# ---------------------------------------------------------------------------------------------- sections


def _cadence(value: Any) -> dict[RiskTier, timedelta]:
    data = _expect_mapping(value, "cadence")
    _reject_unknown(data, {t.value for t in RiskTier}, "cadence")
    out = dict(DEFAULT_CADENCE)
    for key, raw in data.items():
        out[RiskTier(key)] = _interval(raw, f"cadence.{key}")
    return out


def _update_policy(value: Any) -> UpdatePolicy:
    data = _expect_mapping(value, "update_policy")
    ints = {"cooldown_days", "security_cooldown_days"}
    bools = {"require_provenance_continuity", "block_new_install_scripts", "pin_floating", "allow_major"}
    _reject_unknown(data, ints | bools, "update_policy")
    kwargs: dict[str, Any] = {}
    for key, raw in data.items():
        if key in ints:
            kwargs[key] = _int(raw, f"update_policy.{key}", minimum=0, maximum=3650)
        else:
            kwargs[key] = _bool(raw, f"update_policy.{key}")
    return _policy_type()(**kwargs)


def _notify(value: Any) -> tuple[NotifyTarget, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError("notify: expected a list")
    out: list[NotifyTarget] = []
    for i, raw in enumerate(value):
        where = f"notify[{i}]"
        data = _expect_mapping(raw, where)
        if "url" in data:
            raise ConfigError(
                f"{where}: put the webhook URL in an environment variable and name it with url_env"
            )
        _reject_unknown(data, {"type", "url_env", "min_severity", "timeout"}, where)
        if data.get("type", "webhook") != "webhook":
            raise ConfigError(f"{where}.type: only 'webhook' is supported")
        env = _str(data.get("url_env"), f"{where}.url_env", max_len=128)
        if not _ENV_RE.match(env):
            raise ConfigError(
                f"{where}.url_env: expected an environment variable name such as SYMBIOTE_WEBHOOK_URL"
            )
        timeout = 5.0
        if "timeout" in data:
            timeout = _duration(data["timeout"], f"{where}.timeout").total_seconds()
            if timeout > 60:
                raise ConfigError(f"{where}.timeout: at most 60 seconds")
        out.append(
            NotifyTarget(
                type="webhook",
                url_env=env,
                min_severity=_severity(data.get("min_severity", "high"), f"{where}.min_severity"),
                timeout=timeout,
            )
        )
    return tuple(out)


_TARGET_KEYS = {
    "name",
    "path",
    "environment",
    "risk",
    "interval",
    "baseline",
    "attestation",
    "collectors",
    "agent_name",
    "enabled",
}


def _target(raw: Any, i: int, base_dir: Path) -> Target:
    where = f"agents[{i}]"
    data = _expect_mapping(raw, where)
    _reject_unknown(data, _TARGET_KEYS, where)
    name = _str(data.get("name"), f"{where}.name", max_len=128)
    if not _NAME_RE.match(name):
        raise ConfigError(f"{where}.name: use letters, digits, '.', '_' and '-' (at most 128 characters)")
    where = f"agents[{name}]"
    path = _path(data.get("path"), base_dir, f"{where}.path")
    environment = _str(data.get("environment", "development"), f"{where}.environment", max_len=64)
    risk_raw = str(data.get("risk", "auto")).lower()
    if risk_raw == "auto":
        risk: RiskTier | None = None
    else:
        try:
            risk = RiskTier(risk_raw)
        except ValueError:
            raise ConfigError(f"{where}.risk: expected auto, critical, high, medium or low") from None
    interval = _interval(data["interval"], f"{where}.interval") if "interval" in data else None
    baseline = _path(data["baseline"], base_dir, f"{where}.baseline") if "baseline" in data else None
    attestation = None
    if "attestation" in data:
        att = _expect_mapping(data["attestation"], f"{where}.attestation")
        _reject_unknown(att, {"bundle", "policy"}, f"{where}.attestation")
        attestation = AttestationConfig(
            bundle=_path(att.get("bundle"), base_dir, f"{where}.attestation.bundle"),
            policy=_path(att.get("policy"), base_dir, f"{where}.attestation.policy"),
        )
    collectors = None
    if "collectors" in data:
        cl = data["collectors"]
        if not isinstance(cl, list) or not cl or len(cl) > 100:
            raise ConfigError(f"{where}.collectors: expected a non-empty list of collector names")
        names = tuple(_str(c, f"{where}.collectors", max_len=128) for c in cl)
        if not all(_COLLECTOR_RE.match(c) for c in names):
            raise ConfigError(f"{where}.collectors: invalid collector name")
        available = available_collectors()
        unknown = sorted(set(names) - available)
        if unknown:
            # A misspelt name would otherwise run zero collectors and every cycle would look healthy.
            raise ConfigError(
                f"{where}.collectors: unknown or unavailable collector(s): {', '.join(unknown)} "
                f"(available: {', '.join(sorted(available)) or 'none'})"
            )
        collectors = names
    agent_name = None
    if "agent_name" in data:
        agent_name = _str(data["agent_name"], f"{where}.agent_name", max_len=128)
    enabled = _bool(data.get("enabled", True), f"{where}.enabled")
    return Target(
        name=name,
        path=path,
        environment=environment,
        risk=risk,
        interval=interval,
        baseline=baseline,
        attestation=attestation,
        collectors=collectors,
        agent_name=agent_name,
        enabled=enabled,
    )


_TOP_KEYS = {
    "state_dir",
    "cadence",
    "deescalate_after",
    "fail_on",
    "advisories",
    "offline",
    "update_policy",
    "notify",
    "agents",
    "concurrency",
    "agent_budget",
    "lock_timeout",
    "lock_stale_after",
    "max_sleep",
}


def config_from_mapping(data: Any, *, base_dir: Path, config_path: Path | None = None) -> MonitorConfig:
    """Validate an already-parsed configuration mapping. Relative paths resolve against ``base_dir``."""
    top = _expect_mapping(data, "config")
    _reject_unknown(top, _TOP_KEYS, "config")
    agents_raw = top.get("agents")
    if not isinstance(agents_raw, list) or not agents_raw:
        raise ConfigError("agents: expected a non-empty list")
    if len(agents_raw) > MAX_AGENTS:
        raise ConfigError(f"agents: at most {MAX_AGENTS} agents per configuration")
    agents = tuple(_target(raw, i, base_dir) for i, raw in enumerate(agents_raw))
    seen: set[str] = set()
    for t in agents:
        key = t.name.lower()
        if key in seen:
            raise ConfigError(f"agents: duplicate agent name {t.name!r}")
        seen.add(key)
    kwargs: dict[str, Any] = {}
    if "deescalate_after" in top:
        kwargs["deescalate_after"] = _int(
            top["deescalate_after"], "deescalate_after", minimum=1, maximum=1000
        )
    if "fail_on" in top:
        kwargs["fail_on"] = _severity(top["fail_on"], "fail_on")
    if "advisories" in top:
        kwargs["advisories"] = _bool(top["advisories"], "advisories")
    if "offline" in top:
        kwargs["offline"] = _bool(top["offline"], "offline")
    if "concurrency" in top:
        kwargs["concurrency"] = _int(top["concurrency"], "concurrency", minimum=1, maximum=64)
    for key in ("agent_budget", "lock_timeout", "lock_stale_after", "max_sleep"):
        if key in top:
            kwargs[key] = _duration(top[key], key)
    return MonitorConfig(
        config_path=config_path,
        state_dir=_path(top.get("state_dir", ".symbiote/monitor"), base_dir, "state_dir"),
        agents=agents,
        cadence=_cadence(top.get("cadence")),
        update_policy=_update_policy(top.get("update_policy")),
        notify=_notify(top.get("notify")),
        **kwargs,
    )


def load_config(path: Path) -> MonitorConfig:
    """Read, parse (``yaml.safe_load``, 1 MiB cap) and validate ``path``."""
    path = Path(path)
    try:
        with path.open("rb") as fh:
            raw = fh.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        raise ConfigError(f"{path}: not found (create one with `symbiote monitor init`)") from None
    except OSError as exc:
        raise ConfigError(f"{path}: {exc.strerror or exc}") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(f"{path}: larger than {MAX_CONFIG_BYTES} bytes")
    try:
        data = yaml.safe_load(raw.decode("utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: not valid YAML: {str(exc)[:300]}") from None
    base_dir = path.resolve().parent
    return config_from_mapping(data, base_dir=base_dir, config_path=path.resolve())
