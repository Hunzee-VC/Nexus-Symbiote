"""The dependency intelligence engine (``spec/monitoring.md`` §3).

:func:`check_dependencies` turns each :class:`DependencyRef` into :class:`DependencyIntel`: the current, latest
and recommended releases, the advisories that apply, and the supply-chain signals — ``vulnerable``,
``malicious``, ``newer-version``, ``fresh-release``, ``provenance-downgrade``, ``install-script-added``,
``publisher-changed``, ``deprecated``, ``yanked``, ``floating`` and ``retiring-model``.

Rules that keep the answer honest:

* a lookup that fails is recorded in ``errors`` and lowers ``coverage`` (``partial`` when one source answered,
  ``unreachable`` when none did, ``not-attempted`` when no advisor exists or the name was refused); it never
  produces an empty, clean result;
* ``recommended`` is the newest release that passes the :class:`UpdatePolicy` — outside the cooldown (the
  security cooldown when the current version has advisories), within the current major unless ``allow_major``,
  not yanked or deprecated, no provenance downgrade, no newly added install script, and confirmed free of OSV
  advisories. If OSV cannot confirm a candidate, nothing is recommended; under ``require_provenance_continuity``
  a candidate whose provenance is unknown (the provenance source was unreachable) is not recommended either;
* ``fresh-release`` is raised for the newest release inside the cooldown *and* for the release in use when it is
  itself inside the cooldown (``high`` for a floating reference, which adopts it automatically);
* history signals (provenance, install scripts, publisher) compare a release with the releases published
  before it, so a malicious release published *after* a good one (the ``cline@2.3.0`` pattern) is caught even
  though a later release restores provenance.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Literal

from symbiote.advisories.http import HttpClient, HttpError, NotFound
from symbiote.advisories.inventory import parse_purl
from symbiote.advisories.mcp_registry import lookup_server
from symbiote.advisories.npm import (
    InvalidPackageName,
    fetch_npm,
    npm_package_url,
    semver_key,
    semver_major,
    semver_prerelease,
    validate_version,
)
from symbiote.advisories.osv import OSV_QUERY, OsvResult, query_osv
from symbiote.advisories.pypi import (
    PYPI,
    fetch_pypi,
    normalize_pypi_name,
    pep440_key,
    pep440_major,
    pep440_prerelease,
)
from symbiote.advisories.retirements import find_retirement, retirements_version
from symbiote.advisories.types import (
    Advisory,
    DependencyIntel,
    DependencyKind,
    DependencyRef,
    ReleaseInfo,
    Signal,
    SignalKind,
)
from symbiote.update.types import UpdatePolicy

__all__ = ["MAX_CANDIDATE_LOOKUPS", "check_dependencies", "check_dependency"]

#: OSV lookups spent per dependency on confirming update candidates (newest first).
MAX_CANDIDATE_LOOKUPS: Final = 5
#: Releases newer than the current one whose history signals are reported.
MAX_ANALYSED_RELEASES: Final = 20
#: How many distinct earlier publishing accounts form the "usual publishers" window.
PUBLISHER_WINDOW: Final = 5

SignalSeverity = Literal["critical", "high", "medium", "low", "info"]
_ADVISORY_SEVERITY: Final[dict[str, SignalSeverity]] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "unknown": "high",  # an advisory whose severity is not stated is treated as serious
}
_PACKAGE_ECOSYSTEMS: Final = frozenset({"npm", "pypi"})
_OSV_ECOSYSTEM: Final[dict[str, Literal["npm", "PyPI"]]] = {"npm": "npm", "pypi": "PyPI"}


# --------------------------------------------------------------------------------------------- registry view


@dataclass(slots=True)
class _Registry:
    """An ecosystem-neutral view of one package's registry metadata."""

    ecosystem: str
    name: str
    source: str
    releases: list[ReleaseInfo]
    latest: str | None
    key: Callable[[str], Any]
    major: Callable[[str], int | None]
    prerelease: Callable[[str], bool]
    removed: frozenset[str] = frozenset()
    yank_reasons: dict[str, str] = field(default_factory=dict)
    status: str | None = None
    status_reason: str | None = None
    #: False when the provenance source could not be read (PyPI Simple API down): ``None`` then means unknown.
    provenance_checked: bool = True
    #: version -> files without provenance, for releases that mix attested and unattested files (PyPI).
    unattested_files: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def find(self, version: str) -> ReleaseInfo | None:
        k = self.key(version)
        for r in self.releases:
            if r.version == version or (k is not None and self.key(r.version) == k):
                return r
        return None

    def newest_stable(self) -> ReleaseInfo | None:
        stable = [
            r for r in self.releases if self.key(r.version) is not None and not self.prerelease(r.version)
        ]
        return max(stable, key=lambda r: self.key(r.version)) if stable else None


def _registry_url(ref: DependencyRef) -> str:
    if ref.ecosystem == "npm":
        return npm_package_url(ref.name)
    return f"{PYPI}/pypi/{normalize_pypi_name(ref.name)}/json"


def _fetch_registry(client: HttpClient, ref: DependencyRef) -> tuple[_Registry, list[str]]:
    if ref.ecosystem == "npm":
        npm = fetch_npm(client, ref.name)
        return (
            _Registry(
                ecosystem="npm",
                name=npm.name,
                source=npm.source,
                releases=npm.releases,
                latest=npm.latest,
                key=semver_key,
                major=semver_major,
                prerelease=semver_prerelease,
                removed=npm.removed_versions,
                status="unpublished" if npm.unpublished else None,
            ),
            [],
        )
    project, errors = fetch_pypi(client, ref.name)
    return (
        _Registry(
            ecosystem="pypi",
            name=project.name,
            source=project.source,
            releases=project.releases,
            latest=project.latest,
            key=pep440_key,
            major=pep440_major,
            prerelease=pep440_prerelease,
            yank_reasons=project.yank_reasons,
            status=project.status,
            status_reason=project.status_reason,
            provenance_checked=project.provenance_checked,
            unattested_files=project.unattested_files,
        ),
        errors,
    )


# --------------------------------------------------------------------------------------------- helpers


def _err(exc: BaseException) -> str:
    url = getattr(exc, "url", None)
    return f"{type(exc).__name__}: {exc}" + (f" ({url})" if url else "")


def _age(release: ReleaseInfo, now: datetime) -> timedelta | None:
    return None if release.published_at is None else now - release.published_at


def _fmt_age(delta: timedelta) -> str:
    hours = max(0, int(delta.total_seconds() // 3600))
    return f"{hours} hours" if hours < 48 else f"{hours // 24} days"


class _Osv:
    """Per-dependency OSV lookups, memoised by version."""

    def __init__(self, client: HttpClient, ref: DependencyRef, intel: DependencyIntel) -> None:
        self.client = client
        self.ref = ref
        self.intel = intel
        self.results: dict[str, OsvResult | HttpError | InvalidPackageName] = {}

    def query(self, version: str) -> OsvResult | None:
        if version not in self.results:
            try:
                self.results[version] = query_osv(
                    self.client,
                    ecosystem=_OSV_ECOSYSTEM[self.ref.ecosystem],
                    name=self.ref.name,
                    version=version,
                )
                self.intel.sources.append(
                    f"{OSV_QUERY} ({_OSV_ECOSYSTEM[self.ref.ecosystem]}:{self.ref.name}@{version})"
                )
            except (HttpError, InvalidPackageName) as exc:
                self.results[version] = exc
                self.intel.errors.append(f"OSV lookup for {version} failed: {_err(exc)}")
        result = self.results[version]
        return result if isinstance(result, OsvResult) else None


class _History:
    """Publish-time ordering of a package's releases, for "compared with what came before" signals."""

    def __init__(self, reg: _Registry) -> None:
        self.reg = reg
        self.timeline = sorted(
            (r for r in reg.releases if r.published_at is not None),
            key=lambda r: (r.published_at, r.version),
        )

    def before(self, release: ReleaseInfo) -> list[ReleaseInfo]:
        """Releases published before ``release``, oldest first (version order when times are missing)."""
        if release.published_at is not None:
            at = release.published_at
            return [r for r in self.timeline if r.published_at is not None and r.published_at < at]
        k = self.reg.key(release.version)
        if k is None:
            return []
        keyed = [r for r in self.reg.releases if (rk := self.reg.key(r.version)) is not None and rk < k]
        return sorted(keyed, key=lambda r: self.reg.key(r.version))

    def last_known(self, release: ReleaseInfo, attr: str) -> ReleaseInfo | None:
        for prev in reversed(self.before(release)):
            if getattr(prev, attr) is not None:
                return prev
        return None

    def usual_publishers(self, release: ReleaseInfo) -> list[str]:
        """The last :data:`PUBLISHER_WINDOW` *distinct* accounts that published before ``release``.

        Counting accounts (not releases) keeps a returning maintainer from being reported as a new publisher
        after a run of releases by a co-maintainer.
        """
        out: list[str] = []
        for prev in reversed(self.before(release)):
            if prev.publisher and prev.publisher not in out:
                out.append(prev.publisher)
            if len(out) >= PUBLISHER_WINDOW:
                break
        return out


def _attested(reg: _Registry, release: ReleaseInfo) -> bool:
    """The release carried build provenance, on all its files or (a mixed PyPI release) on some of them."""
    return bool(release.has_provenance) or release.version in reg.unattested_files


def _history_signals(reg: _Registry, hist: _History, release: ReleaseInfo, *, role: str) -> list[Signal]:
    out: list[Signal] = []
    mixed = reg.unattested_files.get(release.version)
    if release.has_provenance is False and mixed:
        out.append(
            Signal(
                SignalKind.PROVENANCE_DOWNGRADE,
                "high",
                f"{role} {reg.name}@{release.version} mixes attested and unattested files; "
                f"{', '.join(mixed)} carry no build provenance and an installer may choose them "
                "(a file added to an attested release with a stolen upload token looks like this)",
                reference=release.version,
            )
        )
    elif release.has_provenance is False:
        prev = hist.last_known(release, "has_provenance")
        if prev is not None and _attested(reg, prev):
            out.append(
                Signal(
                    SignalKind.PROVENANCE_DOWNGRADE,
                    "high",
                    f"{role} {reg.name}@{release.version} has no build provenance, but the release before it "
                    f"({prev.version}) did: it may not have been built by the project's trusted pipeline",
                    reference=release.version,
                )
            )
    if release.has_install_script:
        prev = hist.last_known(release, "has_install_script")
        if prev is not None and prev.has_install_script is False:
            out.append(
                Signal(
                    SignalKind.INSTALL_SCRIPT_ADDED,
                    "high",
                    f"{role} {reg.name}@{release.version} runs an install (lifecycle) script; "
                    f"{prev.version} did not",
                    reference=release.version,
                )
            )
    if release.publisher:
        recent = hist.usual_publishers(release)
        if recent and release.publisher not in recent:
            usual = ", ".join(sorted(recent))
            out.append(
                Signal(
                    SignalKind.PUBLISHER_CHANGED,
                    "high" if release.has_provenance is False else "medium",
                    f"{role} {reg.name}@{release.version} was published by {release.publisher!r}, not by the "
                    f"account(s) that published its earlier releases ({usual})",
                    reference=release.version,
                )
            )
    return out


def _advisory_signals(advisories: Sequence[Advisory], version: str, *, floating: bool) -> list[Signal]:
    what = f"{version} (the version the floating reference resolves to today)" if floating else version
    out: list[Signal] = []
    for adv in advisories:
        if adv.malicious:
            out.append(
                Signal(
                    SignalKind.MALICIOUS,
                    "critical",
                    f"{what} is a known malicious release ({adv.id}): {adv.summary}",
                    reference=adv.id,
                )
            )
        else:
            fixed = f"; fixed in {', '.join(adv.fixed_in)}" if adv.fixed_in else "; no fixed version listed"
            out.append(
                Signal(
                    SignalKind.VULNERABLE,
                    _ADVISORY_SEVERITY[adv.severity],
                    f"{what} is affected by {adv.id} (severity {adv.severity}): {adv.summary}{fixed}",
                    reference=adv.id,
                )
            )
    return out


# --------------------------------------------------------------------------------------------- packages


def _check_package(
    ref: DependencyRef, client: HttpClient, now: datetime, policy: UpdatePolicy, intel: DependencyIntel
) -> None:
    try:
        url = _registry_url(ref)
        if ref.version is not None:
            validate_version(ref.version)
    except InvalidPackageName as exc:
        intel.coverage = "not-attempted"
        intel.errors.append(f"refused to query: {exc}")
        return

    reg: _Registry | None = None
    registry_ok = False
    try:
        reg, extra = _fetch_registry(client, ref)
        registry_ok = True
        intel.sources.append(reg.source)
        intel.errors.extend(extra)
    except NotFound:
        registry_ok = True
        intel.sources.append(url)
        intel.signals.append(
            Signal(
                SignalKind.YANKED,
                "high",
                f"{ref.name} is not in the {ref.ecosystem} registry (removed, unpublished or never published)",
                reference=ref.version,
            )
        )
    except HttpError as exc:
        intel.errors.append(f"registry lookup failed: {_err(exc)}")

    if reg is not None:
        intel.releases = sorted(
            reg.releases, key=lambda r: (reg.key(r.version) is None, reg.key(r.version) or (), r.version)
        )
        latest = reg.find(reg.latest) if reg.latest else None
        intel.latest = latest or reg.newest_stable()
        if ref.version is not None:
            intel.current = reg.find(ref.version)
            if intel.current is None:
                why = (
                    "was unpublished"
                    if ref.version in reg.removed or reg.status == "unpublished"
                    else "is not listed by the registry"
                )
                intel.signals.append(
                    Signal(
                        SignalKind.YANKED,
                        "high",
                        f"the pinned version {ref.name}@{ref.version} {why}",
                        reference=ref.version,
                    )
                )
        _status_signals(reg, intel)

    # Advisories for the version in use (for a floating reference: the version it resolves to today).
    osv = _Osv(client, ref, intel)
    effective = ref.version or (intel.latest.version if intel.latest else None)
    osv_ok = False
    if effective is not None:
        result = osv.query(effective)
        if result is not None:
            osv_ok = True
            intel.advisories = list(result.advisories)
            if result.truncated:
                intel.errors.append(f"OSV results for {effective} truncated after {result.pages} pages")
            intel.signals.extend(
                _advisory_signals(result.advisories, effective, floating=ref.version is None)
            )
    else:
        intel.errors.append("no version to query OSV with (floating reference and no registry answer)")

    if ref.version is None:
        resolved = f" (today: {intel.latest.version})" if intel.latest else ""
        intel.signals.append(
            Signal(
                SignalKind.FLOATING,
                "medium",
                f"{ref.name} is not pinned: it resolves to whatever is newest at every start{resolved}",
            )
        )

    if reg is not None:
        _release_signals(ref, reg, intel, now, policy)
        _recommend(ref, reg, intel, osv=osv, now=now, policy=policy)

    if ref.kind is DependencyKind.MCP_SERVER_PACKAGE:
        registry_ok_mcp = _mcp_registry(ref, client, intel)
    else:
        registry_ok_mcp = True

    if registry_ok and osv_ok:
        intel.coverage = "queried" if registry_ok_mcp and not intel.errors else "partial"
    elif registry_ok or osv_ok:
        intel.coverage = "partial"
    else:
        intel.coverage = "unreachable"


def _status_signals(reg: _Registry, intel: DependencyIntel) -> None:
    current = intel.current
    if current is not None and current.deprecated:
        intel.signals.append(
            Signal(
                SignalKind.DEPRECATED,
                "medium",
                f"{reg.name}@{current.version} is deprecated: {current.deprecated}",
                reference=current.version,
            )
        )
    if current is not None and current.yanked:
        reason = reg.yank_reasons.get(current.version)
        intel.signals.append(
            Signal(
                SignalKind.YANKED,
                "high",
                f"{reg.name}@{current.version} was yanked" + (f": {reason}" if reason else ""),
                reference=current.version,
            )
        )
    if reg.status == "quarantined":
        intel.signals.append(
            Signal(
                SignalKind.MALICIOUS,
                "critical",
                f"the registry has quarantined {reg.name} (suspected malicious; not installable)"
                + (f": {reg.status_reason}" if reg.status_reason else ""),
            )
        )
    elif reg.status in ("deprecated", "archived"):
        intel.signals.append(
            Signal(
                SignalKind.DEPRECATED,
                "medium" if reg.status == "deprecated" else "low",
                f"the registry marks {reg.name} as {reg.status}"
                + (f": {reg.status_reason}" if reg.status_reason else ""),
            )
        )


def _release_signals(
    ref: DependencyRef, reg: _Registry, intel: DependencyIntel, now: datetime, policy: UpdatePolicy
) -> None:
    hist = _History(reg)
    seen: set[tuple[SignalKind, str | None]] = set()

    def add(signals: list[Signal]) -> None:
        for s in signals:
            if (s.kind, s.reference) not in seen:
                seen.add((s.kind, s.reference))
                intel.signals.append(s)

    in_use = intel.current if ref.version is not None else intel.latest
    if in_use is not None:
        role = (
            "the version in use,"
            if ref.version is not None
            else "the version the floating reference resolves to,"
        )
        add(_history_signals(reg, hist, in_use, role=role))
    base = reg.key(in_use.version) if in_use is not None else None
    newer = [
        r
        for r in intel.releases
        if (k := reg.key(r.version)) is not None and (base is None or k > base) and r is not in_use
    ]
    for release in newer[-MAX_ANALYSED_RELEASES:]:
        add(_history_signals(reg, hist, release, role="newer release"))

    cooldown = timedelta(days=policy.cooldown_days)
    # The release in use can itself be fresh: a floating reference runs whatever was published minutes ago (the
    # worm window the cooldown exists for), and a pin may have been bumped to a release nobody has vetted yet.
    in_use_age = _age(in_use, now) if in_use is not None else None
    if in_use is not None and in_use_age is not None and in_use_age < cooldown:
        floating = ref.version is None
        add(
            [
                Signal(
                    SignalKind.FRESH_RELEASE,
                    "high" if floating else "medium",
                    f"{reg.name}@{in_use.version}, "
                    + ("which the floating reference runs today," if floating else "the version in use,")
                    + f" was published {_fmt_age(in_use_age)} ago, inside the {policy.cooldown_days}-day "
                    "cooldown: "
                    + (
                        "it is adopted automatically at every start; pin a release outside the cooldown"
                        if floating
                        else "it has not had time to be vetted by the ecosystem"
                    ),
                    reference=in_use.version,
                )
            ]
        )
    fresh = [
        r
        for r in newer
        if not reg.prerelease(r.version) and (age := _age(r, now)) is not None and age < cooldown
    ]
    if fresh:
        newest = fresh[-1]
        age = _age(newest, now)
        assert age is not None
        add(
            [
                Signal(
                    SignalKind.FRESH_RELEASE,
                    "low",
                    f"{reg.name}@{newest.version} was published {_fmt_age(age)} ago, inside the "
                    f"{policy.cooldown_days}-day cooldown: do not adopt it yet",
                    reference=newest.version,
                )
            ]
        )


def _rejection(
    cand: ReleaseInfo,
    *,
    reg: _Registry,
    hist: _History,
    current: ReleaseInfo | None,
    base_major: int | None,
    cooldown: timedelta,
    now: datetime,
    policy: UpdatePolicy,
) -> str | None:
    if cand.yanked:
        return "yanked"
    if cand.deprecated:
        return "deprecated"
    age = _age(cand, now)
    if age is None:
        return "publish time unknown"
    if age < cooldown:
        return "inside the cooldown"
    if not policy.allow_major and base_major is not None and reg.major(cand.version) != base_major:
        return "different major version"
    if policy.require_provenance_continuity and cand.has_provenance is not True:
        if not reg.provenance_checked:
            # Unknown is not clean: without the provenance source, continuity cannot be confirmed.
            return "provenance unknown"
        prev = hist.last_known(cand, "has_provenance")
        if (current is not None and _attested(reg, current)) or (prev is not None and _attested(reg, prev)):
            return "provenance downgrade" if cand.has_provenance is False else "provenance unknown"
    if policy.block_new_install_scripts and cand.has_install_script:
        baseline = current if current is not None else hist.last_known(cand, "has_install_script")
        if baseline is not None and baseline.has_install_script is False:
            return "adds an install script"
    return None


def _recommend(
    ref: DependencyRef,
    reg: _Registry,
    intel: DependencyIntel,
    *,
    osv: _Osv,
    now: datetime,
    policy: UpdatePolicy,
) -> None:
    hist = _History(reg)
    current = intel.current
    base_version = ref.version
    base_key = reg.key(base_version) if base_version is not None else None
    major_from = base_version or (intel.latest.version if intel.latest else None)
    base_major = reg.major(major_from) if major_from is not None else None
    allow_pre = base_version is not None and reg.prerelease(base_version)
    security = bool(intel.advisories) or any(
        s.kind in (SignalKind.MALICIOUS, SignalKind.VULNERABLE) for s in intel.signals
    )
    cooldown = timedelta(days=policy.security_cooldown_days if security else policy.cooldown_days)
    candidates = [
        r
        for r in intel.releases
        if (k := reg.key(r.version)) is not None
        and (base_key is None or k > base_key)
        and (allow_pre or not reg.prerelease(r.version))
    ]
    lookups = 0
    unknown_provenance: list[str] = []
    for cand in reversed(candidates):
        why = _rejection(
            cand,
            reg=reg,
            hist=hist,
            current=current,
            base_major=base_major,
            cooldown=cooldown,
            now=now,
            policy=policy,
        )
        if why == "provenance unknown":
            unknown_provenance.append(cand.version)
        if why is not None:
            continue
        if lookups >= MAX_CANDIDATE_LOOKUPS:
            intel.errors.append(
                f"stopped after {MAX_CANDIDATE_LOOKUPS} advisory lookups without finding a clean candidate"
            )
            return
        lookups += 1
        result = osv.query(cand.version)
        if result is None:
            intel.errors.append(f"cannot recommend {cand.version}: its advisories could not be checked")
            return
        if result.advisories:
            continue
        intel.recommended = cand
        break
    rec = intel.recommended
    skipped = [v for v in unknown_provenance if rec is None or reg.key(v) > reg.key(rec.version)]
    if skipped:
        intel.errors.append(
            f"provenance unknown for {', '.join(skipped[:5])}: continuity cannot be confirmed, so "
            + ("they were not recommended" if len(skipped) > 1 else "it was not recommended")
        )
    if rec is not None and base_key is not None:
        intel.signals.append(
            Signal(
                SignalKind.NEWER_VERSION,
                "info",
                f"{reg.name} {ref.version} -> {rec.version} passes the update policy"
                + (" (security cooldown applied)" if security else ""),
                reference=rec.version,
            )
        )


def _mcp_registry(ref: DependencyRef, client: HttpClient, intel: DependencyIntel) -> bool:
    """Add MCP Registry status for a server package; return False when the registry could not be read."""
    ecosystem: str = ref.ecosystem
    identifier = ref.name
    if ref.ecosystem == "mcp-registry" and ref.purl:
        p = parse_purl(ref.purl)
        if p is None:
            return True
        ecosystem = p.type
    try:
        entry = lookup_server(client, ecosystem=ecosystem, identifier=identifier)
    except HttpError as exc:
        intel.errors.append(f"MCP Registry lookup failed: {_err(exc)}")
        return False
    if entry is None:
        return True
    intel.sources.append(entry.source)
    if entry.truncated:
        intel.errors.append(
            f"MCP Registry search truncated: other entries for {identifier} may exist on later pages"
        )
    if entry.status in ("deprecated", "deleted"):
        intel.signals.append(
            Signal(
                SignalKind.DEPRECATED,
                "high" if entry.status == "deleted" else "medium",
                f"the MCP Registry lists server {entry.server_name} as {entry.status}",
                reference=entry.server_name,
            )
        )
    if ref.ecosystem == "mcp-registry":
        intel.releases = list(entry.versions)
        if entry.latest_version:
            intel.latest = ReleaseInfo(version=entry.latest_version, published_at=entry.published_at)
        if ref.version is not None:
            intel.current = next((r for r in entry.versions if r.version == ref.version), None)
    return True


# --------------------------------------------------------------------------------------------- other kinds


def _check_hosted_model(ref: DependencyRef, now: datetime, intel: DependencyIntel) -> None:
    provider: str | None = None
    if ref.purl:
        p = parse_purl(ref.purl)
        quals = p.qualifiers if p is not None and isinstance(p.qualifiers, dict) else {}
        provider = quals.get("provider")
    intel.coverage = "queried"
    intel.sources.append(f"symbiote retirements table {retirements_version()}")
    if ref.version is None:
        intel.signals.append(
            Signal(
                SignalKind.FLOATING,
                "low",
                f"{ref.name} is an alias: the provider may move it to a different model snapshot at any time",
            )
        )
    entry = find_retirement(ref.name, provider=provider)
    if entry is None:
        return
    intel.sources.append(entry.source)
    successor = (
        f"; documented successor: {entry.successor}" if entry.successor else "; no successor documented"
    )
    confidence = f" (source confidence: {entry.confidence})"
    days = entry.days_left(now)
    severity: SignalSeverity
    if entry.retires_on is None:
        when = (
            f"was deprecated on {entry.deprecated_on.isoformat()}" if entry.deprecated_on else "is deprecated"
        )
        severity = "medium"
    elif days is not None and days <= 0:
        when = f"was retired on {entry.retires_on.isoformat()}: requests to it fail"
        severity = "critical"
    else:
        when = f"retires on {entry.retires_on.isoformat()} ({days} days)"
        severity = (
            "high"
            if days is not None and days <= 30
            else "medium"
            if days is not None and days <= 90
            else "low"
        )
    intel.current = ReleaseInfo(version=ref.version or ref.name, deprecated=f"{ref.name} {when}")
    intel.signals.append(
        Signal(
            SignalKind.RETIRING_MODEL,
            severity,
            f"{ref.name} {when}{successor}{confidence}",
            reference=ref.name,
        )
    )
    if entry.successor:
        intel.recommended = ReleaseInfo(version=entry.successor)


def _not_attempted(ref: DependencyRef, intel: DependencyIntel, why: str) -> None:
    intel.coverage = "not-attempted"
    intel.errors.append(why)
    if ref.version is None and ref.ecosystem in ("oci", "huggingface"):
        intel.signals.append(
            Signal(
                SignalKind.FLOATING,
                "medium",
                f"{ref.name} is not pinned to a digest or revision: it resolves to whatever is current at every start",
            )
        )
    elif ref.version is None and ref.ecosystem == "mcp-registry" and _is_unresolved_package(ref):
        intel.signals.append(
            Signal(
                SignalKind.FLOATING,
                "high",
                f"{ref.name} launches a package from a git, tarball or other non-registry source without a pinned "
                "digest: it runs whatever that source serves at every start, and no advisory covers it",
            )
        )


def _is_unresolved_package(ref: DependencyRef) -> bool:
    """A launcher package recorded without a package URL (see :mod:`symbiote.advisories.inventory`)."""
    return (
        ref.ecosystem == "mcp-registry"
        and not ref.purl
        and ref.kind is not DependencyKind.MCP_SERVER_REMOTE
        and "://" not in ref.name
    )


def check_dependency(
    ref: DependencyRef, *, client: HttpClient, now: datetime, policy: UpdatePolicy | None = None
) -> DependencyIntel:
    """Intelligence for one dependency (see :func:`check_dependencies`)."""
    policy = policy or UpdatePolicy()
    now = now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)
    intel = DependencyIntel(ref=ref, checked_at=now, coverage="not-attempted")
    if ref.ecosystem in _PACKAGE_ECOSYSTEMS:
        _check_package(ref, client, now, policy, intel)
    elif ref.ecosystem == "hosted-model":
        _check_hosted_model(ref, now, intel)
    elif ref.ecosystem == "mcp-registry" and ref.purl:
        ok = _mcp_registry(ref, client, intel)
        intel.errors.append(f"no vulnerability advisor for {ref.purl.split('/', 1)[0]} packages")
        if ref.version is None:
            intel.signals.append(
                Signal(SignalKind.FLOATING, "medium", f"{ref.name} is not pinned to an exact version")
            )
        intel.coverage = "partial" if ok else "unreachable"
    elif _is_unresolved_package(ref):
        _not_attempted(
            ref,
            intel,
            "the launcher package has no package URL (git, tarball or other non-registry source): no registry or "
            "advisory database can be consulted for it",
        )
    elif ref.ecosystem == "mcp-registry":
        _not_attempted(
            ref,
            intel,
            "no advisor for remote MCP endpoints; served tool definitions are compared by the monitor's drift step",
        )
    elif ref.ecosystem == "oci":
        _not_attempted(
            ref, intel, "no advisor for OCI images yet (registry digests and advisories not queried)"
        )
    elif ref.ecosystem == "huggingface":
        _not_attempted(ref, intel, "no advisor for Hugging Face repositories yet")
    elif ref.ecosystem == "a2a":
        _not_attempted(
            ref, intel, "A2A peer cards are compared by the monitor's drift step, not by an advisor"
        )
    else:
        _not_attempted(
            ref, intel, "skills are compared by digest in the monitor's drift step, not by an advisor"
        )
    intel.sources = list(dict.fromkeys(intel.sources))
    return intel


def check_dependencies(
    refs: Sequence[DependencyRef],
    *,
    client: HttpClient,
    now: datetime,
    policy: UpdatePolicy | None = None,
) -> list[DependencyIntel]:
    """Check every dependency, in input order. Network failures are recorded per dependency, never raised."""
    out: list[DependencyIntel] = []
    for ref in refs:
        try:
            out.append(check_dependency(ref, client=client, now=now, policy=policy))
        except Exception as exc:  # one dependency's failure must not cost the others their result
            # A defect or a response shape no parser anticipated: report it, never as a clean result.
            intel = DependencyIntel(ref=ref, checked_at=now, coverage="unreachable")
            intel.errors.append(f"internal error while checking: {type(exc).__name__}: {exc}")
            out.append(intel)
    return out
