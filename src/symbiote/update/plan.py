"""Update planner: from dependency intelligence to at most one proposal per dependency (``spec/monitoring.md`` §4).

The planner is pure: it reads :class:`~symbiote.advisories.types.DependencyIntel` (already fetched, already
untrusted-data-checked by the advisors) and an :class:`~symbiote.update.types.UpdatePolicy`, and returns
:class:`~symbiote.update.types.UpdateProposal` objects without touching the network or the filesystem. "Now" is
each intel record's ``checked_at``, so planning is deterministic.

Decision order for one dependency (the first that applies wins):

1. ``security`` — the current version is vulnerable or malicious: the engine's ``recommended`` release (the
   release the advisors confirmed free of advisories and inside the policy, security cooldown applied);
   otherwise ``replace`` (remove or replace the server), naming the advisories' fixed versions as a hint only.
2. ``retire-model`` — a hosted model with an announced retirement: its documented successor, as advice.
3. ``pin`` — a floating reference: pin to the recommended version (or OCI digest).
4. ``version`` — the recommended release, re-checked against the policy (cooldown, provenance continuity, no
   new install script, same major unless ``allow_major``).
5. ``replace`` — the dependency is deprecated or its pinned version yanked and nothing else applies.

Only ``intel.recommended`` is ever proposed as an editable version: the advisors set it only after OSV
confirmed the exact release free of advisories, and leave it ``None`` when that could not be confirmed. The
planner re-checks it against the policy (defence in depth) but never substitutes a release of its own choosing,
because it cannot know whether such a release is itself vulnerable.

A lookup that failed (``coverage`` ``unreachable``/``not-attempted``) yields no proposal: it is reported by the
caller as missing coverage, never as "up to date". The one exception is a floating OCI image or Hugging Face
reference, which the advisors flag (``floating``) without resolving: it gets non-editable ``pin`` advice.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Literal

from symbiote.advisories.types import (
    Advisory,
    DependencyIntel,
    DependencyKind,
    DependencyRef,
    ReleaseInfo,
    Signal,
    SignalKind,
)
from symbiote.update.types import UpdateKind, UpdatePolicy, UpdateProposal

__all__ = ["SEVERITY_ORDER", "Severity", "plan_updates", "version_key"]

Severity = Literal["critical", "high", "medium", "low", "info"]

#: Severity rank, highest first (index 0 is the most severe).
SEVERITY_ORDER: Final[tuple[Severity, ...]] = ("critical", "high", "medium", "low", "info")

_VERSION: Final = re.compile(r"^[vV]?(\d{1,9}(?:\.\d{1,9}){0,5})(.{0,64})$")
_PRE: Final = re.compile(r"^(?:-|\.|_)?(?P<tag>a|alpha|b|beta|c|rc|pre|preview|dev)\.?(?P<n>\d{0,9})", re.I)
_POST: Final = re.compile(r"^(?:\.|-|_)?post\.?(?P<n>\d{0,9})", re.I)
_OCI_DIGEST: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_PRE_RANK: Final[dict[str, int]] = {
    "dev": -4,
    "a": -3,
    "alpha": -3,
    "pre": -3,
    "preview": -3,
    "b": -2,
    "beta": -2,
    "c": -1,
    "rc": -1,
}
_PACKAGE_ECOSYSTEMS: Final = frozenset({"npm", "pypi", "oci"})

VersionKey = tuple[tuple[int, ...], int, int]


def version_key(version: str) -> VersionKey | None:
    """A comparable key for semver and PEP 440 style versions; ``None`` when the string is not a version.

    The key is ``(release numbers padded to 6, pre/post rank, pre/post number)``: ``1.2.3rc1 < 1.2.3 <
    1.2.3.post1``. Build metadata (``+...``) is ignored. Bounded patterns only (no backtracking blow-up).
    """
    text = version.strip().split("+", 1)[0]
    match = _VERSION.match(text)
    if not match:
        return None
    nums = tuple(int(p) for p in match.group(1).split("."))
    nums = nums + (0,) * (6 - len(nums))
    rest = match.group(2)
    if not rest:
        return nums, 0, 0
    pre = _PRE.match(rest)
    if pre:
        return nums, _PRE_RANK[pre.group("tag").lower()], int(pre.group("n") or 0)
    post = _POST.match(rest)
    if post:
        return nums, 1, int(post.group("n") or 0)
    if rest.startswith("-"):  # other semver pre-release identifiers sort before the release
        return nums, -5, 0
    return None


def _is_prerelease(version: str) -> bool:
    key = version_key(version)
    return key is not None and key[1] < 0


def _major(version: str) -> int | None:
    key = version_key(version)
    return None if key is None else key[0][0]


def _max_severity(values: Iterable[str], default: Severity) -> Severity:
    ranks = [SEVERITY_ORDER.index(v) for v in values if v in SEVERITY_ORDER]
    return SEVERITY_ORDER[min(ranks)] if ranks else default


def _raise_to(severity: Severity, floor: Severity) -> Severity:
    return severity if SEVERITY_ORDER.index(severity) <= SEVERITY_ORDER.index(floor) else floor


def _age_text(release: ReleaseInfo, now: datetime) -> str:
    if release.published_at is None:
        return "publish time unknown"
    days = (now - release.published_at).days
    return f"published {days} day{'s' if days != 1 else ''} ago"


@dataclass(frozen=True, slots=True)
class _Verdict:
    ok: bool
    reasons: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


class _Context:
    """Per-dependency facts the policy checks need."""

    def __init__(self, intel: DependencyIntel, policy: UpdatePolicy) -> None:
        self.intel = intel
        self.policy = policy
        self.now = intel.checked_at
        self.current_version = intel.ref.version or (intel.current.version if intel.current else None)
        self.current_key = version_key(self.current_version) if self.current_version else None
        self.by_version: dict[str, ReleaseInfo] = {}
        for rel in intel.releases:
            self.by_version.setdefault(rel.version, rel)
        for extra in (intel.current, intel.latest, intel.recommended):
            if extra is not None:
                self.by_version.setdefault(extra.version, extra)
        self.current_release: ReleaseInfo | None = (
            self.by_version.get(self.current_version) if self.current_version else intel.current
        )
        #: Versions a signal explicitly flags as unsafe to adopt.
        self.flagged: dict[str, list[str]] = {}
        for sig in intel.signals:
            if sig.reference and sig.kind in (
                SignalKind.FRESH_RELEASE,
                SignalKind.PROVENANCE_DOWNGRADE,
                SignalKind.INSTALL_SCRIPT_ADDED,
                SignalKind.MALICIOUS,
                SignalKind.YANKED,
            ):
                self.flagged.setdefault(sig.reference, []).append(sig.kind.value)

    def provenance_before(self, version: str) -> bool:
        key = version_key(version)
        if key is None:
            return False
        for rel in self.by_version.values():
            rkey = version_key(rel.version)
            if rkey is not None and rkey < key and rel.has_provenance is True:
                return True
        return False

    def check(self, release: ReleaseInfo, *, cooldown_days: int) -> _Verdict:
        """Does adopting ``release`` pass the policy? Unknown facts that the policy depends on fail closed."""
        reasons: list[str] = []
        notes: list[str] = []
        if release.published_at is None:
            reasons.append("publish time unknown (cooldown cannot be verified)")
        elif self.now - release.published_at < timedelta(days=cooldown_days):
            reasons.append(f"inside the {cooldown_days}-day cooldown ({_age_text(release, self.now)})")
        if release.yanked:
            reasons.append("yanked")
        if release.deprecated:
            reasons.append("deprecated")
        if (
            self.policy.require_provenance_continuity
            and release.has_provenance is not True
            and self.provenance_before(release.version)
        ):
            reasons.append("no build provenance although earlier releases had it")
        if self.policy.block_new_install_scripts and release.has_install_script is True:
            had = self.current_release.has_install_script if self.current_release else None
            if had is not True:
                reasons.append("adds an install (lifecycle) script")
        for kind in self.flagged.get(release.version, []):
            reasons.append(f"flagged {kind}")
        if (
            self.current_release is not None
            and self.current_release.publisher
            and release.publisher
            and release.publisher != self.current_release.publisher
        ):
            notes.append(
                f"{release.version} was published by a different account ({release.publisher!r}, "
                f"current {self.current_release.publisher!r}): confirm the maintainer change is legitimate."
            )
        return _Verdict(not reasons, tuple(reasons), tuple(notes))

    def newer_candidates(self) -> list[ReleaseInfo]:
        """Known releases newer than the current one, oldest first (pre-releases only from a pre-release)."""
        allow_pre = bool(self.current_version and _is_prerelease(self.current_version))
        out: list[tuple[VersionKey, ReleaseInfo]] = []
        for rel in self.by_version.values():
            key = version_key(rel.version)
            if key is None or (key[1] < 0 and not allow_pre):
                continue
            if self.current_key is not None and key <= self.current_key:
                continue
            out.append((key, rel))
        out.sort(key=lambda kv: kv[0])
        return [rel for _, rel in out]


def _line(key: VersionKey) -> tuple[int, int]:
    return key[0][0], key[0][1]


def _fixes(advisory: Advisory, version: str) -> bool:
    """Heuristic: is ``version`` outside every range that ``advisory.fixed_in`` closes?

    Fixed versions often belong to several release lines (backports: ``1.4.5`` and ``1.5.2``). A version is
    treated as fixed only when it is at or above every fixed version on its own ``major.minor`` line and
    either such a fix exists on that line or it is at or above every fixed version. So ``1.5.0`` is *not* fixed
    by ``(1.4.5, 1.5.2)`` (the 1.5 line is fixed only from 1.5.2), while ``1.4.6`` and ``1.6.0`` are. Used only
    for hints and review notes: proposals rely on the advisors' exact-version confirmation.
    """
    key = version_key(version)
    if key is None:
        return False
    keyed = [k for k in (version_key(f) for f in advisory.fixed_in) if k is not None]
    if not keyed:
        return False
    same_line = [k for k in keyed if _line(k) == _line(key)]
    if same_line:
        return all(k <= key for k in same_line)
    return all(k <= key for k in keyed)


def _review_notes(ref: DependencyRef, kind: UpdateKind) -> list[str]:
    notes: list[str] = []
    if ref.kind in (DependencyKind.MCP_SERVER_PACKAGE, DependencyKind.MCP_SERVER_REMOTE):
        if kind == "replace":
            notes.append(
                "Remove the server or replace it with a trusted alternative; revoke credentials it was given."
            )
        else:
            notes.append(
                "After upgrading, re-capture the served tool definitions (live `symbiote scan`), diff them "
                "against the approved snapshot and re-approve the toolset digest."
            )
            notes.append(
                "Review the server's changelog and instructions for new tools or widened permissions."
            )
    elif ref.kind is DependencyKind.A2A_PEER:
        notes.append("Re-fetch the peer's agent card, diff its skills and re-approve the card digest.")
    elif ref.kind is DependencyKind.SKILL:
        notes.append("Review the skill's files and scripts and re-approve its directory-manifest digest.")
    elif ref.kind is DependencyKind.TOOL_PLUGIN:
        notes.append("Review the plugin's new permissions and re-approve its digest.")
    elif ref.kind in (DependencyKind.HOSTED_MODEL, DependencyKind.LOCAL_MODEL):
        notes.append(
            "Re-run the agent's evaluations (task quality and prompt-injection resistance) on the new "
            "model before switching, and update the approved snapshot."
        )
    if kind == "pin":
        notes.append(
            "Pinning freezes what runs at every start; later releases arrive as `symbiote update` proposals."
        )
    return notes


def _signal_text(signals: Sequence[Signal]) -> str:
    return ", ".join(f"{s.kind.value}" + (f" ({s.reference})" if s.reference else "") for s in signals)


def _advisory_text(advisories: Sequence[Advisory]) -> str:
    parts = []
    for adv in advisories:
        tag = "malicious" if adv.malicious else adv.severity
        parts.append(f"{adv.id} ({tag})")
    return ", ".join(parts)


def _proposal(  # noqa: PLR0917 - internal constructor, every argument is required
    ctx: _Context,
    kind: UpdateKind,
    proposed: str,
    title: str,
    rationale: str,
    severity: Severity,
    extra_notes: Iterable[str] = (),
) -> UpdateProposal:
    ref = ctx.intel.ref
    notes = list(dict.fromkeys([*_review_notes(ref, kind), *extra_notes]))
    return UpdateProposal(
        kind=kind,
        dependency=ref,
        current=ctx.current_version or "(floating)",
        proposed=proposed,
        title=title,
        rationale=rationale,
        signals=list(ctx.intel.signals),
        review_notes=notes,
        severity=severity,
    )


def _confirmed(ctx: _Context, *, cooldown_days: int) -> tuple[ReleaseInfo | None, list[str]]:
    """The engine's ``recommended`` release when it is newer than the current one and passes the policy.

    ``recommended`` is the only release the advisors confirmed free of advisories for its exact version; any
    other release in ``intel.releases`` may itself be vulnerable, so it is never proposed. Returns the release
    (or ``None``) and the reasons it was refused.
    """
    rec = ctx.intel.recommended
    if rec is None:
        return None, []
    rkey = version_key(rec.version)
    if rkey is None or rec.version == ctx.current_version:
        return None, []
    if ctx.current_key is not None and rkey <= ctx.current_key:
        return None, []
    full = ctx.by_version.get(rec.version, rec)
    reasons: list[str] = []
    cur_major = _major(ctx.current_version) if ctx.current_version else None
    if not ctx.policy.allow_major and cur_major is not None and rkey[0][0] != cur_major:
        reasons.append("major-version change (allow_major is off)")
    verdict = ctx.check(full, cooldown_days=cooldown_days)
    reasons.extend(verdict.reasons)
    if reasons:
        return None, [f"{rec.version}: {'; '.join(reasons)}"]
    return full, list(verdict.notes)


def _lowest_named_fix(ctx: _Context, fixable: Sequence[Advisory]) -> str | None:
    """The lowest version newer than the current one that the advisories' ``fixed_in`` say fixes all of them."""
    if not fixable or not all(a.fixed_in for a in fixable):
        return None
    names = {f for a in fixable for f in a.fixed_in if version_key(f) is not None}
    names |= {r.version for r in ctx.newer_candidates()}
    for ver in sorted(names, key=lambda v: version_key(v) or ((), 0, 0)):
        key = version_key(ver)
        if key is None or (ctx.current_key is not None and key <= ctx.current_key):
            continue
        if all(_fixes(a, ver) for a in fixable):
            return ver
    return None


def _plan_security(ctx: _Context) -> UpdateProposal | None:
    intel = ctx.intel
    vuln_signals = [s for s in intel.signals if s.kind in (SignalKind.VULNERABLE, SignalKind.MALICIOUS)]
    advisories = list(intel.advisories)
    if not vuln_signals and not advisories:
        return None
    malicious = any(a.malicious for a in advisories) or any(
        s.kind is SignalKind.MALICIOUS for s in vuln_signals
    )
    # Advisory severity "unknown" counts as high: an unrated vulnerability is not a low one.
    rated = [("high" if a.severity == "unknown" else a.severity) for a in advisories]
    severity: Severity = (
        "critical" if malicious else _max_severity([*rated, *(s.severity for s in vuln_signals)], "high")
    )
    name = intel.ref.name
    current = ctx.current_version or "(floating)"
    cited = _advisory_text(advisories) or _signal_text(vuln_signals)
    fixable = [a for a in advisories if not a.malicious]
    hint = _lowest_named_fix(ctx, fixable)
    chosen, chosen_notes = _confirmed(ctx, cooldown_days=ctx.policy.security_cooldown_days)
    if chosen is None:
        rejected = chosen_notes
        why = f" The recommended release was refused: {'; '.join(rejected)}." if rejected else ""
        if hint is not None and not malicious:
            hint_rel = ctx.by_version.get(hint)
            facts = (
                f"{hint} ({_age_text(hint_rel, ctx.now)}) could not be confirmed free of advisories and inside "
                "the policy"
                if hint_rel is not None
                else f"no release metadata for {hint} was available (age, provenance and install scripts "
                "unknown)"
            )
            title = f"No verified fix for {name} {current}: review {hint} by hand"
            rationale = (
                f"{name} {current} is affected by {cited}. The advisories name {hint} as the lowest fixed "
                f"version, but {facts}, so no edit is proposed: an unverified release is not adopted "
                f"automatically.{why}"
            )
            extra = [
                f"Check {hint} on the registry (age, build provenance, install scripts, publisher) and query OSV "
                "for it before upgrading by hand; re-run `symbiote update` once the lookups succeed."
            ]
            return _proposal(ctx, "replace", f"(verify {hint} by hand)", title, rationale, severity, extra)
        return _proposal(
            ctx,
            "replace",
            "(remove or replace)",
            f"Remove or replace {name} {current}: {'malicious release' if malicious else 'no safe fixed version'}",
            f"{name} {current} is affected by {cited} and no release was confirmed free of advisories and "
            f"inside the update policy (security cooldown {ctx.policy.security_cooldown_days} days, provenance "
            f"continuity, no new install script).{why}",
            severity,
        )
    notes = list(chosen_notes)
    if hint is not None and hint != chosen.version:
        notes.append(
            f"The advisories name {hint} as the lowest fixed version; {chosen.version} is proposed because it is "
            "the release the advisors confirmed free of advisories."
        )
    cur_major, new_major = (
        (_major(ctx.current_version) if ctx.current_version else None),
        _major(chosen.version),
    )
    if cur_major is not None and new_major is not None and new_major != cur_major:
        notes.append(f"This is a major-version change ({cur_major} -> {new_major}): expect breaking changes.")
    if malicious:
        notes.append(
            "The running version is a known malicious release: rotate every credential the server could read "
            "and review its activity logs."
        )
    return _proposal(
        ctx,
        "security",
        chosen.version,
        f"Upgrade {name} from {current} to {chosen.version} (security)",
        f"{name} {current} is affected by {cited}. {chosen.version} was confirmed free of advisories and passes "
        f"the update policy ({_age_text(chosen, ctx.now)}; security cooldown "
        f"{ctx.policy.security_cooldown_days} days). Signals: {_signal_text(ctx.intel.signals) or 'none'}.",
        severity,
        notes,
    )


def _plan_retire(ctx: _Context) -> UpdateProposal | None:
    ref = ctx.intel.ref
    if ref.kind is not DependencyKind.HOSTED_MODEL:
        return None
    retiring = [s for s in ctx.intel.signals if s.kind is SignalKind.RETIRING_MODEL]
    if not retiring:
        return None
    # only an explicitly recommended successor counts; a signal's ``reference`` names the retiring model itself
    successor = ctx.intel.recommended.version if ctx.intel.recommended is not None else None
    if successor == ref.name:
        successor = None
    severity = _max_severity((s.severity for s in retiring), "medium")
    details = "; ".join(s.detail for s in retiring)
    if successor:
        title = f"Move {ref.name} to {successor} (announced retirement)"
        proposed = successor
    else:
        title = f"Plan a replacement for {ref.name} (announced retirement)"
        proposed = "(no documented successor)"
    return _proposal(
        ctx,
        "retire-model",
        proposed,
        title,
        f"{ref.name} has an announced retirement ({details}). "
        + (
            f"The provider documents {successor} as its successor."
            if successor
            else "No successor is documented."
        )
        + " This is advice: model changes alter agent behaviour and are never applied automatically.",
        severity,
    )


def _plan_pin(ctx: _Context) -> UpdateProposal | None:
    ref = ctx.intel.ref
    floating = ref.version is None or any(s.kind is SignalKind.FLOATING for s in ctx.intel.signals)
    if not floating or not ctx.policy.pin_floating or ref.ecosystem not in _PACKAGE_ECOSYSTEMS:
        return None
    target: str | None = None
    notes: list[str] = []
    rec = ctx.intel.recommended
    if ref.ecosystem == "oci":
        if rec is not None and _OCI_DIGEST.match(rec.version):
            target = rec.version
        elif ctx.intel.current is not None and _OCI_DIGEST.match(ctx.intel.current.version):
            target = ctx.intel.current.version
            notes.append("Pinned to the digest the tag resolves to today; verify the image before merging.")
    else:
        chosen, notes = _confirmed(ctx, cooldown_days=ctx.policy.cooldown_days)
        if chosen is not None:
            target = chosen.version
        else:
            notes = []
    if target is None:
        return None
    floating_sigs = [s for s in ctx.intel.signals if s.kind is SignalKind.FLOATING]
    severity = _raise_to(_max_severity((s.severity for s in floating_sigs), "medium"), "medium")
    how = "digest" if ref.ecosystem == "oci" else "version"
    spec = ref.version or "latest"
    return _proposal(
        ctx,
        "pin",
        target,
        f"Pin {ref.name} to {target if how == 'version' else target[:19] + '…'}",
        f"{ref.name} is referenced without an immutable {how} ({spec!s}): every start fetches whatever the "
        f"registry serves, the rug-pull channel. Pin to {target}, which passes the update policy "
        f"(cooldown {ctx.policy.cooldown_days} days, provenance continuity, no new install script). "
        f"Signals: {_signal_text(ctx.intel.signals) or 'none'}.",
        severity,
        notes,
    )


def _plan_unresolved_pin(ctx: _Context) -> UpdateProposal | None:
    """Advice (no edit) for a floating OCI image or Hugging Face reference the advisors could not resolve."""
    ref = ctx.intel.ref
    if ref.ecosystem not in ("oci", "huggingface") or not ctx.policy.pin_floating:
        return None
    floating_sigs = [s for s in ctx.intel.signals if s.kind is SignalKind.FLOATING]
    if not floating_sigs:
        return None
    what = "image digest (@sha256:…)" if ref.ecosystem == "oci" else "commit revision"
    severity = _raise_to(_max_severity((s.severity for s in floating_sigs), "medium"), "medium")
    return _proposal(
        ctx,
        "pin",
        f"(pin to a reviewed {what})",
        f"Pin {ref.name} to an immutable {what}",
        f"{ref.name} is referenced without an immutable {what}: every start fetches whatever is current, the "
        f"rug-pull channel. SymBiote has no advisor for {ref.ecosystem} yet, so it cannot choose or verify the "
        f"{what}; pin by hand to one you have reviewed. Signals: {_signal_text(ctx.intel.signals)}.",
        severity,
        [
            f"Resolve the {what} you have reviewed and pin the reference to it; no edit is proposed automatically."
        ],
    )


def _plan_version(ctx: _Context) -> UpdateProposal | None:
    ref = ctx.intel.ref
    if ctx.current_key is None:
        return None
    best, notes = _confirmed(ctx, cooldown_days=ctx.policy.cooldown_days)
    if best is None:
        return None
    severity = _max_severity(
        (
            s.severity
            for s in ctx.intel.signals
            if s.kind in (SignalKind.DEPRECATED, SignalKind.YANKED, SignalKind.NEWER_VERSION)
        ),
        "low",
    )
    cur_major, new_major = _major(ctx.current_version or ""), _major(best.version)
    if cur_major is not None and new_major is not None and cur_major != new_major:
        notes.append(f"This is a major-version change ({cur_major} -> {new_major}): expect breaking changes.")
    return _proposal(
        ctx,
        "version",
        best.version,
        f"Update {ref.name} from {ctx.current_version} to {best.version}",
        f"{best.version} is the release of {ref.name} the advisors recommend: confirmed free of advisories and "
        f"inside the update policy ({_age_text(best, ctx.now)}; cooldown {ctx.policy.cooldown_days} days, "
        f"provenance continuity, no new install script{'' if ctx.policy.allow_major else ', same major version'}). "
        f"Signals: {_signal_text(ctx.intel.signals) or 'none'}.",
        severity,
        notes,
    )


def _plan_replace(ctx: _Context) -> UpdateProposal | None:
    ref = ctx.intel.ref
    bad = [
        s
        for s in ctx.intel.signals
        if s.kind is SignalKind.DEPRECATED
        or (s.kind is SignalKind.YANKED and (s.reference in (None, ctx.current_version)))
    ]
    if not bad:
        return None
    severity = _max_severity((s.severity for s in bad), "medium")
    return _proposal(
        ctx,
        "replace",
        "(remove or replace)",
        f"Replace {ref.name}: {', '.join(sorted({s.kind.value for s in bad}))}",
        f"{ref.name} {ctx.current_version or ''} is {'; '.join(s.detail for s in bad)} and no release passes "
        "the update policy.",
        severity,
    )


def _ref_key(ref: DependencyRef) -> tuple[str, str, str, str]:
    return ref.kind.value, ref.ecosystem, ref.name, ref.version or ""


def plan_updates(
    intel: Sequence[DependencyIntel], policy: UpdatePolicy | None = None
) -> list[UpdateProposal]:
    """At most one proposal per dependency, most severe first (``spec/monitoring.md`` §4)."""
    pol = policy or UpdatePolicy()
    seen: set[tuple[str, str, str, str]] = set()
    proposals: list[UpdateProposal] = []
    for item in intel:
        key = _ref_key(item.ref)
        if key in seen:
            continue
        seen.add(key)
        ctx = _Context(item, pol)
        if item.coverage in ("unreachable", "not-attempted"):
            advice = _plan_unresolved_pin(ctx) if item.coverage == "not-attempted" else None
            if advice is not None:
                proposals.append(advice)
            continue
        for planner in (_plan_security, _plan_retire, _plan_pin, _plan_version, _plan_replace):
            proposal = planner(ctx)
            if proposal is not None:
                proposals.append(proposal)
                break
    proposals.sort(key=lambda p: (SEVERITY_ORDER.index(p.severity), p.dependency.name, p.kind))
    return proposals
