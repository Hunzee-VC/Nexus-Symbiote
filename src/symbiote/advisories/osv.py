"""OSV advisor: vulnerabilities and malicious-package records for one exact version (``api.osv.dev/v1/query``).

``MAL-*`` records (the OpenSSF malicious-packages feed) mark a release as malicious. Severity comes from the
record's ``database_specific.severity`` (GitHub advisories: ``LOW``/``MODERATE``/``HIGH``/``CRITICAL``), then
from an affected entry's ``ecosystem_specific``/``database_specific`` severity, then from a CVSS v3 base vector
(scored here), else ``unknown``. ``fixed_in`` lists the ``fixed`` events of the ``ECOSYSTEM``/``SEMVER`` ranges
that name this package (``GIT`` ranges are skipped: their events are commit hashes, not installable versions).
Records marked ``withdrawn`` no longer apply and are skipped.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from typing import Any, Final, Literal

from symbiote.advisories.http import HttpClient, MalformedResponse
from symbiote.advisories.npm import validate_version
from symbiote.advisories.types import Advisory

__all__ = ["OSV_QUERY", "OsvResult", "cvss3_base_score", "parse_vulns", "query_osv"]

OSV_QUERY: Final = "https://api.osv.dev/v1/query"
MAX_PAGES: Final = 5

Severity = Literal["critical", "high", "medium", "low", "unknown"]

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_TOKEN: Final = re.compile(r"[A-Za-z0-9+/=_.:-]{1,1024}")
_WORDS: Final[dict[str, Severity]] = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
}
_MAX_TEXT: Final = 300
_MAX_VULNS: Final = 500
_VERSION_RANGES: Final = frozenset({"ECOSYSTEM", "SEMVER"})

# CVSS v3.x base metric weights (FIRST CVSS v3.1 specification §7.4).
_AV: Final = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC: Final = {"L": 0.77, "H": 0.44}
_PR_U: Final = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C: Final = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI: Final = {"N": 0.85, "R": 0.62}
_CIA: Final = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Base score of a ``CVSS:3.x/...`` vector; ``None`` when the vector is not a complete v3 base vector."""
    if len(vector) > 200 or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, sep, val = part.partition(":")
        if not sep:
            return None
        metrics[key] = val
    try:
        scope_changed = metrics["S"] == "C"
        if metrics["S"] not in ("U", "C"):
            return None
        av, ac, ui = _AV[metrics["AV"]], _AC[metrics["AC"]], _UI[metrics["UI"]]
        pr = (_PR_C if scope_changed else _PR_U)[metrics["PR"]]
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    total = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return _roundup(min(total, 10.0))


def _score_severity(score: float) -> Severity:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def _word(value: object) -> Severity | None:
    if isinstance(value, str):
        return _WORDS.get(value.strip().lower())
    return None


def _matches(pkg: object, name: str, ecosystem: str) -> bool:
    if not isinstance(pkg, dict):
        return False
    pname, peco = pkg.get("name"), pkg.get("ecosystem")
    if not isinstance(pname, str) or not isinstance(peco, str):
        return False
    if peco.split(":", 1)[0].lower() != ecosystem.lower():
        return False
    if ecosystem.lower() == "pypi":
        return re.sub(r"[-_.]+", "-", pname).lower() == re.sub(r"[-_.]+", "-", name).lower()
    return pname == name


def _severity(vuln: dict[str, Any], affected: list[dict[str, Any]]) -> Severity:
    db = vuln.get("database_specific")
    if isinstance(db, dict) and (w := _word(db.get("severity"))):
        return w
    for entry in affected:
        for key in ("ecosystem_specific", "database_specific"):
            spec = entry.get(key)
            if isinstance(spec, dict) and (w := _word(spec.get("severity"))):
                return w
    best: float | None = None
    sev = vuln.get("severity")
    for item in sev if isinstance(sev, list) else []:
        if isinstance(item, dict) and isinstance(item.get("score"), str):
            score = cvss3_base_score(item["score"])
            if score is not None and (best is None or score > best):
                best = score
    return _score_severity(best) if best is not None else "unknown"


def _fixed(affected: Iterable[dict[str, Any]]) -> tuple[str, ...]:
    out: list[str] = []
    for entry in affected:
        ranges = entry.get("ranges")
        for rng in ranges if isinstance(ranges, list) else []:
            if not isinstance(rng, dict) or rng.get("type") not in _VERSION_RANGES:
                continue  # GIT ranges name commits; an unknown range type names nothing installable
            events = rng.get("events")
            for ev in events if isinstance(events, list) else []:
                fixed = ev.get("fixed") if isinstance(ev, dict) else None
                if isinstance(fixed, str) and fixed not in out:
                    try:
                        out.append(validate_version(fixed))
                    except ValueError:
                        continue
    return tuple(out)


def _text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return " ".join(value.split())[:_MAX_TEXT]
    return None


def parse_vulns(vulns: object, *, name: str, ecosystem: str) -> list[Advisory]:
    """Turn OSV ``vulns`` records into :class:`Advisory` values (records with unusable ids are skipped)."""
    out: list[Advisory] = []
    for vuln in vulns if isinstance(vulns, list) else []:
        if not isinstance(vuln, dict):
            continue
        vid = vuln.get("id")
        if not isinstance(vid, str) or not _ID.fullmatch(vid):
            continue
        withdrawn = vuln.get("withdrawn")
        if isinstance(withdrawn, str) and withdrawn:
            continue  # the database retracted it
        aliases_raw = vuln.get("aliases")
        aliases = tuple(
            a
            for a in (aliases_raw if isinstance(aliases_raw, list) else [])
            if isinstance(a, str) and _ID.fullmatch(a)
        )[:32]
        affected_raw = vuln.get("affected")
        affected = [
            a
            for a in (affected_raw if isinstance(affected_raw, list) else [])
            if isinstance(a, dict) and _matches(a.get("package"), name, ecosystem)
        ]
        malicious = vid.startswith("MAL-") or any(a.startswith("MAL-") for a in aliases)
        severity: Severity = "critical" if malicious else _severity(vuln, affected)
        out.append(
            Advisory(
                id=vid,
                summary=_text(vuln.get("summary")) or _text(vuln.get("details")) or vid,
                severity=severity,
                malicious=malicious,
                fixed_in=_fixed(affected),
                url=f"https://osv.dev/vulnerability/{vid}",
                aliases=aliases,
            )
        )
        if len(out) >= _MAX_VULNS:
            break
    return out


class OsvResult:
    __slots__ = ("advisories", "pages", "truncated")

    def __init__(self, advisories: list[Advisory], pages: int, truncated: bool) -> None:
        self.advisories = advisories
        self.pages = pages
        self.truncated = truncated


def query_osv(client: HttpClient, *, ecosystem: Literal["npm", "PyPI"], name: str, version: str) -> OsvResult:
    """Query OSV for ``name@version``; follows ``next_page_token`` for at most :data:`MAX_PAGES` pages."""
    validate_version(version)
    advisories: list[Advisory] = []
    seen: set[str] = set()
    token: str | None = None
    pages = 0
    while True:
        body: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        if token is not None:
            body["page_token"] = token
        data = client.post_json(OSV_QUERY, body)
        pages += 1
        if not isinstance(data, dict):
            raise MalformedResponse("OSV response is not a JSON object", url=OSV_QUERY)
        for adv in parse_vulns(data.get("vulns"), name=name, ecosystem=ecosystem):
            if adv.id not in seen:
                seen.add(adv.id)
                advisories.append(adv)
        nxt = data.get("next_page_token")
        if not isinstance(nxt, str) or not nxt:
            return OsvResult(advisories, pages, truncated=False)
        if not _TOKEN.fullmatch(nxt):
            raise MalformedResponse("OSV next_page_token has an unexpected shape", url=OSV_QUERY)
        if pages >= MAX_PAGES:
            return OsvResult(advisories, pages, truncated=True)
        token = nxt
