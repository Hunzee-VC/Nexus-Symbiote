"""Offline advisory matching with provenance, alias deduplication, and KEV/EPSS enrichment.

Matches exact pinned PyPI and npm packages in an AgentBOM against an operator-supplied
OSV bundle (a JSON file or a flat directory of them) without network I/O. Files are
opened without following symlinks and bounded in size. A bundle or catalog that is empty
or wrongly shaped is refused, and a package whose ecosystem the bundle holds no record
for is an error, so neither can pass as a complete result with no advisories.
"""

from __future__ import annotations

import csv
import hashlib
import io
import math
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from nexus_symbiote import __version__
from nexus_symbiote.advisories import (
    MAX_ADVISORIES,
    AdvisoryReport,
    _excluded,
    _in_scope,
    _normalize,
    _origin_exclusion,
    mcp_package_identity,
    package_identity,
)
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_bytes, open_regular_file, parse_json_strict
from nexus_symbiote.core.models import MCPServerComponent, RegistryEntryComponent

MAX_DB_BYTES = 32 * 1024 * 1024
MAX_DB_FILES = 10_000
MAX_DB_RECORDS = 100_000
MAX_CATALOG_BYTES = 16 * 1024 * 1024
MAX_OFFLINE_COMPONENTS = 50_000

_SEMVER_RE = re.compile(
    r"^v?(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)
_SUPPORTED_RANGE_TYPES = frozenset({"ECOSYSTEM", "SEMVER"})
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


@dataclass(frozen=True)
class _ParsedAdvisory:
    record_id: str
    aliases: tuple[str, ...]
    summary: str
    severity: str
    affected: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class _KEVEntry:
    source: str
    date_added: str | None


@dataclass(frozen=True)
class _EPSSEntry:
    score: float
    percentile: float | None


def _read_bounded_bytes(path: Path, max_bytes: int, label: str) -> bytes:
    with open_regular_file(path) as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"{label} exceeds maximum size of {max_bytes} bytes")
    return data


def _semver_key(raw: str) -> tuple[int, int, int, int, tuple[tuple[int, int | str], ...]] | None:
    match = _SEMVER_RE.fullmatch(raw.strip())
    if match is None:
        return None
    major, minor, patch = int(match[1]), int(match[2] or 0), int(match[3] or 0)
    pre = match[4]
    if not pre:
        return (major, minor, patch, 1, ())
    parts = tuple((0, int(tok)) if tok.isdigit() else (1, tok) for tok in pre.split("."))
    return (major, minor, patch, 0, parts)


def _compare_versions(ecosystem: str, left: str, right: str) -> int | None:
    if ecosystem == "PyPI":
        try:
            lv, rv = Version(left), Version(right)
        except InvalidVersion:
            return None
        return -1 if lv < rv else (1 if lv > rv else 0)
    if ecosystem == "npm":
        lk, rk = _semver_key(left), _semver_key(right)
        if lk is None or rk is None:
            return None
        return -1 if lk < rk else (1 if lk > rk else 0)
    return None


def _parse_epss_unit(raw: object, field_name: str) -> float:
    """Validate that an EPSS score or percentile is a finite float in [0.0, 1.0]."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        raise ValueError(f"EPSS {field_name} must be a finite number in [0, 1]")
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"EPSS {field_name} must be a finite number in [0, 1]") from exc
    if not math.isfinite(value) or not (0.0 <= value <= 1.0):
        raise ValueError(f"EPSS {field_name} must be a finite number in [0, 1]")
    return value


def _extract_severity(record: dict[str, Any]) -> str:
    db_spec = record.get("database_specific")
    candidates = [
        db_spec.get("severity") if isinstance(db_spec, dict) else None,
        record.get("severity"),
    ]
    for raw in candidates:
        if isinstance(raw, str):
            norm = "medium" if raw.strip().lower() == "moderate" else raw.strip().lower()
            if norm in _SEVERITY_ORDER:
                return norm
    return "unknown"


def _parse_osv_records(payload: object) -> list[_ParsedAdvisory]:
    items: object = payload
    if isinstance(payload, dict):
        wrapper = next((k for k in ("advisories", "vulnerabilities") if k in payload), None)
        items = [payload] if wrapper is None else payload[wrapper]
    if not isinstance(items, list):
        raise ValueError("Offline advisory DB must be an OSV record or an array of OSV records")

    parsed: list[_ParsedAdvisory] = []
    for item in items:
        rec_id = item.get("id") if isinstance(item, dict) else None
        if not isinstance(rec_id, str) or not rec_id.strip():
            raise ValueError("Offline advisory DB entry is not an OSV record with an 'id'")
        if item.get("withdrawn"):
            continue
        raw_aliases = item.get("aliases")
        aliases = (
            tuple(sorted({a.strip() for a in raw_aliases if isinstance(a, str) and a.strip()}))
            if isinstance(raw_aliases, list)
            else ()
        )
        raw_summary = item.get("summary")
        summary = raw_summary.strip() if isinstance(raw_summary, str) else ""
        raw_affected = item.get("affected")
        affected = (
            tuple(a for a in raw_affected if isinstance(a, dict))
            if isinstance(raw_affected, list)
            else ()
        )
        parsed.append(
            _ParsedAdvisory(rec_id.strip(), aliases, summary, _extract_severity(item), affected)
        )
    return parsed


def load_offline_advisory_db(path: Path) -> tuple[list[_ParsedAdvisory], str]:
    """Load bounded offline OSV records from a JSON file or directory, returning (records, sha256)."""
    if path.is_symlink():
        raise ValueError("Offline advisory DB path must not be a symbolic link")
    if path.is_dir():
        records: list[_ParsedAdvisory] = []
        total_bytes = 0
        manifest_lines: list[str] = []
        file_count = 0
        for entry in sorted(os.scandir(path), key=lambda e: e.name):
            if entry.is_dir():
                raise ValueError("Offline advisory DB directory must not contain subdirectories")
            if not entry.name.endswith(".json"):
                continue
            if entry.is_symlink():
                raise ValueError("Offline advisory DB directory must not contain symbolic links")
            file_count += 1
            if file_count > MAX_DB_FILES:
                raise ValueError(f"Offline advisory DB exceeds {MAX_DB_FILES} files")
            data = _read_bounded_bytes(Path(entry.path), MAX_DB_BYTES - total_bytes, entry.name)
            total_bytes += len(data)
            manifest_lines.append(f"{entry.name}:{hash_bytes(data)}")
            payload = parse_json_strict(data.decode("utf-8"), max_bytes=MAX_DB_BYTES)
            records.extend(_parse_osv_records(payload))
            if len(records) > MAX_DB_RECORDS:
                raise ValueError(f"Offline advisory DB exceeds {MAX_DB_RECORDS} records")
        digest = "sha256:" + hashlib.sha256("\n".join(manifest_lines).encode("utf-8")).hexdigest()
    else:
        data = _read_bounded_bytes(path, MAX_DB_BYTES, "Offline advisory DB")
        records = _parse_osv_records(
            parse_json_strict(data.decode("utf-8"), max_bytes=MAX_DB_BYTES)
        )
        digest = hash_bytes(data)
    if not records:
        raise ValueError("Offline advisory DB holds no advisory records")
    if len(records) > MAX_DB_RECORDS:
        raise ValueError(f"Offline advisory DB exceeds {MAX_DB_RECORDS} records")
    return records, digest


def load_kev_catalog(path: Path) -> tuple[dict[str, list[_KEVEntry]], str]:
    """Load an offline CISA or ENISA KEV JSON catalog."""
    data = _read_bounded_bytes(path, MAX_CATALOG_BYTES, "KEV catalog")
    payload = parse_json_strict(data.decode("utf-8"), max_bytes=MAX_CATALOG_BYTES)
    if not isinstance(payload, dict):
        raise ValueError("KEV catalog must be a JSON object")
    default_source = payload.get("source")
    if not isinstance(default_source, str) or not default_source.strip():
        default_source = (
            "enisa-kev" if "enisa" in str(payload.get("title", "")).lower() else "cisa-kev"
        )
    raw_entries = payload.get("vulnerabilities", payload.get("entries"))
    if not isinstance(raw_entries, list):
        raise ValueError("KEV catalog must hold a 'vulnerabilities' or 'entries' array")

    index: dict[str, list[_KEVEntry]] = {}
    for entry in raw_entries:
        if not isinstance(entry, dict):
            continue
        raw_id = entry.get("cveID") or entry.get("id") or entry.get("cve")
        if not isinstance(raw_id, str) or not raw_id.strip():
            continue
        src = entry.get("source")
        src_name = src.strip() if isinstance(src, str) and src.strip() else default_source
        date_added = entry.get("dateAdded") or entry.get("date_added")
        index.setdefault(raw_id.strip().upper(), []).append(
            _KEVEntry(src_name, date_added.strip() if isinstance(date_added, str) else None)
        )
    if not index:
        raise ValueError("KEV catalog holds no entries")
    return index, hash_bytes(data)


def load_epss_catalog(path: Path) -> tuple[dict[str, _EPSSEntry], str]:
    """Load an offline EPSS CSV or JSON catalog with strict finite [0, 1] validation."""
    data = _read_bounded_bytes(path, MAX_CATALOG_BYTES, "EPSS catalog")
    text = data.decode("utf-8")
    index: dict[str, _EPSSEntry] = {}
    if text.lstrip().startswith(("{", "[")):
        payload = parse_json_strict(text, max_bytes=MAX_CATALOG_BYTES)
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise ValueError("EPSS JSON catalog must be an object with a 'data' array")
        for row in payload["data"]:
            if not isinstance(row, dict):
                continue
            cve, epss, pct = row.get("cve"), row.get("epss"), row.get("percentile")
            if not isinstance(cve, str) or not cve.strip() or epss is None:
                continue
            index[cve.strip().upper()] = _EPSSEntry(
                _parse_epss_unit(epss, "score"),
                _parse_epss_unit(pct, "percentile") if pct is not None else None,
            )
    else:
        rows = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        for row in csv.DictReader(io.StringIO("\n".join(rows))):
            cve, epss, pct = row.get("cve"), row.get("epss"), row.get("percentile")
            if not cve or not cve.strip() or not epss or not epss.strip():
                continue
            index[cve.strip().upper()] = _EPSSEntry(
                _parse_epss_unit(epss.strip(), "score"),
                _parse_epss_unit(pct.strip(), "percentile") if pct and pct.strip() else None,
            )
    if not index:
        raise ValueError("EPSS catalog holds no entries")
    return index, hash_bytes(data)


def _range_matches(ecosystem: str, version: str, rng: dict[str, Any]) -> tuple[bool, list[str]]:
    """Evaluate one OSV range by version intervals (order-independent per OSV spec)."""
    raw_type = rng.get("type")
    if raw_type is not None and (
        not isinstance(raw_type, str) or raw_type.upper() not in _SUPPORTED_RANGE_TYPES
    ):
        return False, []
    events = rng.get("events")
    if not isinstance(events, list):
        return False, []

    has_zero_intro = False
    intros: list[str] = []
    fixed_versions: list[str] = []
    last_affected: list[str] = []
    limits: list[str] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if "introduced" in ev:
            raw_intro = ev["introduced"]
            if raw_intro == "0" or (
                isinstance(raw_intro, int) and not isinstance(raw_intro, bool) and raw_intro == 0
            ):
                has_zero_intro = True
            elif isinstance(raw_intro, str) and raw_intro.strip():
                intros.append(raw_intro.strip())
        elif "fixed" in ev and isinstance(ev["fixed"], str) and ev["fixed"].strip():
            fixed_versions.append(ev["fixed"].strip())
        elif (
            "last_affected" in ev
            and isinstance(ev["last_affected"], str)
            and ev["last_affected"].strip()
        ):
            last_affected.append(ev["last_affected"].strip())
        elif "limit" in ev and isinstance(ev["limit"], str) and ev["limit"].strip():
            limits.append(ev["limit"].strip())

    if any(
        (c := _compare_versions(ecosystem, version, lim)) is not None and c >= 0 for lim in limits
    ):
        return False, []

    best_intro: str | None = None
    found_intro = has_zero_intro
    for intro in intros:
        cmp_v = _compare_versions(ecosystem, intro, version)
        if cmp_v is None or cmp_v > 0:
            continue
        found_intro = True
        if best_intro is None or (
            (cb := _compare_versions(ecosystem, intro, best_intro)) is not None and cb > 0
        ):
            best_intro = intro
    if not found_intro:
        return False, []

    for fix in fixed_versions:
        cmp_v = _compare_versions(ecosystem, fix, version)
        if cmp_v is None or cmp_v > 0:
            continue
        if best_intro is None or (
            (ci := _compare_versions(ecosystem, best_intro, fix)) is not None and ci <= 0
        ):
            return False, []

    for last in last_affected:
        cmp_v = _compare_versions(ecosystem, last, version)
        if cmp_v is None or cmp_v >= 0:
            continue
        if best_intro is None or (
            (ci := _compare_versions(ecosystem, best_intro, last)) is not None and ci <= 0
        ):
            return False, []

    relevant_fixes = [
        fix
        for fix in fixed_versions
        if (cf := _compare_versions(ecosystem, fix, version)) is not None and cf > 0
    ]
    return True, relevant_fixes


def _matches_affected_version(
    affected: dict[str, Any], ecosystem: str, version: str
) -> tuple[bool, list[str]]:
    """Evaluate version lists and OSV ranges for an already-package-matched affected block."""
    fixed_versions: list[str] = []
    matched = False
    raw_versions = affected.get("versions")
    if isinstance(raw_versions, list) and any(
        isinstance(ver, str) and _compare_versions(ecosystem, version, ver) == 0
        for ver in raw_versions
    ):
        matched = True
    raw_ranges = affected.get("ranges")
    if isinstance(raw_ranges, list):
        for rng in raw_ranges:
            if not isinstance(rng, dict):
                continue
            in_range, rng_fixed = _range_matches(ecosystem, version, rng)
            if in_range:
                matched = True
                fixed_versions.extend(rng_fixed)
    return matched, sorted(set(fixed_versions))


def _build_package_index(
    records: list[_ParsedAdvisory],
) -> dict[tuple[str, str], list[tuple[_ParsedAdvisory, dict[str, Any]]]]:
    """Index OSV affected blocks by ``(ecosystem.lower(), normalized_name)`` for O(1) lookup."""
    index: dict[tuple[str, str], list[tuple[_ParsedAdvisory, dict[str, Any]]]] = {}
    for adv in records:
        for aff in adv.affected:
            pkg = aff.get("package")
            if not isinstance(pkg, dict):
                continue
            pkg_eco, pkg_name = pkg.get("ecosystem"), pkg.get("name")
            if not isinstance(pkg_eco, str) or not isinstance(pkg_name, str):
                continue
            eco_lower = pkg_eco.strip().lower()
            if eco_lower in {"pypi", "npm"}:
                index.setdefault((eco_lower, _normalize(eco_lower, pkg_name.strip())), []).append(
                    (adv, aff)
                )
    return index


def _deduplicate_matches(
    matches: list[tuple[_ParsedAdvisory, list[str]]],
) -> list[dict[str, Any]]:
    """Collapse alias pairs into one canonical advisory entry via union-find."""
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        while parent.get(node, node) != node:
            parent[node] = parent.get(parent[node], parent[node])
            node = parent[node]
        return node

    for adv, _ in matches:
        ids = [adv.record_id, *adv.aliases]
        for ident in ids:
            parent.setdefault(ident, ident)
        for ident in ids[1:]:
            ra, rb = find(ids[0]), find(ident)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)

    grouped: dict[str, list[tuple[_ParsedAdvisory, list[str]]]] = {}
    for adv, fixed in matches:
        grouped.setdefault(find(adv.record_id), []).append((adv, fixed))

    merged: list[dict[str, Any]] = []
    for items in grouped.values():
        all_ids: set[str] = set()
        matched_ids: set[str] = set()
        fixed_all: set[str] = set()
        summaries: list[str] = []
        best_severity = "unknown"
        for adv, fixed in items:
            matched_ids.add(adv.record_id)
            all_ids.add(adv.record_id)
            all_ids.update(adv.aliases)
            fixed_all.update(fixed)
            if adv.summary:
                summaries.append(adv.summary)
            if _SEVERITY_ORDER[adv.severity] < _SEVERITY_ORDER[best_severity]:
                best_severity = adv.severity
        cves = sorted(i for i in all_ids if i.upper().startswith("CVE-"))
        primary_id = cves[0] if cves else sorted(all_ids)[0]
        merged.append(
            {
                "id": primary_id,
                "advisory_id": primary_id,
                "aliases": sorted(i for i in all_ids if i != primary_id),
                "matched_ids": sorted(matched_ids),
                "severity": best_severity,
                "base_severity": best_severity,
                "summary": sorted(set(summaries))[0] if summaries else "",
                "fixed_versions": sorted(fixed_all),
            }
        )
    merged.sort(key=lambda entry: entry["id"])
    return merged


def match_offline_advisories(
    bom: AIBOM,
    *,
    db_path: Path,
    kev_paths: Iterable[Path] = (),
    epss_path: Path | None = None,
    exclude: Iterable[str] = (),
    exclude_private_origins: bool = False,
    inventory_sha256: str | None = None,
) -> tuple[AdvisoryReport, dict[str, Any]]:
    """Match pinned packages in ``bom`` against an offline OSV DB with KEV/EPSS enrichment."""
    patterns = list(exclude)
    if any(not isinstance(p, str) or not p or len(p) > 256 for p in patterns):
        raise ValueError("exclusion patterns must be 1 to 256 characters")
    if any("*" in p[:-1] for p in patterns):
        raise ValueError("an exclusion pattern may hold '*' only as its last character")

    records, db_digest = load_offline_advisory_db(db_path)
    pkg_index = _build_package_index(records)
    covered = {ecosystem for ecosystem, _ in pkg_index}

    kev_index: dict[str, list[_KEVEntry]] = {}
    kev_provenance: list[dict[str, Any]] = []
    for kpath in kev_paths:
        k_idx, k_digest = load_kev_catalog(kpath)
        kev_provenance.append({"path": kpath.name, "sha256": k_digest, "entries": len(k_idx)})
        for key, entries in k_idx.items():
            kev_index.setdefault(key, []).extend(entries)

    epss_index: dict[str, _EPSSEntry] = {}
    epss_provenance: dict[str, Any] | None = None
    if epss_path is not None:
        epss_index, digest = load_epss_catalog(epss_path)
        epss_provenance = {"path": epss_path.name, "sha256": digest, "entries": len(epss_index)}

    provenance: dict[str, Any] = {
        "offline": True,
        "db_sha256": db_digest,
        "records_loaded": len(records),
        "kev_catalogs": kev_provenance,
        "epss_catalog": epss_provenance,
    }
    report = AdvisoryReport(
        tool_version=__version__, inventory_sha256=inventory_sha256, dry_run=False
    )

    targets: list[tuple[str, str, str, str]] = []
    for comp in sorted(bom.components, key=lambda c: c.bom_ref):
        kind = _in_scope(comp)
        if kind is None:
            continue
        if not kind:
            report.components_skipped += 1
            report.skipped.append(
                {"component_ref": comp.bom_ref, "reason": "ecosystem is not queried"}
            )
            continue
        try:
            if isinstance(comp, RegistryEntryComponent):
                eco, name, version = package_identity(comp)
            elif isinstance(comp, MCPServerComponent):
                eco, name, version = mcp_package_identity(comp)
            else:
                continue
        except (ValueError, TypeError, UnicodeError):
            report.errors.append(f"{comp.bom_ref}: exact package identity unavailable")
            continue
        reason = (
            "excluded by the operator"
            if _excluded(kind, name, patterns)
            else _origin_exclusion(comp, kind)
            if exclude_private_origins
            else None
        )
        if reason is not None:
            report.components_excluded += 1
            report.excluded.append({"component_ref": comp.bom_ref, "reason": reason})
            continue
        if eco.lower() not in covered:
            report.errors.append(f"{comp.bom_ref}: offline advisory DB holds no {eco} records")
            continue
        targets.append((comp.bom_ref, eco, name, version))

    if len(targets) > MAX_OFFLINE_COMPONENTS:
        report.errors.append(
            f"Package component limit exceeded ({len(targets)} > {MAX_OFFLINE_COMPONENTS})"
        )
        return report, provenance

    for bom_ref, eco, name, version in targets:
        report.components_checked += 1
        report.queries.append(
            {"component_ref": bom_ref, "ecosystem": eco, "name": name, "version": version}
        )
        matched_by_adv: dict[str, tuple[_ParsedAdvisory, list[str]]] = {}
        for adv, aff in pkg_index.get((eco.lower(), name), ()):
            is_match, fixed = _matches_affected_version(aff, eco, version)
            if is_match:
                existing = matched_by_adv.get(adv.record_id)
                if existing is None:
                    matched_by_adv[adv.record_id] = (adv, list(fixed))
                else:
                    existing[1].extend(fixed)
        raw_matches = [(adv, sorted(set(fx))) for adv, fx in matched_by_adv.values()]
        for entry in _deduplicate_matches(raw_matches):
            if len(report.advisories) >= MAX_ADVISORIES:
                report.errors.append(f"Advisory report limit reached ({MAX_ADVISORIES})")
                return report, provenance
            lookup_ids = [entry["id"].upper(), *(a.upper() for a in entry["aliases"])]
            kev_hits = [hit for lid in lookup_ids for hit in kev_index.get(lid, ())]
            entry["in_kev"] = bool(kev_hits)
            if kev_hits:
                sources = sorted({h.source for h in kev_hits})
                dates = sorted(h.date_added for h in kev_hits if h.date_added)
                entry["kev_sources"] = sources
                if dates:
                    entry["kev_date_added"] = dates[0]
                if entry["severity"] != "critical":
                    entry["severity"] = "critical"
                    entry["severity_elevated_by"] = sources[0]
            for lid in lookup_ids:
                if (epss_hit := epss_index.get(lid)) is not None:
                    entry["epss_score"] = epss_hit.score
                    if epss_hit.percentile is not None:
                        entry["epss_percentile"] = epss_hit.percentile
                    break
            entry.update(
                {
                    "component_ref": bom_ref,
                    "bom_ref": bom_ref,
                    "ecosystem": eco,
                    "package": name,
                    "version": version,
                    "offline": True,
                    "db_sha256": db_digest,
                }
            )
            report.advisories.append(entry)
    return report, provenance
