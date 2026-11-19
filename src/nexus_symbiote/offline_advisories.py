"""Offline advisory matching with provenance, alias deduplication, and KEV/EPSS enrichment.

Matches exact pinned PyPI and npm package identities in an AgentBOM against an
operator-supplied offline OSV bundle (JSON file or directory of OSV JSON files)
without opening any network socket.

Security properties:
- Every input file is opened with ``open_regular_file`` (no symlinks, regular files
  only) and bounded in size and record count.
- Alias pairs (for example a ``CVE-*`` record and a ``GHSA-*`` record that name each
  other in ``aliases``) are collapsed via union-find so each vulnerability appears once
  per affected component with its canonical ID and full alias list.
- Optional offline CISA/ENISA KEV and EPSS catalogs enrich matched advisories; a
  KEV-listed advisory elevates severity to ``critical`` while recording the base
  severity and naming the KEV source.
"""

from __future__ import annotations

import csv
import hashlib
import io
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
    MAX_COMPONENTS,
    AdvisoryReport,
    _excluded,
    _normalize,
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

_SEMVER_RE = re.compile(
    r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "unknown": 4,
}


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
    major, minor, patch = int(match[1]), int(match[2]), int(match[3])
    pre = match[4]
    if not pre:
        return (major, minor, patch, 1, ())
    parts: list[tuple[int, int | str]] = []
    for token in pre.split("."):
        if token.isdigit():
            parts.append((0, int(token)))
        else:
            parts.append((1, token))
    return (major, minor, patch, 0, tuple(parts))


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


def _extract_severity(record: dict[str, Any]) -> str:
    db_spec = record.get("database_specific")
    if isinstance(db_spec, dict):
        raw = db_spec.get("severity")
        if isinstance(raw, str):
            norm = raw.strip().lower()
            if norm == "moderate":
                return "medium"
            if norm in _SEVERITY_ORDER:
                return norm
    raw_sev = record.get("severity")
    if isinstance(raw_sev, str):
        norm = raw_sev.strip().lower()
        if norm == "moderate":
            return "medium"
        if norm in _SEVERITY_ORDER:
            return norm
    return "unknown"


def _parse_osv_records(payload: object) -> list[_ParsedAdvisory]:
    if isinstance(payload, dict):
        items = payload.get("advisories") or payload.get("vulnerabilities") or [payload]
    elif isinstance(payload, list):
        items = payload
    else:
        raise ValueError("Offline advisory DB must be a JSON object or array of OSV records")
    if not isinstance(items, list):
        raise ValueError("Offline advisory DB entries must be a JSON array")

    parsed: list[_ParsedAdvisory] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        rec_id = item.get("id")
        if not isinstance(rec_id, str) or not rec_id.strip():
            continue
        raw_aliases = item.get("aliases")
        aliases = (
            tuple(sorted({a.strip() for a in raw_aliases if isinstance(a, str) and a.strip()}))
            if isinstance(raw_aliases, list)
            else ()
        )
        summary = item.get("summary")
        if not isinstance(summary, str):
            summary = ""
        raw_affected = item.get("affected")
        affected = (
            tuple(a for a in raw_affected if isinstance(a, dict))
            if isinstance(raw_affected, list)
            else ()
        )
        parsed.append(
            _ParsedAdvisory(
                record_id=rec_id.strip(),
                aliases=aliases,
                summary=summary.strip(),
                severity=_extract_severity(item),
                affected=affected,
            )
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
        entries = sorted(os.scandir(path), key=lambda e: e.name)
        file_count = 0
        for entry in entries:
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
            payload = parse_json_strict(data.decode("utf-8"))
            records.extend(_parse_osv_records(payload))
            if len(records) > MAX_DB_RECORDS:
                raise ValueError(f"Offline advisory DB exceeds {MAX_DB_RECORDS} records")
        digest = "sha256:" + hashlib.sha256("\n".join(manifest_lines).encode("utf-8")).hexdigest()
        return records, digest

    data = _read_bounded_bytes(path, MAX_DB_BYTES, "Offline advisory DB")
    payload = parse_json_strict(data.decode("utf-8"))
    records = _parse_osv_records(payload)
    if len(records) > MAX_DB_RECORDS:
        raise ValueError(f"Offline advisory DB exceeds {MAX_DB_RECORDS} records")
    return records, hash_bytes(data)


def load_kev_catalog(path: Path) -> tuple[dict[str, list[_KEVEntry]], str]:
    """Load an offline CISA or ENISA KEV JSON catalog."""
    data = _read_bounded_bytes(path, MAX_CATALOG_BYTES, "KEV catalog")
    payload = parse_json_strict(data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("KEV catalog must be a JSON object")
    default_source = payload.get("source")
    if not isinstance(default_source, str) or not default_source.strip():
        title = str(payload.get("title", "")).lower()
        default_source = "enisa-kev" if "enisa" in title else "cisa-kev"
    raw_entries = payload.get("vulnerabilities")
    if raw_entries is None:
        raw_entries = payload.get("entries", [])
    if not isinstance(raw_entries, list):
        raise ValueError("KEV catalog entries must be a JSON array")

    index: dict[str, list[_KEVEntry]] = {}
    for entry in raw_entries:
        if not isinstance(entry, dict):
            continue
        raw_id = entry.get("cveID") or entry.get("id") or entry.get("cve")
        if not isinstance(raw_id, str) or not raw_id.strip():
            continue
        source = entry.get("source")
        src_name = source.strip() if isinstance(source, str) and source.strip() else default_source
        date_added = entry.get("dateAdded") or entry.get("date_added")
        index.setdefault(raw_id.strip().upper(), []).append(
            _KEVEntry(
                source=src_name,
                date_added=date_added.strip() if isinstance(date_added, str) else None,
            )
        )
    return index, hash_bytes(data)


def load_epss_catalog(path: Path) -> tuple[dict[str, _EPSSEntry], str]:
    """Load an offline EPSS CSV or JSON catalog."""
    data = _read_bounded_bytes(path, MAX_CATALOG_BYTES, "EPSS catalog")
    text = data.decode("utf-8")
    index: dict[str, _EPSSEntry] = {}
    if text.lstrip().startswith("{"):
        payload = parse_json_strict(text)
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise ValueError("EPSS JSON catalog must be an object with a 'data' array")
        for row in payload["data"]:
            if not isinstance(row, dict):
                continue
            cve = row.get("cve")
            epss = row.get("epss")
            if not isinstance(cve, str) or epss is None:
                continue
            pct = row.get("percentile")
            index[cve.strip().upper()] = _EPSSEntry(
                score=float(epss),
                percentile=float(pct) if pct is not None else None,
            )
        return index, hash_bytes(data)

    lines = [
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    for row in reader:
        cve = row.get("cve")
        epss = row.get("epss")
        if not cve or not epss:
            continue
        pct = row.get("percentile")
        index[cve.strip().upper()] = _EPSSEntry(
            score=float(epss),
            percentile=float(pct) if pct else None,
        )
    return index, hash_bytes(data)


def _matches_affected(
    affected: dict[str, Any], ecosystem: str, normalized_name: str, version: str
) -> tuple[bool, list[str]]:
    pkg = affected.get("package")
    if not isinstance(pkg, dict):
        return False, []
    pkg_eco = pkg.get("ecosystem")
    pkg_name = pkg.get("name")
    if not isinstance(pkg_eco, str) or not isinstance(pkg_name, str):
        return False, []
    if pkg_eco.lower() != ecosystem.lower():
        return False, []
    kind = "pypi" if ecosystem == "PyPI" else "npm"
    if _normalize(kind, pkg_name) != normalized_name:
        return False, []

    fixed_versions: list[str] = []
    matched = False
    raw_versions = affected.get("versions")
    if isinstance(raw_versions, list):
        for ver in raw_versions:
            if isinstance(ver, str) and _compare_versions(ecosystem, version, ver) == 0:
                matched = True
                break

    raw_ranges = affected.get("ranges")
    if isinstance(raw_ranges, list):
        for rng in raw_ranges:
            if not isinstance(rng, dict):
                continue
            events = rng.get("events")
            if not isinstance(events, list):
                continue
            in_range = False
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                if "introduced" in ev and isinstance(ev["introduced"], str):
                    intro = ev["introduced"]
                    if intro == "0":
                        in_range = True
                    else:
                        cmp_val = _compare_versions(ecosystem, version, intro)
                        if cmp_val is not None and cmp_val >= 0:
                            in_range = True
                elif "fixed" in ev and isinstance(ev["fixed"], str):
                    fixed = ev["fixed"]
                    fixed_versions.append(fixed)
                    cmp_val = _compare_versions(ecosystem, version, fixed)
                    if cmp_val is not None and cmp_val >= 0:
                        in_range = False
                elif "last_affected" in ev and isinstance(ev["last_affected"], str):
                    cmp_val = _compare_versions(ecosystem, version, ev["last_affected"])
                    if cmp_val is not None and cmp_val > 0:
                        in_range = False
            if in_range:
                matched = True

    return matched, sorted(set(fixed_versions))


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

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            if ra < rb:
                parent[rb] = ra
            else:
                parent[ra] = rb

    for adv, _ in matches:
        ids = [adv.record_id, *adv.aliases]
        for ident in ids:
            parent.setdefault(ident, ident)
        for ident in ids[1:]:
            union(ids[0], ident)

    grouped: dict[str, list[tuple[_ParsedAdvisory, list[str]]]] = {}
    for adv, fixed in matches:
        root = find(adv.record_id)
        grouped.setdefault(root, []).append((adv, fixed))

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
        aliases = sorted(i for i in all_ids if i != primary_id)
        merged.append(
            {
                "id": primary_id,
                "aliases": aliases,
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
    inventory_sha256: str | None = None,
) -> tuple[AdvisoryReport, dict[str, Any]]:
    """Match pinned packages in ``bom`` against an offline OSV DB with KEV/EPSS enrichment."""
    records, db_digest = load_offline_advisory_db(db_path)
    kev_index: dict[str, list[_KEVEntry]] = {}
    kev_provenance: list[dict[str, str]] = []
    for kpath in kev_paths:
        k_idx, k_digest = load_kev_catalog(kpath)
        kev_provenance.append({"path": kpath.name, "sha256": k_digest})
        for key, entries in k_idx.items():
            kev_index.setdefault(key, []).extend(entries)

    epss_index: dict[str, _EPSSEntry] = {}
    epss_provenance: dict[str, str] | None = None
    if epss_path is not None:
        epss_index, epss_digest = load_epss_catalog(epss_path)
        epss_provenance = {"path": epss_path.name, "sha256": epss_digest}

    patterns = tuple(exclude)
    report = AdvisoryReport(
        tool_version=__version__,
        inventory_sha256=inventory_sha256,
        dry_run=False,
    )

    targets: list[tuple[str, str, str, str]] = []
    for comp in sorted(bom.components, key=lambda c: c.bom_ref):
        if isinstance(comp, RegistryEntryComponent):
            if comp.registry_type not in {"pypi", "npm"}:
                report.components_skipped += 1
                report.skipped.append({"bom_ref": comp.bom_ref, "reason": "unsupported ecosystem"})
                continue
            try:
                eco, name, version = package_identity(comp)
            except ValueError as exc:
                report.components_skipped += 1
                report.skipped.append({"bom_ref": comp.bom_ref, "reason": str(exc)})
                continue
        elif isinstance(comp, MCPServerComponent):
            if not getattr(comp, "package_url", None):
                continue
            try:
                eco, name, version = mcp_package_identity(comp)
            except ValueError as exc:
                report.components_skipped += 1
                report.skipped.append({"bom_ref": comp.bom_ref, "reason": str(exc)})
                continue
        else:
            continue

        kind = "pypi" if eco == "PyPI" else "npm"
        if _excluded(kind, name, patterns):
            report.components_excluded += 1
            report.excluded.append({"bom_ref": comp.bom_ref, "package": name, "ecosystem": eco})
            continue
        targets.append((comp.bom_ref, eco, name, version))

    if len(targets) > MAX_COMPONENTS:
        report.errors.append(
            f"Package component limit exceeded ({len(targets)} > {MAX_COMPONENTS})"
        )
        provenance = {
            "offline": True,
            "db_sha256": db_digest,
            "kev_catalogs": kev_provenance,
            "epss_catalog": epss_provenance,
        }
        return report, provenance

    for bom_ref, eco, name, version in targets:
        report.components_checked += 1
        report.queries.append(
            {"bom_ref": bom_ref, "ecosystem": eco, "package": name, "version": version}
        )
        raw_matches: list[tuple[_ParsedAdvisory, list[str]]] = []
        for adv in records:
            for aff in adv.affected:
                is_match, fixed = _matches_affected(aff, eco, name, version)
                if is_match:
                    raw_matches.append((adv, fixed))
                    break

        for entry in _deduplicate_matches(raw_matches):
            if len(report.advisories) >= MAX_ADVISORIES:
                report.errors.append(f"Advisory report limit reached ({MAX_ADVISORIES})")
                break
            lookup_ids = [entry["id"].upper(), *(a.upper() for a in entry["aliases"])]
            kev_hits: list[_KEVEntry] = []
            for lid in lookup_ids:
                kev_hits.extend(kev_index.get(lid, ()))
            if kev_hits:
                sources = sorted({h.source for h in kev_hits})
                dates = sorted(h.date_added for h in kev_hits if h.date_added)
                entry["in_kev"] = True
                entry["kev_sources"] = sources
                if dates:
                    entry["kev_date_added"] = dates[0]
                if entry["severity"] != "critical":
                    entry["severity"] = "critical"
                    entry["severity_elevated_by"] = sources[0]
            else:
                entry["in_kev"] = False

            for lid in lookup_ids:
                epss_hit = epss_index.get(lid)
                if epss_hit is not None:
                    entry["epss_score"] = epss_hit.score
                    if epss_hit.percentile is not None:
                        entry["epss_percentile"] = epss_hit.percentile
                    break

            entry["bom_ref"] = bom_ref
            entry["ecosystem"] = eco
            entry["package"] = name
            entry["version"] = version
            entry["offline"] = True
            entry["db_sha256"] = db_digest
            report.advisories.append(entry)

    provenance = {
        "offline": True,
        "db_sha256": db_digest,
        "records_loaded": len(records),
        "kev_catalogs": kev_provenance,
        "epss_catalog": epss_provenance,
    }
    return report, provenance
