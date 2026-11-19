"""Foreign SBOM import, nested manifest walker, pinning_state, and unread_shapes census (R1.2-2)."""

from __future__ import annotations

import configparser
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import yaml
from packaging.requirements import InvalidRequirement, Requirement

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.canonical import json_text
from nexus_symbiote.core.enums import AssuranceLevel, RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_bytes, open_regular_file, parse_json_strict
from nexus_symbiote.core.models import (
    AnyComponent,
    ClaimEvidence,
    CompletenessClaim,
    MCPServerComponent,
    ModelComponent,
    RegistryEntryComponent,
    RiskAssessment,
)
from nexus_symbiote.scanners.registry import (
    AI_IMAGE_KEYWORDS,
    AI_PACKAGE_NAMES,
    AI_PACKAGE_PREFIXES,
)
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import redact_text
from nexus_symbiote.utils.terminal import neutralize
from nexus_symbiote.utils.toml import loads as load_toml

MAX_FOREIGN_SBOM_BYTES: Final[int] = 16 * 1024 * 1024
MAX_FOREIGN_COMPONENTS: Final[int] = 10_000
MAX_MANIFEST_YAML_BYTES: Final[int] = 512 * 1024
MAX_MANIFEST_YAML_DEPTH: Final[int] = 64
_EXACT_VERSION_RE: Final[re.Pattern[str]] = re.compile(
    r"v?[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][0-9A-Za-z.-]+)?",
    re.ASCII,
)
_SHA256_HEX_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-fA-F]{64}", re.ASCII)


@dataclass(frozen=True)
class UnreadShapeCount:
    """Advisory count of repository artifact shapes owned by ShadowScan / external tools."""

    shape: str
    count: int
    owner: str = "shadowscan"


@dataclass
class SBOMImportSummary:
    """Result of importing a foreign CycloneDX or SPDX BOM into an AIBOM."""

    aibom: AIBOM
    source_format: str
    document_sha256: str
    imported_count: int = 0
    bound_local_count: int = 0
    conflict_count: int = 0
    conflicts: list[str] = field(default_factory=list)


_EXTRA_AI_PREFIXES: Final[tuple[str, ...]] = (
    "candle-",
    "async-openai",
    "rig-",
    "tokenizers",
    "burn-",
    "langchaingo",
    "go-openai",
)


def _is_ai_package_name(name: str) -> bool:
    lowered = re.sub(r"[-_.]+", "-", name.strip().lower())
    if lowered in AI_PACKAGE_NAMES or lowered == "ort":
        return True
    unscoped = lowered.rsplit("/", 1)[-1] if "/" in lowered else lowered
    return any(
        unscoped.startswith(prefix) for prefix in (*AI_PACKAGE_PREFIXES, *_EXTRA_AI_PREFIXES)
    ) or any(kw in lowered for kw in AI_IMAGE_KEYWORDS)


def _normalize_sha256(alg: str, digest: str) -> str | None:
    cleaned_alg = alg.strip().upper().replace("-", "")
    cleaned_val = digest.strip().removeprefix("sha256:").lower()
    if cleaned_alg == "SHA256" and _SHA256_HEX_RE.fullmatch(cleaned_val):
        return f"sha256:{cleaned_val}"
    return None


def _display_name(raw_name: str, *, doc_sha256: str, reveal_names: bool) -> str:
    cleaned = neutralize(redact_text(raw_name.strip()))
    if reveal_names and cleaned:
        return cleaned[:200]
    digest = hashlib.sha256(f"{doc_sha256}:{raw_name}".encode()).hexdigest()[:16]
    return f"imported-{digest}"


def _yaml_flow_depth_exceeds(text: str, max_depth: int = MAX_MANIFEST_YAML_DEPTH) -> bool:
    depth = 0
    in_single = False
    in_double = False
    escape = False
    for ch in text:
        if escape:
            escape = False
            continue
        if in_double and ch == "\\":
            escape = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            continue
        if in_single or in_double:
            continue
        if ch in "[{":
            depth += 1
            if depth > max_depth:
                return True
        elif ch in "]}" and depth > 0:
            depth -= 1
    return False


def _extract_cdx_entries(doc: dict[str, Any]) -> list[dict[str, Any]]:
    raw_comps = doc.get("components")
    if raw_comps is None:
        return []
    if not isinstance(raw_comps, list):
        raise ValueError("CycloneDX components field must be a JSON array")
    if len(raw_comps) > MAX_FOREIGN_COMPONENTS:
        raise ValueError(f"foreign SBOM exceeds maximum component count ({MAX_FOREIGN_COMPONENTS})")
    entries: list[dict[str, Any]] = []
    for item in raw_comps:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        sha256_val: str | None = None
        raw_hashes = item.get("hashes")
        if isinstance(raw_hashes, list):
            for h in raw_hashes:
                if (
                    isinstance(h, dict)
                    and isinstance(h.get("alg"), str)
                    and isinstance(h.get("content"), str)
                ):
                    sha256_val = _normalize_sha256(h["alg"], h["content"])
                    if sha256_val:
                        break
        entries.append(
            {
                "raw_entry": item,
                "name": item["name"],
                "version": item.get("version") if isinstance(item.get("version"), str) else None,
                "purl": item.get("purl") if isinstance(item.get("purl"), str) else None,
                "type": item.get("type") if isinstance(item.get("type"), str) else "library",
                "supplier": (
                    item["supplier"].get("name")
                    if isinstance(item.get("supplier"), dict)
                    and isinstance(item["supplier"].get("name"), str)
                    else None
                ),
                "sha256": sha256_val,
            }
        )
    return entries


def _extract_spdx_entries(doc: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    entries: list[dict[str, Any]] = []
    if isinstance(doc.get("@graph"), list):
        graph = doc["@graph"]
        if len(graph) > MAX_FOREIGN_COMPONENTS:
            raise ValueError(
                f"foreign SPDX @graph exceeds maximum element count ({MAX_FOREIGN_COMPONENTS})"
            )
        for node in graph:
            if not isinstance(node, dict):
                continue
            typ = node.get("type")
            if typ not in {"software_Package", "ai_AIPackage", "dataset_DatasetPackage"}:
                continue
            name = node.get("name")
            if not isinstance(name, str) or not name:
                continue
            sha256_val: str | None = None
            verified = node.get("verifiedUsing")
            if isinstance(verified, list):
                for h in verified:
                    if (
                        isinstance(h, dict)
                        and isinstance(h.get("algorithm"), str)
                        and isinstance(h.get("hashValue"), str)
                    ):
                        sha256_val = _normalize_sha256(h["algorithm"], h["hashValue"])
                        if sha256_val:
                            break
            entries.append(
                {
                    "raw_entry": node,
                    "name": name,
                    "version": (
                        node.get("software_packageVersion")
                        if isinstance(node.get("software_packageVersion"), str)
                        else None
                    ),
                    "purl": (
                        node.get("software_packageUrl")
                        if isinstance(node.get("software_packageUrl"), str)
                        else None
                    ),
                    "type": "machine-learning-model" if typ == "ai_AIPackage" else "library",
                    "supplier": None,
                    "sha256": sha256_val,
                }
            )
        return "spdx-3.0.1", entries

    if isinstance(doc.get("packages"), list):
        packages = doc["packages"]
        if len(packages) > MAX_FOREIGN_COMPONENTS:
            raise ValueError(
                f"foreign SPDX packages exceeds maximum count ({MAX_FOREIGN_COMPONENTS})"
            )
        for pkg in packages:
            if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
                continue
            sha256_val = None
            for chk in pkg.get("checksums", []) if isinstance(pkg.get("checksums"), list) else []:
                if (
                    isinstance(chk, dict)
                    and isinstance(chk.get("algorithm"), str)
                    and isinstance(chk.get("checksumValue"), str)
                ):
                    sha256_val = _normalize_sha256(chk["algorithm"], chk["checksumValue"])
                    if sha256_val:
                        break
            purl_val: str | None = None
            for ref in (
                pkg.get("externalRefs", []) if isinstance(pkg.get("externalRefs"), list) else []
            ):
                if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                    loc = ref.get("referenceLocator")
                    if isinstance(loc, str):
                        purl_val = loc
                        break
            entries.append(
                {
                    "raw_entry": pkg,
                    "name": pkg["name"],
                    "version": (
                        pkg.get("versionInfo") if isinstance(pkg.get("versionInfo"), str) else None
                    ),
                    "purl": purl_val,
                    "type": "library",
                    "supplier": None,
                    "sha256": sha256_val,
                }
            )
        return "spdx-2.3", entries

    raise ValueError("unrecognized foreign SBOM format (expected CycloneDX or SPDX JSON)")


def _local_digest_index(
    aibom: AIBOM, project_root: Path | None
) -> tuple[dict[str, str], list[str]]:
    """Map sha256:<hex> to existing component bom_ref or local relative path."""
    by_digest: dict[str, str] = {}
    for comp in aibom.components:
        sha = comp.hashes.get("sha256")
        if isinstance(sha, str):
            by_digest[sha] = comp.bom_ref
    failures: list[str] = []
    if project_root is not None:
        with ConfinedCollection(project_root, failures) as files:
            for rel_path in files.iter_files():
                raw = files.read_bytes(rel_path.as_posix(), missing_ok=True)
                if raw is not None:
                    by_digest.setdefault(hash_bytes(raw), rel_path.as_posix())
    return by_digest, failures


def import_foreign_sbom(
    bom_path: Path,
    *,
    target_aibom: AIBOM | None = None,
    project_root: Path | None = None,
    reveal_names: bool = False,
) -> SBOMImportSummary:
    """Import any CycloneDX or SPDX JSON BOM as DECLARED evidence without picking silent winners."""
    with open_regular_file(bom_path) as handle:
        raw_bytes = handle.read(MAX_FOREIGN_SBOM_BYTES + 1)
    if len(raw_bytes) > MAX_FOREIGN_SBOM_BYTES:
        raise ValueError("foreign SBOM exceeds maximum size limit (16 MiB)")

    doc_sha256 = hash_bytes(raw_bytes)
    parsed = parse_json_strict(raw_bytes, max_bytes=MAX_FOREIGN_SBOM_BYTES)
    if not isinstance(parsed, dict):
        raise ValueError("foreign SBOM must be a JSON object")

    if parsed.get("bomFormat") == "CycloneDX":
        spec_val = parsed.get("specVersion")
        spec = neutralize(spec_val)[:32] if isinstance(spec_val, str) and spec_val else "unknown"
        source_format = f"cyclonedx-{spec}"
        entries = _extract_cdx_entries(parsed)
    else:
        source_format, entries = _extract_spdx_entries(parsed)

    bom = target_aibom.model_copy(deep=True) if target_aibom is not None else AIBOM()
    digest_index, local_failures = _local_digest_index(bom, project_root)

    # Index existing components by canonical package_url or normalized name to detect source_conflict.
    by_identity: dict[str, list[AnyComponent]] = {}
    for existing in bom.components:
        if isinstance(existing, RegistryEntryComponent) and existing.package_url:
            by_identity.setdefault(f"purl:{existing.package_url.split('@')[0]}", []).append(
                existing
            )
        by_identity.setdefault(f"name:{existing.name.lower()}", []).append(existing)

    summary = SBOMImportSummary(
        aibom=bom,
        source_format=source_format,
        document_sha256=doc_sha256,
    )

    for index, entry in enumerate(entries):
        entry_sha256 = hash_bytes(json_text(entry["raw_entry"]).encode("utf-8"))
        raw_name: str = entry["name"]
        shown_name = _display_name(raw_name, doc_sha256=doc_sha256, reveal_names=reveal_names)
        raw_ver = entry["version"]
        clean_ver = neutralize(redact_text(raw_ver))[:128] if raw_ver else None
        raw_purl = entry["purl"]
        clean_purl = neutralize(redact_text(raw_purl))[:512] if raw_purl else None
        sha256_val: str | None = entry["sha256"]

        key_base = (
            f"purl:{clean_purl.split('@')[0]}"
            if clean_purl
            else f"name:{neutralize(raw_name).lower()}"
        )
        peers = by_identity.get(key_base, [])

        bound_target = digest_index.get(sha256_val) if sha256_val else None
        if bound_target is not None:
            summary.bound_local_count += 1

        conflict_msgs: list[str] = []
        for peer in peers:
            peer_sha = peer.hashes.get("sha256")
            if clean_ver and peer.version and peer.version != clean_ver:
                conflict_msgs.append(
                    f"version disagrees with {peer.bom_ref} ({peer.version} vs {clean_ver})"
                )
            elif sha256_val and peer_sha and peer_sha != sha256_val:
                conflict_msgs.append(f"digest disagrees with {peer.bom_ref}")

        ref_seed = f"{doc_sha256}:{index}:{raw_name}:{clean_ver or ''}"
        ref_hash = hashlib.sha256(ref_seed.encode("utf-8")).hexdigest()[:16]

        risks: list[RiskAssessment] = []
        if conflict_msgs:
            summary.conflict_count += 1
            joined = "; ".join(conflict_msgs)
            summary.conflicts.append(f"sbom:{ref_hash}: {joined}")
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="source_conflict",
                    detail=(
                        f"Imported SBOM entry '{shown_name}' conflicts with existing inventory "
                        f"declaration ({neutralize(joined)}); both records are retained."
                    ),
                    recommendation=(
                        "Reconcile the supplier SBOM with the repository lockfiles and manifests."
                    ),
                )
            )
            for peer in peers:
                peer_risks = getattr(peer, "risks", None)
                if isinstance(peer_risks, list) and not any(
                    r.category == "source_conflict" for r in peer_risks
                ):
                    peer_risks.append(
                        RiskAssessment(
                            severity=RiskSeverity.MEDIUM,
                            category="source_conflict",
                            detail=(
                                f"Component '{neutralize(peer.name)}' conflicts with imported "
                                f"SBOM {doc_sha256[:19]} ({neutralize(joined)})."
                            ),
                            recommendation=(
                                "Reconcile the repository manifest or lockfile with the imported SBOM."
                            ),
                        )
                    )

        claims = {
            "imported.sbom": ClaimEvidence(
                assurance=AssuranceLevel.DECLARED,
                method=f"sbom-import:{source_format}",
                scope="component",
                locator=f"{neutralize(bom_path.name)}#{index}",
            )
        }
        props: dict[str, Any] = {
            "imported_document_sha256": doc_sha256,
            "imported_entry_sha256": entry_sha256,
            "imported_source_format": source_format,
            "name_hashed": not reveal_names,
        }
        if bound_target is not None:
            props["local_digest_binding"] = bound_target

        hashes = {"sha256": sha256_val} if sha256_val else {}
        pinned = bool(clean_ver and _EXACT_VERSION_RE.fullmatch(clean_ver)) or bool(hashes)

        comp: AnyComponent
        if entry["type"] == "machine-learning-model":
            comp = ModelComponent(
                bom_ref=f"sbom:model:{ref_hash}",
                name=shown_name,
                version=clean_ver,
                supplier=(
                    neutralize(redact_text(entry["supplier"]))[:200]
                    if (reveal_names and entry["supplier"])
                    else None
                ),
                hashes=hashes,
                assurance_level=AssuranceLevel.DECLARED,
                trust_tier=TrustTier.UNKNOWN,
                properties=props,
                claims=claims,
                risks=risks,
            )
        else:
            reg_type = (
                "pypi"
                if (clean_purl and clean_purl.startswith("pkg:pypi/"))
                else (
                    "npm" if (clean_purl and clean_purl.startswith("pkg:npm/")) else "foreign-sbom"
                )
            )
            props["version_pinned"] = pinned
            comp = RegistryEntryComponent(
                bom_ref=f"sbom:pkg:{ref_hash}",
                name=shown_name,
                version=clean_ver,
                registry_type=reg_type,
                package_url=clean_purl if reveal_names else None,
                hashes=hashes,
                assurance_level=AssuranceLevel.DECLARED,
                trust_tier=TrustTier.UNKNOWN,
                properties=props,
                claims=claims,
                risks=risks,
            )

        bom.components.append(comp)
        by_identity.setdefault(key_base, []).append(comp)
        summary.imported_count += 1

    # Ensure completeness reflects imported discovery (never complete!).
    limitation = f"foreign-sbom:{source_format}:{doc_sha256}"
    if bom.metadata.completeness is None:
        bom.metadata.completeness = CompletenessClaim(
            scope="sbom-imported",
            collectors_requested=[],
            collectors_completed=[],
            scanner_status={},
            scan_failures=list(local_failures),
            source_report_status="incomplete",
            source_projection_limitations=[limitation],
            unobserved_surfaces=["runtime", "network", "filesystem"],
        )
    else:
        if "sbom" not in bom.metadata.completeness.scope:
            bom.metadata.completeness.scope = f"{bom.metadata.completeness.scope}+sbom"
        existing_lims = list(bom.metadata.completeness.source_projection_limitations or [])
        if limitation not in existing_lims:
            existing_lims.append(limitation)
        bom.metadata.completeness.source_projection_limitations = existing_lims
        for fail in local_failures:
            if fail not in bom.metadata.completeness.scan_failures:
                bom.metadata.completeness.scan_failures.append(fail)

    return summary


def unread_shape_census(project_root: Path) -> list[UnreadShapeCount]:
    """Count unread non-control-plane artifact shapes below project_root (advisory by default)."""
    failures: list[str] = []
    counts: dict[str, int] = {
        "*.ipynb": 0,
        "n8n/*.json": 0,
        "*.tf": 0,
        "Chart.yaml": 0,
    }
    with ConfinedCollection(project_root, failures) as files:
        for rel in files.iter_files():
            posix = rel.as_posix()
            name = rel.name
            if name.endswith(".ipynb"):
                counts["*.ipynb"] += 1
            elif name.endswith(".tf"):
                counts["*.tf"] += 1
            elif name == "Chart.yaml":
                counts["Chart.yaml"] += 1
            elif name.endswith(".json") and ("n8n/" in posix or posix.startswith("workflows/")):
                raw = files.read_text(posix, missing_ok=True)
                if raw and '"nodes"' in raw and '"connections"' in raw:
                    counts["n8n/*.json"] += 1
    return [
        UnreadShapeCount(shape=shape, count=count)
        for shape, count in sorted(counts.items())
        if count > 0
    ]


def _parse_nested_manifest(
    rel_posix: str,
    text: str,
    sibling_names: set[str],
) -> list[RegistryEntryComponent]:
    name = Path(rel_posix).name
    parent_dir = str(Path(rel_posix).parent)
    prefix = "" if parent_dir == "." else f"{parent_dir}/"
    found: list[tuple[str, str | None, str, str]] = []

    if name == "package.json":
        parsed = parse_json_strict(text)
        if isinstance(parsed, dict):
            locked = any(
                f"{prefix}{lk}" in sibling_names
                for lk in (
                    "package-lock.json",
                    "npm-shrinkwrap.json",
                    "pnpm-lock.yaml",
                    "yarn.lock",
                )
            )
            pin_state = "locked" if locked else "manifest-only"
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                deps = parsed.get(section)
                if isinstance(deps, dict):
                    for pkg_name, spec in deps.items():
                        if (
                            isinstance(pkg_name, str)
                            and isinstance(spec, str)
                            and _is_ai_package_name(pkg_name)
                        ):
                            found.append((pkg_name, spec.strip(), "npm", pin_state))
    elif name.startswith("requirements") and name.endswith(".txt"):
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            try:
                req = Requirement(line)
            except InvalidRequirement:
                continue
            if _is_ai_package_name(req.name):
                spec_str = str(req.specifier) or None
                pin_state = "digest-pinned" if "--hash=" in raw_line else "manifest-only"
                found.append((req.name, spec_str, "pypi", pin_state))
    elif name == "pyproject.toml":
        parsed_toml = load_toml(text)
        locked = any(f"{prefix}{lk}" in sibling_names for lk in ("uv.lock", "poetry.lock"))
        pin_state = "locked" if locked else "manifest-only"
        proj = parsed_toml.get("project")
        if isinstance(proj, dict) and isinstance(proj.get("dependencies"), list):
            for item in proj["dependencies"]:
                if isinstance(item, str):
                    try:
                        req = Requirement(item)
                    except InvalidRequirement:
                        continue
                    if _is_ai_package_name(req.name):
                        found.append((req.name, str(req.specifier) or None, "pypi", pin_state))
    elif name == "setup.cfg":
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(text)
        if parser.has_option("options", "install_requires"):
            for line in parser.get("options", "install_requires").splitlines():
                cleaned = line.strip()
                if not cleaned:
                    continue
                try:
                    req = Requirement(cleaned)
                except InvalidRequirement:
                    continue
                if _is_ai_package_name(req.name):
                    found.append((req.name, str(req.specifier) or None, "pypi", "manifest-only"))
    elif name == "Cargo.toml":
        parsed_cargo = load_toml(text)
        locked = f"{prefix}Cargo.lock" in sibling_names
        pin_state = "locked" if locked else "manifest-only"
        for sec in ("dependencies", "dev-dependencies"):
            deps = parsed_cargo.get(sec)
            if isinstance(deps, dict):
                for crate, spec in deps.items():
                    if isinstance(crate, str) and _is_ai_package_name(crate):
                        ver = (
                            spec
                            if isinstance(spec, str)
                            else (
                                spec.get("version")
                                if isinstance(spec, dict) and isinstance(spec.get("version"), str)
                                else None
                            )
                        )
                        found.append((crate, ver, "cargo", pin_state))
    elif name == "go.mod":
        locked = f"{prefix}go.sum" in sibling_names
        pin_state = "locked" if locked else "manifest-only"
        for line in text.splitlines():
            parts = line.split("//", 1)[0].strip().split()
            if not parts:
                continue
            if parts[0] == "require" and len(parts) >= 3 and parts[1] != "(":
                mod, ver = parts[1], parts[2]
                if _is_ai_package_name(mod):
                    found.append((mod, ver, "golang", pin_state))
            elif len(parts) >= 2 and parts[0] not in {
                "module",
                "go",
                "require",
                "replace",
                "exclude",
                "retract",
                ")",
            }:
                mod, ver = parts[0], parts[1]
                if _is_ai_package_name(mod):
                    found.append((mod, ver, "golang", pin_state))
    elif name in {"environment.yml", "environment.yaml", "conda.yml", "conda.yaml"}:
        if len(text.encode("utf-8")) > MAX_MANIFEST_YAML_BYTES:
            raise ValueError("conda manifest exceeds size limit")
        if _yaml_flow_depth_exceeds(text):
            raise ValueError("conda manifest exceeds flow nesting limit")
        parsed_conda = yaml.safe_load(text)
        if isinstance(parsed_conda, dict) and isinstance(parsed_conda.get("dependencies"), list):
            for dep in parsed_conda["dependencies"]:
                if isinstance(dep, str):
                    pkg, _, ver = dep.partition("=")
                    if _is_ai_package_name(pkg):
                        found.append((pkg.strip(), ver.strip() or None, "conda", "manifest-only"))
    elif name == "devcontainer.json" or name == ".devcontainer.json":
        parsed_dev = parse_json_strict(text)
        if isinstance(parsed_dev, dict) and isinstance(parsed_dev.get("image"), str):
            img = parsed_dev["image"].strip()
            if _is_ai_package_name(img):
                pin_state = "digest-pinned" if "@sha256:" in img else "manifest-only"
                found.append((img, None, "oci", pin_state))

    out: list[RegistryEntryComponent] = []
    for pkg_name, spec, ecosystem, pin_state in found:
        clean_ver = spec.lstrip("=") if spec and spec.startswith("==") else spec
        exact = bool(clean_ver and _EXACT_VERSION_RE.fullmatch(clean_ver))
        seed = f"{rel_posix}:{ecosystem}:{pkg_name}"
        ref_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        out.append(
            RegistryEntryComponent(
                bom_ref=f"registry:nested:{ref_id}",
                name=neutralize(redact_text(pkg_name))[:200],
                version=neutralize(redact_text(clean_ver))[:128] if clean_ver else None,
                registry_type=ecosystem,
                source_path=rel_posix,
                assurance_level=AssuranceLevel.DECLARED,
                trust_tier=TrustTier.UNKNOWN,
                properties={
                    "pinning_state": pin_state,
                    "version_pinned": exact and pin_state != "manifest-only",
                },
                claims={
                    "manifest": ClaimEvidence(
                        assurance=AssuranceLevel.DECLARED,
                        method="nested-manifest-walk",
                        scope="dependency",
                        collector="registry",
                        locator=rel_posix,
                    )
                },
            )
        )
    return out


def walk_nested_manifests(project_root: Path) -> tuple[list[RegistryEntryComponent], list[str]]:
    """Walk manifests below project_root using ConfinedCollection (recording symlink & parse failures)."""
    failures: list[str] = []
    components: list[RegistryEntryComponent] = []
    with ConfinedCollection(project_root, failures) as files:
        all_paths = [p.as_posix() for p in files.iter_files()]
        path_set = set(all_paths)
        for posix in all_paths:
            # Root manifests are already owned by RegistryScanner's root pass except setup.cfg/go.mod/Cargo.toml/conda/devcontainer.
            rel = Path(posix)
            is_root = rel.parent == Path(".")
            name = rel.name
            if is_root and name in {"package.json", "pyproject.toml"}:
                continue
            if is_root and name.startswith("requirements") and name.endswith(".txt"):
                continue
            if not (
                name
                in {
                    "package.json",
                    "pyproject.toml",
                    "setup.cfg",
                    "Cargo.toml",
                    "go.mod",
                    "environment.yml",
                    "environment.yaml",
                    "conda.yml",
                    "conda.yaml",
                }
                or (name.startswith("requirements") and name.endswith(".txt"))
                or posix.endswith(".devcontainer/devcontainer.json")
                or posix == ".devcontainer.json"
            ):
                continue
            text = files.read_text(posix, missing_ok=True)
            if text is not None:
                try:
                    components.extend(_parse_nested_manifest(posix, text, path_set))
                except (
                    ValueError,
                    yaml.YAMLError,
                    configparser.Error,
                    RecursionError,
                ) as exc:
                    failures.append(
                        f"{neutralize(posix)}: manifest parse failed ({type(exc).__name__})"
                    )
    return components, failures


def classify_pinning_state(aibom: AIBOM) -> dict[str, str]:
    """Compute pinning_state ('digest-pinned', 'locked', 'pinned-version', 'manifest-only', 'unpinned') per server/package."""
    states: dict[str, str] = {}
    for comp in aibom.components:
        existing_prop = comp.properties.get("pinning_state")
        if isinstance(existing_prop, str):
            states[comp.bom_ref] = existing_prop
            continue
        if isinstance(comp, RegistryEntryComponent):
            if comp.hashes:
                state = "locked"
            elif comp.package_url or comp.properties.get("version_pinned") is True:
                state = "pinned-version"
            else:
                state = "manifest-only"
            comp.properties["pinning_state"] = state
            states[comp.bom_ref] = state
        elif isinstance(comp, MCPServerComponent):
            if comp.hashes:
                state = "digest-pinned"
            elif comp.version_pinned:
                state = "pinned-version"
            else:
                state = "unpinned"
            comp.properties["pinning_state"] = state
            states[comp.bom_ref] = state
    return states
