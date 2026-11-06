"""Offline registry references collected from bounded local manifests.

These declarations do not establish registry authenticity, resolved artifacts,
installed versions, or cryptographic verification.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import re
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import Specifier
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from nexus_symbiote.core.enums import AssuranceLevel, RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import extract_version_pin, hash_bytes, parse_json_strict
from nexus_symbiote.core.models import ClaimEvidence, RegistryEntryComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult, sanitized_origin
from nexus_symbiote.utils.secrets import redact_text, redact_url
from nexus_symbiote.utils.terminal import UNSAFE_TEXT

AI_PACKAGE_PATTERNS = [
    re.compile(r"(?:^|/)@modelcontextprotocol/", re.I),
    re.compile(r"(?:^|/)mcp[-_]", re.I),
    re.compile(r"(?:^|/)(?:langchain|llama[-_]index|crewai|autogen|openai|anthropic|cohere)", re.I),
    re.compile(r"(?:^|/)(?:transformers|torch|tensorflow|safetensors|tokenizers)", re.I),
    re.compile(r"(?:^|/)(?:chromadb|pinecone|qdrant|weaviate|pgvector|faiss)", re.I),
    re.compile(r"(?:^|/)(?:guardrails|nemo[-_]guardrails|rebuff)", re.I),
]


def _url_origin(url: str) -> str:
    # The parsed URL as one token: a pattern over the whole line stops at a quote
    # and would leave the rest of the path, query or a credential behind.
    return redact_url(url) if "//" in url else url


def _unparsed(text: str) -> str:
    """Text with no reliable URL boundary, kept only up to the word holding its first //.

    Words end at an ASCII space or tab, as in a PEP 508 URL; any other character,
    including a quote, @, / or another space, may still belong to the URL.
    """
    cut = text.find("//")
    if cut < 0:
        return redact_text(text)
    while cut and text[cut - 1] not in " \t":
        cut -= 1
    return redact_text(text[:cut]) + "[redacted-url]"


def _recorded(reference: str) -> str:
    """A requirement as the inventory records it, with a direct URL reduced to its origin."""
    if "//" not in reference:
        return redact_text(reference)
    try:
        requirement = Requirement(reference)
    except InvalidRequirement:
        return _unparsed(reference)
    if not requirement.url:
        # A // in a marker literal or an arbitrary-equality version.
        return _unparsed(reference)
    extras = f"[{','.join(sorted(requirement.extras))}]" if requirement.extras else ""
    text = f"{requirement.name}{extras} @ {_url_origin(requirement.url)}"
    if requirement.marker:
        text += f" ; {_unparsed(str(requirement.marker))}"
    return redact_text(text)


# Real versions are short. packaging re-parses a clause's version on every
# comparison, so a declaration with a longer one is recorded but not compared.
_LONGEST_VERSION = 128


def _parsed(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def _admits(clause: Specifier, text: str, version: Version | None) -> bool:
    """Whether a clause admits a pin, given as written and as parsed once."""
    if clause.operator == "===":
        # PEP 440 arbitrary equality compares the text, ignoring case; deciding it
        # here keeps the answer the same on every supported packaging release.
        return clause.version.lower() == text.lower()
    # Only arbitrary equality can name a version that is not PEP 440.
    return version is not None and clause.contains(version, prereleases=True)


class _Declared:
    """What a package's declarations under one set of markers require together.

    Pins are kept once per version and range clauses once each, so a declaration
    costs a pass over the ranges only when it brings a new pin, and pins that do
    not conflict with each other are few. With versions bounded in length, the
    work is linear in the size of the files read.
    """

    def __init__(self) -> None:
        self.pins: dict[object, tuple[Specifier, str, Version | None]] = {}
        self.ranges: set[Specifier] = set()
        self.origins: set[str] = set()
        self.plain = False

    def add(self, requirement: Requirement) -> bool:
        """Record a declaration; whether it cannot hold with an earlier one."""
        if requirement.url:
            # Only the origin is kept (paths and queries can carry credentials).
            origin = _url_origin(requirement.url)
            conflict = self.plain or bool(self.origins - {origin})
            self.origins.add(origin)
            return conflict
        clauses = list(requirement.specifier)
        if any(len(clause.version) > _LONGEST_VERSION for clause in clauses):
            return False
        conflict = bool(self.origins)
        self.plain = True
        exact = [c for c in clauses if c.operator in ("==", "===") and not c.version.endswith(".*")]
        pin = exact[0] if len(exact) == 1 else None
        for clause in clauses:
            if clause is pin or clause in self.ranges:
                continue
            if any(not _admits(clause, text, parsed) for _, text, parsed in self.pins.values()):
                conflict = True
            self.ranges.add(clause)
        if pin is not None:
            text, parsed = pin.version, _parsed(pin.version)
            key: object = (
                ("===", text.lower()) if pin.operator == "===" or parsed is None else parsed
            )
            if key not in self.pins:
                # Two pins conflict only when neither admits the other: ==2.3.0
                # admits the local build 2.3.0+cu121 that a lock file records.
                if any(
                    not (_admits(pin, known, known_parsed) or _admits(clause, text, parsed))
                    for clause, known, known_parsed in self.pins.values()
                ) or any(not _admits(clause, text, parsed) for clause in self.ranges):
                    conflict = True
                self.pins[key] = (pin, text, parsed)
        return conflict


class RegistryScanner(Scanner):
    name = "registry"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        with self._collection(project_root, result) as files:
            result.components.extend(self._scan_npm(files.root, result))
            result.components.extend(self._scan_pip(files.root, result))
            result.components.extend(self._scan_docker(files.root, result))
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("registry (no AI-related dependencies found)")
        return result

    def _read(self, path: Path, result: ScanResult) -> str | None:
        if self._files is None:
            raise RuntimeError("_read called outside a _collection context")
        content = self._files.read_text(path, missing_ok=True)
        if content is not None:
            result.surfaces_scanned.append(str(path))
        return content

    def _scan_npm(self, root: Path, result: ScanResult) -> list[RegistryEntryComponent]:
        if self._files is None:
            raise RuntimeError("_scan_npm called outside a _collection context")
        path = root / "package.json"
        data = self._files.read_json(path, missing_ok=True)
        if data is None:
            return []
        result.surfaces_scanned.append(str(path))
        if not isinstance(data, dict):
            result.scan_failures.append("package.json: expected an object")
            return []
        all_deps: dict[str, str] = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(key, {})
            if not isinstance(deps, dict) or not all(
                isinstance(value, str) for value in deps.values()
            ):
                result.scan_failures.append(f"package.json: invalid {key} map")
                continue
            all_deps.update(deps)
        # Parse and bind the same bounded bytes; a second open for hashing could
        # associate a swapped lockfile with a previously parsed resolution.
        lock_path = root / "package-lock.json"
        lock_bytes = self._files.read_bytes(lock_path, missing_ok=True)
        resolutions: dict[str, Any] = {}
        lock_digest = None
        if lock_bytes is not None:
            result.surfaces_scanned.append("package-lock.json")
            try:
                lock = parse_json_strict(lock_bytes)
                if (
                    not isinstance(lock, dict)
                    or not isinstance(lock.get("packages"), dict)
                    or (
                        lock.get("lockfileVersion") is not None
                        and (
                            type(lock["lockfileVersion"]) is not int
                            or lock["lockfileVersion"] not in (2, 3)
                        )
                    )
                ):
                    raise ValueError("unsupported npm lockfile structure")
                resolutions = lock["packages"]
                lock_digest = hash_bytes(lock_bytes)
            except (ValueError, TypeError, UnicodeError, RecursionError):
                result.scan_failures.append("package-lock.json: invalid or unsupported lockfile")
        components: list[RegistryEntryComponent] = []
        for raw_name, raw_spec in sorted(all_deps.items()):
            if not self._is_ai_package(raw_name):
                continue
            name, spec = redact_text(raw_name), redact_text(raw_spec)
            properties: dict[str, Any] = {
                "collection_mode": "manifest-reference",
                "registry_origin_verified": False,
                "requested_version": spec,
            }
            claims: dict[str, ClaimEvidence] = {}
            version = spec
            registry_origin = None
            source = str(path)
            key = "node_modules/" + raw_name
            record = resolutions.get(key)
            if record is not None:
                if not isinstance(record, dict):
                    result.scan_failures.append(
                        "package-lock.json: invalid selected package record"
                    )
                elif record.get("name", raw_name) != raw_name:
                    result.surfaces_excluded.append(
                        "package-lock.json: aliased package identity is unresolved"
                    )
                elif record.get("link") is True:
                    result.surfaces_excluded.append(
                        "package-lock.json: local link resolution is unverified"
                    )
                else:
                    resolved_version = record.get("version")
                    if (
                        isinstance(resolved_version, str)
                        and len(resolved_version) <= 128
                        and re.fullmatch(
                            r"\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
                            resolved_version,
                        )
                    ):
                        version = resolved_version
                    else:
                        result.scan_failures.append(
                            "package-lock.json: selected package lacks an exact version"
                        )
                    locator = "package-lock.json#/packages/" + key.replace("~", "~0").replace(
                        "/", "~1"
                    )
                    # Keep only source origin; paths, credentials and signed URLs
                    # are not needed to identify this declared registry reference.
                    url = record.get("resolved")
                    if isinstance(url, str) and url.startswith(("https://", "http://")):
                        origin = sanitized_origin(url)
                        registry_origin = origin if origin != "[redacted]" else None
                    properties.update(
                        {
                            "collection_mode": "lockfile-resolution-claim",
                            "lockfile_sha256": lock_digest,
                            "lockfile_record": locator,
                            "artifact_verified": False,
                        }
                    )
                    claims["package_resolution"] = ClaimEvidence(
                        assurance=AssuranceLevel.DECLARED,
                        method="npm-lockfile",
                        scope="dependency-resolution",
                        collector="registry",
                        locator=locator,
                    )
                    source = "package-lock.json"
                    integrity = record.get("integrity")
                    if integrity is not None:
                        try:
                            if not isinstance(integrity, str) or len(integrity) > 1024:
                                raise ValueError("invalid integrity")
                            algorithm, encoded = integrity.split("-", 1)
                            size = {"sha256": 32, "sha384": 48, "sha512": 64}.get(algorithm)
                            if (
                                size is None
                                or len(base64.b64decode(encoded, validate=True)) != size
                            ):
                                raise ValueError("invalid integrity")
                        except (ValueError, binascii.Error):
                            result.scan_failures.append(
                                "package-lock.json: invalid selected package integrity"
                            )
                        else:
                            properties["lockfile_integrity"] = integrity
            risks: list[RiskAssessment] = []
            if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?", raw_spec):
                risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.MEDIUM,
                        category="version_pinning",
                        detail=f"npm package '{name}' has a nonexact declared reference: {spec}",
                        recommendation="Resolve and verify an immutable artifact with lockfile integrity evidence.",
                    )
                )
            components.append(
                RegistryEntryComponent(
                    bom_ref=f"registry:npm/{name}",
                    name=name,
                    version=version,
                    package_url=(
                        f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='')}"
                        if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?", version)
                        else None
                    ),
                    registry_type="npm",
                    registry_uri=registry_origin,
                    source_path=source,
                    trust_tier=TrustTier.UNKNOWN,
                    assurance_level=AssuranceLevel.DECLARED,
                    risks=risks,
                    properties=properties,
                    claims=claims,
                )
            )
        return components

    def _pip_component(
        self, line: str, path: Path, result: ScanResult | None = None
    ) -> RegistryEntryComponent | None:
        reference = line.strip().split(" #", 1)[0].strip()
        match = re.match(r"^([a-zA-Z0-9_.-]+)", reference)
        if not match or not self._is_ai_package(match.group(1)):
            return None
        name = str(canonicalize_name(match.group(1)))
        invalid = False
        try:
            requirement = Requirement(reference)
        except InvalidRequirement:
            invalid = True
            spec = _unparsed(reference[len(match.group(1)) :].strip())
            if result is not None:
                result.scan_failures.append(f"{path.name}: invalid or unsupported PyPI requirement")
        else:
            name = str(canonicalize_name(requirement.name))
            # Retain markers and URLs as declared, unresolved conditions; they
            # must not silently turn into an unconditional exact package URL.
            if requirement.url:
                spec = "@ " + _url_origin(requirement.url)
            else:
                spec = _unparsed(str(requirement.specifier))
            if requirement.marker:
                spec += "; " + _unparsed(str(requirement.marker))
            spec = redact_text(spec)
        version = extract_version_pin(reference, ecosystem="python") if not invalid else None
        risks = (
            []
            if version is not None
            else [
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="version_pinning",
                    detail=f"PyPI package '{name}' has an unresolved or nonexact declared reference.",
                    recommendation="Resolve the declared conditions, pin the version and verify artifact hashes.",
                )
            ]
        )
        return RegistryEntryComponent(
            bom_ref=f"registry:pypi/{name}",
            name=name,
            version=spec or None,
            package_url=(
                f"pkg:pypi/{quote(name, safe='')}@{quote(version, safe='')}"
                if version is not None
                else None
            ),
            registry_type="pypi",
            registry_uri="https://pypi.org",
            source_path=str(path),
            trust_tier=TrustTier.UNKNOWN,
            risks=risks,
            properties={
                "collection_mode": "manifest-reference",
                "registry_origin_verified": False,
                "requested_requirement": _recorded(reference),
            },
        )

    _COMMENT = re.compile(r"(?:^|\s)#.*$")

    def _requirement_files(self) -> list[str]:
        if self._files is None:
            raise RuntimeError("_requirement_files called outside a _collection context")
        # Without regard to case, as a fixed-name open is on macOS and Windows file
        # systems. The exact name, which pip reads on a case-sensitive system, comes
        # first, then its case variants, then the other files.
        names = [
            n
            for n in self._files.root_entries()
            if fnmatch.fnmatchcase(n.casefold(), "requirements*.txt")
        ]
        return sorted(
            names,
            key=lambda n: (n.casefold() != "requirements.txt", n != "requirements.txt", n),
        )

    @staticmethod
    def _requirement_lines(content: str) -> list[str]:
        """Logical lines as pip's join_lines builds them.

        A trailing backslash continues a line and the parts are joined with nothing
        in between, so a URL or version wrapped mid-token reads as pip reads it.
        """
        lines: list[str] = []
        pending: list[str] = []
        for raw in content.removeprefix("\ufeff").splitlines():
            comment = raw.lstrip().startswith("#")
            if raw.endswith("\\") and not comment:
                pending.append(raw.strip("\\"))
                continue
            if pending:
                pending.append(" " + raw if comment else raw)
                lines.append("".join(pending))
                pending = []
            else:
                lines.append(raw)
        if pending:
            lines.append("".join(pending))
        return lines

    def _scan_pip(self, root: Path, result: ScanResult) -> list[RegistryEntryComponent]:
        components: list[RegistryEntryComponent] = []
        kept: dict[str, RegistryEntryComponent] = {}
        sources: dict[str, set[str]] = {}
        seen: dict[str, set[str]] = {}
        declared: dict[str, dict[tuple[str, str], _Declared]] = {}
        conflicted: set[str] = set()

        def declare(
            component: RegistryEntryComponent, source: str, reference: str, group: str = ""
        ) -> None:
            # One component per package across manifests. Every declaration is kept
            # on it, so a change to any of them changes the inventory and its diff.
            ref = component.bom_ref
            sources.setdefault(ref, set()).add(f"{source}: {_recorded(reference)}")
            first = kept.get(ref)
            if first is None:
                kept[ref] = component
                components.append(component)
            if ref in conflicted or reference in seen.setdefault(ref, set()):
                return
            seen[ref].add(reference)
            try:
                requirement = Requirement(reference)
            except InvalidRequirement:
                # Already a collection failure; there is nothing reliable to compare.
                return
            # Declarations under different markers apply to different environments
            # (uv writes platform splits that way), and so do different optional-
            # dependency groups (uv's cpu and cu121 extras), so only equal ones are
            # compared.
            marker = str(requirement.marker) if requirement.marker else ""
            state = declared.setdefault(ref, {}).setdefault((marker, group), _Declared())
            if state.add(requirement) and first is not None:
                conflicted.add(ref)
                detail = (
                    f"PyPI package '{first.name}' is declared more than once with "
                    "requirements that conflict."
                )
                first.risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.MEDIUM,
                        category="version_pinning",
                        detail=detail,
                        recommendation="Check that each declaration is intended, make them agree where possible, and verify artifact hashes.",
                    )
                )

        self._scan_requirements(root, result, declare)
        path = root / "pyproject.toml"
        for declaration, group in self._pyproject_declarations(path, result):
            component = self._pip_component(declaration, path, result)
            if component:
                # Compare the text _pip_component parsed, without a trailing comment.
                reference = declaration.strip().split(" #", 1)[0].strip()
                declare(component, "pyproject.toml", reference, group)
        for component in components:
            if len(sources[component.bom_ref]) > 1:
                component.properties["declarations"] = sorted(sources[component.bom_ref])
        return components

    def _scan_requirements(
        self,
        root: Path,
        result: ScanResult,
        declare: Callable[[RegistryEntryComponent, str, str], None],
    ) -> None:
        filenames = self._requirement_files()
        for filename in filenames:
            if (
                UNSAFE_TEXT.search(filename)
                or "\t" in filename
                or any("\ud800" <= c <= "\udfff" for c in filename)
            ):
                # Undecodable bytes (lone surrogates) cannot be carried in the inventory
                # or its exports, and controls or format characters disguise output, so
                # the file is a gap, not data. A fixed list, unlike str.isprintable(),
                # gives the same answer on every supported Python.
                failure = "requirements file with an unprintable name: not read"
                if failure not in result.scan_failures:
                    result.scan_failures.append(failure)
                continue
            path = root / filename
            content = self._read(path, result)
            if content is None:
                continue
            for line in self._requirement_lines(content):
                text = self._COMMENT.sub("", line).strip()
                if not text:
                    continue
                if text.startswith("-"):
                    # Option lines (includes, editable installs, index options) are not
                    # followed; the README states this limit.
                    continue
                # Per-requirement options such as --hash follow the requirement itself.
                words: list[str] = []
                # pip splits options on spaces only, so a tab or another space
                # character stays inside the requirement.
                for word in (w for w in text.split(" ") if w):
                    if word.startswith("-"):
                        break
                    words.append(word)
                reference = " ".join(words)
                component = self._pip_component(reference, path, result)
                if component is not None:
                    declare(component, filename, reference)

    def _pyproject_declarations(self, path: Path, result: ScanResult) -> list[tuple[str, str]]:
        """Each declaration with its optional-dependency group ("" for none)."""
        content = self._read(path, result)
        if content is None:
            return []
        try:
            data = tomllib.loads(content)
        except (tomllib.TOMLDecodeError, RecursionError):
            result.scan_failures.append("pyproject.toml: invalid TOML")
            return []
        declarations: list[tuple[str, str]] = []
        project = data.get("project", {})
        if not isinstance(project, dict):
            result.scan_failures.append("pyproject.toml: invalid project table")
            return []
        deps = project.get("dependencies", [])
        if isinstance(deps, list) and all(isinstance(value, str) for value in deps):
            declarations.extend((value, "") for value in deps)
        else:
            result.scan_failures.append("pyproject.toml: invalid project dependencies")
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for extra, values in optional.items():
                if isinstance(values, list) and all(isinstance(value, str) for value in values):
                    declarations.extend((value, str(extra)) for value in values)
                else:
                    result.scan_failures.append("pyproject.toml: invalid optional dependencies")
        tool = data.get("tool", {})
        poetry: Any = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        poetry_deps = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
        if isinstance(poetry_deps, dict):
            for name, value in poetry_deps.items():
                if isinstance(value, str):
                    declarations.append((f"{name}{value}", ""))
                elif isinstance(value, dict) and isinstance(value.get("version"), str):
                    declarations.append((f"{name}{value['version']}", ""))
        return declarations

    def _scan_docker(self, root: Path, result: ScanResult) -> list[RegistryEntryComponent]:
        components: list[RegistryEntryComponent] = []
        for filename in (
            "Dockerfile",
            "Dockerfile.agent",
            "docker-compose.yml",
            "docker-compose.yaml",
        ):
            path = root / filename
            content = self._read(path, result)
            if content is None:
                continue
            # One whitespace quantifier only: two adjacent ones backtrack quadratically
            # when a file ends in "image:" followed by a long run of whitespace.
            for raw_image in re.findall(r"(?:FROM|image:)\s*([^\s]+)", content):
                if not any(
                    word in raw_image.lower()
                    for word in ("vllm", "ollama", "triton", "tgi", "llama", "model")
                ):
                    continue
                image = redact_text(raw_image)
                has_digest = bool(re.search(r"@sha256:[0-9a-fA-F]{64}$", raw_image))
                has_tag = ":" in raw_image.rsplit("/", 1)[-1] and not raw_image.endswith(":latest")
                risks: list[RiskAssessment] = []
                if not has_digest:
                    risks.append(
                        RiskAssessment(
                            severity=RiskSeverity.MEDIUM if has_tag else RiskSeverity.HIGH,
                            category="mutable_image_tag" if has_tag else "version_pinning",
                            detail=f"Docker image '{image}' lacks an immutable digest pin.",
                            recommendation="Pin to a SHA256 artifact digest and verify its provenance.",
                        )
                    )
                components.append(
                    RegistryEntryComponent(
                        bom_ref=f"registry:docker/{image}",
                        name=image,
                        registry_type="docker-hub",
                        source_path=str(path),
                        trust_tier=TrustTier.UNKNOWN,
                        risks=risks,
                        properties={
                            "collection_mode": "manifest-reference",
                            "registry_origin_verified": False,
                        },
                    )
                )
        return components

    @staticmethod
    def _conflict(one: str, other: str) -> bool:
        """Whether two declarations of a package conflict, as the collector decides it.

        Only declarations under the same markers are compared, and the extras a
        requirement names are not.
        A range and a pin that satisfies it, as pip-tools, uv and lock files write
        them, do not conflict; two ranges are not compared.
        """
        try:
            first, second = Requirement(one), Requirement(other)
        except InvalidRequirement:
            return False
        if str(first.marker or "") != str(second.marker or ""):
            return False
        state = _Declared()
        state.add(first)
        return state.add(second)

    def _is_ai_package(self, name: str) -> bool:
        return any(pattern.search(name) for pattern in AI_PACKAGE_PATTERNS)
