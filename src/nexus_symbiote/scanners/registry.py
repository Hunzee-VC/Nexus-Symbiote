"""Offline registry references collected from bounded local manifests.

These declarations do not establish registry authenticity, resolved artifacts,
installed versions, or cryptographic verification.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import re
import shlex
import tomllib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote

from packaging.markers import InvalidMarker, Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, Specifier
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
# All root requirements*.txt files together, in characters.
_REQUIREMENTS_BUDGET = 4 * 1024 * 1024


def _parsed(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


_POETRY_RANGE = re.compile(r"([\^~])[ \t]*([0-9]{1,64})(?:\.([0-9]{1,64}))?(?:\.([0-9]{1,64}))?")
# The characters of Poetry's constraint grammar. A constraint made only of them
# that is not translated is a condition left out; anything else is invalid.
_POETRY_CONSTRAINT = re.compile(r"[0-9A-Za-z.*+!_^~=<>|, \t-]*")
_PEP508_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_PLATFORM = re.compile(r"[A-Za-z0-9_.-]+")


def _poetry_specifier(text: str) -> str | None:
    """A Poetry version constraint as a PEP 440 specifier set, or None if not translated.

    A bare version is exact; ^ allows changes that keep the first non-zero part
    given, and ~ changes below the minor part, or below the major part if it is
    the only one given.
    """
    text = text.strip()
    if text in ("", "*"):
        return ""
    clauses: list[str] = []
    for part in (p.strip() for p in text.split(",")):
        ranged = _POETRY_RANGE.fullmatch(part)
        if ranged is not None:
            given = [g for g in ranged.groups()[1:] if g is not None]
            numbers = [int(g) for g in given]
            if ranged.group(1) == "~":
                bump = min(1, len(numbers) - 1)
            else:
                bump = next((i for i, n in enumerate(numbers) if n), len(numbers) - 1)
            upper = [*numbers[:bump], numbers[bump] + 1]
            clauses += [f">={'.'.join(given)}", f"<{'.'.join(map(str, upper))}"]
            continue
        if "0" <= part[:1] <= "9":
            part = "==" + part
        elif part[:1] == "=" and part[1:2] != "=":
            part = "=" + part
        try:
            Specifier(part)
        except InvalidSpecifier:
            return None
        clauses.append(part)
    return ",".join(clauses)


def _valid_marker(text: str) -> bool:
    try:
        Marker(text)
    except (InvalidMarker, RecursionError):
        return False
    return True


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
    # The options pip accepts in a requirements file that add or constrain packages.
    _PACKAGE_OPTIONS = {
        "--requirement": "requirements include not followed",
        "--constraint": "constraints file not followed",
        "--editable": "editable install not followed",
    }
    # Every option pip 26.3 accepts in a requirements file, and whether it takes a value.
    _PIP_OPTIONS = {
        "--index-url": True,
        "--pypi-url": True,
        "--extra-index-url": True,
        "--no-index": False,
        "--constraint": True,
        "--requirement": True,
        "--editable": True,
        "--find-links": True,
        "--no-binary": True,
        "--only-binary": True,
        "--prefer-binary": False,
        "--require-hashes": False,
        "--no-require-hashes": False,
        "--pre": False,
        "--all-releases": True,
        "--only-final": True,
        "--trusted-host": True,
        "--use-feature": True,
        "--hash": True,
        "--config-settings": True,
    }
    _SHORT_OPTIONS = {
        "i": "--index-url",
        "c": "--constraint",
        "r": "--requirement",
        "e": "--editable",
        "f": "--find-links",
        "C": "--config-settings",
    }
    # shlex's whitespace; str.split() would also split on a no-break space.
    _SHLEX_SPACE = re.compile(r"[ \t\r\n]+")
    # pip replaces ${NAME} with the environment variable before it reads a line.
    _ENV_VAR = re.compile(r"\$\{[A-Z0-9_]+\}")
    _ENV_NAME = re.compile(r"[A-Za-z0-9_.-]*\$\{[A-Z0-9_]+\}")
    # pip decodes a file without a byte order mark by the PEP 263 declaration in its
    # first two lines.
    _CODING = re.compile(r"coding[:=]\s*([-\w.]+)", re.ASCII)
    # A URL scheme as urlsplit finds one, after it drops leading C0 controls and spaces
    # and every tab, CR and LF. Any scheme, not only pip's: no PEP 508 name has one.
    _URL_SCHEME = re.compile(r"[\x00-\x20]*[A-Za-z0-9+.-]+:")
    _URL_DROPPED = dict.fromkeys(map(ord, "\t\r\n"))
    # "name @ URL", which pip reads by its name.
    _NAMED_URL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*[ \t]*(?:\[[^\]/\\]*\][ \t]*)?@")
    # pip 26.3's archive extensions.
    _ARCHIVES = (
        ".zip",
        ".whl",
        ".tar.bz2",
        ".tbz",
        ".tar.gz",
        ".tgz",
        ".tar",
        ".tar.xz",
        ".txz",
        ".tlz",
        ".tar.lz",
        ".tar.lzma",
    )

    @staticmethod
    def _requirement_files(entries: list[str]) -> list[str]:
        # Without regard to case, as a fixed-name open is on macOS and Windows file
        # systems. The exact name, which pip reads on a case-sensitive system, comes
        # first, then its case variants, then the other files.
        names = [n for n in entries if fnmatch.fnmatchcase(n.casefold(), "requirements*.txt")]
        return sorted(
            names,
            key=lambda n: (n.casefold() != "requirements.txt", n != "requirements.txt", n),
        )

    @classmethod
    def _options(cls, text: str) -> tuple[list[tuple[str, str]], list[str]]:
        """The options pip reads from option words, with their values, and what it
        may read that is not known.

        pip splits the words with shlex and parses them with optparse, so one line
        can hold several options, and "-rX", "-r X", "--requirement=X" and an
        unambiguous prefix of a long name all apply. An option that takes a value
        takes the next word, even "--". An option pip 26.3 does not know may take
        one in another pip.
        """
        try:
            words = (
                shlex.split(text)
                if any(c in text for c in "\"'\\")
                else [w for w in cls._SHLEX_SPACE.split(text) if w]
            )
        except ValueError:
            return [], ["option line not parsed"]
        options: list[tuple[str, str]] = []
        problems: list[str] = []
        index = 0
        while index < len(words):
            word = words[index]
            index += 1
            if word == "--":
                # optparse leaves the rest as arguments, which pip ignores.
                break
            if not word.startswith("-") or word == "-":
                if cls._ENV_VAR.search(word):
                    # An ignored argument, unless the variable holds an option.
                    problems.append("environment variable not resolved")
                continue
            if word.startswith("--"):
                name, equals, value = word.partition("=")
                found = [o for o in cls._PIP_OPTIONS if o.startswith(name)]
                if name in cls._PIP_OPTIONS:
                    found = [name]
                option = found[0] if len(found) == 1 else None
                attached = bool(equals)
            else:
                option = cls._SHORT_OPTIONS.get(word[1])
                value, attached = word[2:], len(word) > 2
            if option is None:
                variable = cls._ENV_VAR.search(word.partition("=")[0])
                problems.append(
                    "environment variable not resolved" if variable else "option line not parsed"
                )
                continue
            if cls._PIP_OPTIONS[option] and not attached:
                value = words[index] if index < len(words) else ""
                index += 1
            options.append((option, value))
        return options, problems

    @classmethod
    def _option_gaps(cls, text: str, names: set[str], entries: set[str]) -> list[str]:
        """What an option line adds or pins that the collector does not read.

        The gap never names the target, which can be a URL carrying a credential.
        """
        options, gaps = cls._options(text)
        for option, value in options:
            gap = cls._PACKAGE_OPTIONS.get(option)
            if gap is None:
                continue
            covered = (
                cls._editable_covered(value, entries)
                if option == "--editable"
                else cls._include_covered(value, names)
            )
            if not covered:
                gaps.append(gap)
        return gaps

    @staticmethod
    def _include_covered(target: str, names: set[str]) -> bool:
        """Whether -r or -c names a root requirements file the collector reads."""
        parts = [part for part in target.split("/") if part not in ("", ".")]
        return (
            len(parts) == 1
            and not target.startswith("/")
            # A separator on Windows and a name character elsewhere; pip expands
            # ${VAR} from the environment.
            and not any(c in target for c in "\\$")
            and parts[0].casefold() in names
        )

    @staticmethod
    def _editable_covered(target: str, entries: set[str]) -> bool:
        """Whether -e installs the project itself, whose pyproject.toml is read."""
        # One trailing extras group, as pip strips it from a local path.
        match = re.fullmatch(r"([^\[\]]+)(?:\[[^\[\]]+\])?", target)
        if match is None:
            return False
        path = match.group(1)
        if path[:5].lower() == "file:":
            # pip installs a directory with that name instead, if there is one.
            if path.split("/", 1)[0].casefold() in entries:
                return False
            path = path[5:]
        return (
            bool(path)
            and not path.startswith("/")
            and all(part in ("", ".") for part in path.split("/"))
        )

    @classmethod
    def _unnamed(cls, reference: str, entries: set[str]) -> bool:
        """Whether pip installs a requirement from a URL, an archive or a path other
        than the project itself, where the collector reads no package name.

        pip 26.3 takes a URL by its scheme, then a path with a separator or a leading
        ".", then a name ending in an archive extension; only then a PEP 508
        requirement. Whether such a directory or file exists is known only where pip
        runs, so it is taken to exist.
        """
        named = cls._NAMED_URL.match(reference) is not None
        url = not named and cls._URL_SCHEME.match(reference.translate(cls._URL_DROPPED))
        # pip's marker separator, which a URL may contain without a space.
        target = reference.split("; " if url else ";", 1)[0].strip()
        if named:
            return cls._shadowed(target, entries)
        if not (
            url
            or any(c in target for c in "/\\")
            or target.startswith(".")
            or re.sub(r"\[[^\]]+\]$", "", target).lower().endswith(cls._ARCHIVES)
        ):
            return False
        # pip takes extras off a path but not off a URL: "file:.[dev]" is a directory
        # named ".[dev]".
        return bool(url and "[" in target) or not cls._editable_covered(target, entries)

    @staticmethod
    def _shadowed(target: str, entries: set[str]) -> bool:
        """Whether pip may install "name @ URL" from a path instead.

        pip first reads the whole text as a relative path, normalised without looking
        at the file system, and installs a directory or archive found there. That
        path can exist where pip runs only if it leaves the project root or starts
        with an entry of it.
        """
        parts: list[str] = []
        for part in re.split(r"[/\\]", re.sub(r"\[[^\]]+\]$", "", target)):
            if part == "..":
                if not parts:
                    return True
                parts.pop()
            elif part not in ("", "."):
                parts.append(part)
        return bool(parts) and parts[0].casefold() in entries

    # Python's names for UTF-8, lower case with "-" as "_".
    _UTF8_NAMES = frozenset({"utf_8", "utf8", "u8", "utf", "cp65001", "utf_8_sig"})

    @classmethod
    def _declares_other_encoding(cls, content: str) -> bool:
        """Whether pip decodes the file by a PEP 263 declaration of another encoding."""
        if content.startswith("\ufeff"):
            return False
        for line in content.split("\n", 2)[:2]:
            match = cls._CODING.search(line) if line.startswith("#") else None
            if match is not None:
                return match.group(1).lower().replace("-", "_") not in cls._UTF8_NAMES
        return False

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
        if self._files is None:
            raise RuntimeError("_scan_requirements called outside a _collection context")
        entries = self._files.root_entries()
        filenames = self._requirement_files(entries)
        names = {n.casefold() for n in filenames}
        folded = {n.casefold() for n in entries}
        noted: set[str] = set()
        unprintable = False
        remaining = _REQUIREMENTS_BUDGET
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
                if not unprintable:
                    result.scan_failures.append(
                        "requirements file with an unprintable name: not read"
                    )
                    unprintable = True
                continue
            path = root / filename
            content = self._read(path, result)
            if content is None:
                continue
            remaining -= len(content)
            if remaining < 0:
                # Every root requirements file is read, so their parsing time must be
                # bounded together; what does not fit is a coverage gap.
                result.scan_failures.append(
                    "requirements files exceed the combined size limit: the rest were not read"
                )
                break
            if self._declares_other_encoding(content):
                # pip would decode other text than the UTF-8 read here.
                result.scan_failures.append(
                    f"{filename}: declared encoding other than UTF-8: not read"
                )
                continue
            for line in self._requirement_lines(content):
                text = self._COMMENT.sub("", line).strip()
                if not text:
                    continue
                gaps: list[str] = []
                if text.startswith("-"):
                    # Includes, constraints and editable installs are not followed. One
                    # that reaches beyond what is read here is a coverage gap; index
                    # options add no package.
                    gaps = self._option_gaps(text, names, folded)
                else:
                    # Per-requirement options such as --hash follow the requirement
                    # itself. pip splits them off on spaces only, so a tab or another
                    # space character stays inside the requirement.
                    tokens = text.split(" ")
                    split = next(
                        (i for i, t in enumerate(tokens) if t.startswith("-")), len(tokens)
                    )
                    # pip reads the words before them as written, with the empty
                    # words two spaces leave.
                    args = " ".join(tokens[:split])
                    reference = " ".join(t for t in tokens[:split] if t)
                    options, _ = self._options(" ".join(tokens[split:]))
                    if self._ENV_NAME.match(reference):
                        # The variable can make the line any package, or an option.
                        gaps = ["environment variable not resolved"]
                    else:
                        if any(o == "--editable" for o, _ in options) and not (
                            self._editable_covered(reference, folded)
                        ):
                            # pip installs the requirement itself as editable.
                            gaps = ["editable install not followed"]
                        elif self._unnamed(args, folded):
                            # The gap never names the reference, which can carry a
                            # credential.
                            gaps = ["URL, VCS or path requirement not followed"]
                        component = self._pip_component(reference, path, result)
                        if component is not None:
                            declare(component, filename, reference)
                for gap in gaps:
                    message = f"{filename}: {gap}"
                    if message not in noted:
                        noted.add(message)
                        result.surfaces_excluded.append(message)

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
        if not isinstance(poetry, dict):
            result.scan_failures.append(self._POETRY_PROBLEMS["table"])
            return declarations
        failures: dict[str, None] = {}
        gaps: dict[str, None] = {}
        # The legacy dev-dependencies table is Poetry's dev group. Group labels keep
        # main and group declarations from being compared with each other.
        tables: list[tuple[str, Any]] = [
            ("", poetry.get("dependencies", {})),
            ("poetry:group:dev", poetry.get("dev-dependencies", {})),
        ]
        groups = poetry.get("group", {})
        if not isinstance(groups, dict):
            failures[self._POETRY_PROBLEMS["table"]] = None
            groups = {}
        for group_name, group in groups.items():
            dependencies = group.get("dependencies", {}) if isinstance(group, dict) else None
            tables.append((f"poetry:group:{group_name}", dependencies))
        for group_label, table in tables:
            if not isinstance(table, dict):
                failures[self._POETRY_PROBLEMS["table"]] = None
                continue
            for name, value in table.items():
                if not self._is_ai_package(name):
                    continue
                if not _PEP508_NAME.fullmatch(name):
                    failures[self._POETRY_PROBLEMS["invalid"]] = None
                    continue
                for entry in value if isinstance(value, list) and value else [value]:
                    text, problem = self._poetry_requirement(name, entry)
                    if problem is None:
                        declarations.append((text, group_label))
                        continue
                    # The bare name, never compared: what it leaves out is unknown.
                    declarations.append((name, "poetry:untranslated"))
                    record = failures if problem == "invalid" else gaps
                    record[self._POETRY_PROBLEMS[problem]] = None
        result.scan_failures.extend(failures)
        result.surfaces_excluded.extend(gaps)
        return declarations

    _POETRY_PROBLEMS = {
        "table": "pyproject.toml: invalid Poetry dependencies",
        "invalid": "pyproject.toml: invalid or unsupported Poetry dependency",
        "source": "pyproject.toml: Poetry git, path or URL dependency not translated",
        "index": "pyproject.toml: Poetry dependency from a source other than PyPI not translated",
        "condition": "pyproject.toml: Poetry dependency condition not translated",
    }

    @staticmethod
    def _poetry_requirement(name: str, entry: Any) -> tuple[str, str | None]:
        """One Poetry declaration as PEP 508 text, or the bare name and why it is not.

        A version, extras, markers and platform are translated. A git, path or URL
        source, a package source other than PyPI and a python restriction are left
        out, and so is a constraint that does not translate, such as a || union.
        """
        if isinstance(entry, str):
            entry = {"version": entry}
        if not isinstance(entry, dict):
            return name, "invalid"
        if any(key in entry for key in ("git", "path", "url", "file")):
            return name, "source"
        source = entry.get("source", "pypi")
        if not isinstance(source, str):
            return name, "invalid"
        if source.lower() != "pypi":
            # Not a PyPI package, though it may share a name with one.
            return name, "index"
        version = entry.get("version", "*")
        extras = entry.get("extras", [])
        markers = entry.get("markers")
        platform = entry.get("platform")
        if (
            not isinstance(version, str)
            or not isinstance(extras, list)
            or not all(isinstance(e, str) and _PEP508_NAME.fullmatch(e) for e in extras)
            or not (markers is None or (isinstance(markers, str) and _valid_marker(markers)))
            or not (
                platform is None or (isinstance(platform, str) and _PLATFORM.fullmatch(platform))
            )
        ):
            return name, "invalid"
        if "python" in entry:
            return name, "condition"
        specifier = _poetry_specifier(version)
        if specifier is None:
            return name, "condition" if _POETRY_CONSTRAINT.fullmatch(version) else "invalid"
        conditions = [markers] if markers else []
        if platform:
            conditions.append(f'sys_platform == "{platform}"')
        text = name + (f"[{','.join(extras)}]" if extras else "") + specifier
        if len(conditions) == 1:
            text += f" ; {conditions[0]}"
        elif conditions:
            text += " ; " + " and ".join(f"({c})" for c in conditions)
        return text, None

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
            if filename.startswith("Dockerfile"):
                images, gaps = self._dockerfile_images(content)
                result.surfaces_excluded.extend(f"{filename}: {gap}" for gap in gaps)
            else:
                # One whitespace quantifier only: two adjacent ones backtrack quadratically
                # when a file ends in "image:" followed by a long run of whitespace.
                images = re.findall(r"(?:FROM|image:)\s*([^\s]+)", content)
            for raw_image in images:
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

    # BuildKit's word separators; a no-break space is part of a word.
    _DOCKER_WORD = re.compile(r"[^\t\v\f\r ]+")
    # Go's unicode.IsSpace, which BuildKit trims lines with and splits shell words on;
    # str.strip() would also take \x1c-\x1f.
    _GO_SPACE = (
        "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008"
        "\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
    )
    # Go's \s, which has no \v.
    _DOCKER_DIRECTIVE = re.compile(
        r"#[\t\n\f\r ]*([A-Za-z][A-Za-z0-9]*)[\t\n\f\r ]*=[\t\n\f\r ]*(.+?)[\t\n\f\r ]*"
    )
    # A heredoc word: an optional descriptor, <<, an optional - and the terminator.
    _HEREDOC = re.compile(r"[0-9]*<<(-?)[\t\n\f\r ]*([^<]*)")
    # The substitutions BuildKit's lexer keeps as written when no variable is set.
    # The others can move word boundaries or fail the line.
    _DOLLAR = r"\$(?:\{(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[-@*#?$!])\}|(?!\{))"
    _SHELL_TOKEN = re.compile(
        f"(?P<space>[{_GO_SPACE}]+)"
        f"|(?P<plain>[^{_GO_SPACE}'\"$<\\\\]+|<(?!<))"
        r"|(?P<heredoc><<[\t\r ]*)"
        r"|(?P<single>'[^']*')"
        rf'|(?P<double>"(?:[^"\\$]|\\[\s\S]|{_DOLLAR})*")'
        rf"|(?P<dollar>{_DOLLAR})"
        r"|(?P<escape>\\[\s\S]?)"
    )
    _QUOTED_ESCAPE = re.compile(r'\\([\\"$])')

    @classmethod
    def _dockerfile_images(cls, content: str) -> tuple[list[str], list[str]]:
        """Images named by FROM instructions, as written, and what was not collected.

        The file is read as BuildKit reads it: a trailing backslash continues an
        instruction and comment lines are dropped, even inside one; the lines of a
        heredoc are its body, not instructions; the instruction word is
        case-insensitive; --flag words come before the image; and a FROM naming an
        earlier stage is not an image. Each line is handled once.
        """
        lines = content.removeprefix("\ufeff").split("\n")
        for line in lines:
            directive = cls._DOCKER_DIRECTIVE.fullmatch(line.rstrip("\r").lstrip(cls._GO_SPACE))
            if directive is None:
                break
            if directive.group(1).lower() == "escape" and directive.group(2) != "\\":
                # Another escape character changes where instructions end.
                return [], ["escape parser directive not followed"]
        images: list[str] = []
        gaps: list[str] = []
        stages: set[str] = set()
        for joined in cls._dockerfile_instructions(lines, gaps):
            # BuildKit trims the arguments too: a trailing no-break space is not part
            # of the image, and "latest\xa0" is still the latest tag.
            line = joined.rstrip(cls._GO_SPACE)
            instruction = cls._DOCKER_WORD.match(line)
            if instruction is None or cls._command(instruction.group()) != "from":
                continue
            words = cls._DOCKER_WORD.findall(line, instruction.end())
            start = 0
            while start < len(words) and words[start].startswith("--"):
                start += 1
            if start == len(words) or any(c in w for w in words[:start] for c in "\"'\\"):
                # No image, or a quoted or escaped flag whose end is not certain.
                gaps.append("FROM instruction not parsed")
                continue
            image, rest = words[start], words[start + 1 :]
            if image.lower() not in stages:
                if "$" in image:
                    gaps.append("FROM image substitution not resolved")
                if any(c in image for c in "\"'\\"):
                    # BuildKit's lexer removes them, so the image pulled is another word.
                    gaps.append("FROM image quoting not resolved")
                images.append(image)
            if len(rest) == 2 and rest[0].lower() == "as":
                stages.add(rest[1].lower())
        return images, list(dict.fromkeys(gaps))

    @staticmethod
    def _command(word: str) -> str:
        # As Go's strings.ToLower does; str.lower() makes U+0130 two characters.
        return word.replace("\u0130", "i").lower()

    @classmethod
    def _dockerfile_instructions(cls, lines: list[str], gaps: list[str]) -> Iterator[str]:
        """Instructions as BuildKit joins their lines, without comment, empty or heredoc lines."""
        index = 0
        while index < len(lines):
            parts: list[str] = []
            while index < len(lines):
                line = lines[index].rstrip("\r")
                index += 1
                stripped = line.lstrip(cls._GO_SPACE)
                if not stripped or stripped.startswith("#"):
                    continue
                body = line if parts else stripped
                trimmed = body.rstrip(" \t")
                # One backslash continues the line; an escaped one does not.
                if not trimmed.endswith("\\") or trimmed.endswith("\\\\"):
                    parts.append(body)
                    break
                parts.append(trimmed[:-1])
            if not parts:
                return
            # BuildKit trims the joined line, which keeps a continuation line's
            # indentation when the first line holds only the backslash.
            instruction = "".join(parts).lstrip(cls._GO_SPACE)
            yield instruction
            heredocs = cls._heredocs(instruction)
            if heredocs is None:
                gaps.append("heredoc not parsed")
                continue
            for name, chomp in heredocs:
                # The body runs to the terminator as written: no comment or
                # continuation applies inside it.
                while index < len(lines):
                    line = lines[index].rstrip("\r")
                    index += 1
                    if (line.lstrip("\t") if chomp else line) == name:
                        break
                else:
                    gaps.append("heredoc not parsed")
                    return

    @classmethod
    def _heredocs(cls, instruction: str) -> list[tuple[str, bool]] | None:
        """The terminator of each heredoc BuildKit reads after an instruction.

        With whether leading tabs are removed before the comparison. Only RUN, COPY
        and ADD, alone or after ONBUILD, take heredocs. None when the line uses
        shell syntax that is not modelled, so where the instruction ends is unknown.
        """
        if "<<" not in instruction:
            return []
        words = cls._DOCKER_WORD.findall(instruction)
        command = cls._command(words[0]) if words else ""
        if command == "onbuild":
            command = cls._command(next((w for w in words[1:] if not w.startswith("--")), ""))
        if command not in ("run", "copy", "add"):
            return []
        raw = cls._shell_words(instruction, raw=True)
        if raw is None:
            return None
        heredocs: list[tuple[str, bool]] = []
        for word in raw:
            match = cls._HEREDOC.fullmatch(word)
            if match is None or not match.group(2):
                continue
            name = cls._shell_words(match.group(2), raw=False)
            if name is None:
                return None
            if len(name) == 1:
                heredocs.append((name[0], match.group(1) == "-"))
        return heredocs

    @classmethod
    def _shell_words(cls, text: str, *, raw: bool) -> list[str] | None:
        """Words as BuildKit's shell lexer splits text when no variable is set.

        With raw, quotes and escapes stay in the words, as when BuildKit looks for
        heredocs; without, they are resolved, as for a heredoc's terminator. None
        for a substitution that is not modelled, for text the lexer rejects, and
        for a byte order mark, which Go's scanner can drop.
        """
        if "\ufeff" in text:
            return None
        words: list[str] = []
        word = ""
        position = 0
        while position < len(text):
            token = cls._SHELL_TOKEN.match(text, position)
            if token is None:
                return None
            position = token.end()
            kind, value = token.lastgroup, token.group()
            if kind == "space":
                if word:
                    words.append(word)
                word = ""
            elif raw or kind in ("plain", "heredoc", "dollar"):
                word += value
            elif kind == "single":
                word += value[1:-1]
            elif kind == "double":
                word += cls._QUOTED_ESCAPE.sub(r"\1", value[1:-1])
            else:
                word += value[1:]
        if word:
            words.append(word)
        return words

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
