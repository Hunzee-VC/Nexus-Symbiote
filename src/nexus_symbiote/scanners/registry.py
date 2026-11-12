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
import unicodedata
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, NamedTuple
from urllib.parse import quote, unquote, urlsplit

from packageurl import PackageURL
from packaging.markers import InvalidMarker, Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, Specifier
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from nexus_symbiote.core.enums import AssuranceLevel, RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import extract_version_pin, hash_bytes, parse_json_strict
from nexus_symbiote.core.models import ClaimEvidence, RegistryEntryComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult, sanitized_origin
from nexus_symbiote.scanners.mcp import (
    _npmrc,
    _origin_label,
    _registries,
    _setting_name,
    _uv_settings,
    _yarnrc,
    npm_registry_settings,
    npm_scope_registry,
)
from nexus_symbiote.scanners.mcp_launch import expands
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import redact_text, redact_url
from nexus_symbiote.utils.terminal import UNSAFE_TEXT

# The registry collector inventories only the packages these name, on PyPI and npm
# alike; docs/registry-collector.md lists them. A name is compared in its normal
# form, in which runs of "-", "_" and "." are one "-" and letters are lower case, as
# PEP 503 normalises a PyPI name. A name matches when it is listed whole in
# AI_PACKAGE_NAMES, when its npm scope is in AI_PACKAGE_SCOPES, or when the part
# after any scope starts with one of AI_PACKAGE_PREFIXES or has one of
# AI_PACKAGE_WORDS among its "-"-separated words. A prefix without a trailing "-"
# also matches longer names, as the patterns of earlier releases did.
AI_PACKAGE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "@aws-sdk/client-bedrock-agent-runtime",
        "@aws-sdk/client-bedrock-runtime",
        "@browserbasehq/stagehand",
        "@google-cloud/aiplatform",
        "@google-cloud/vertexai",
        "@google/adk",
        "@google/genai",
        "@google/generative-ai",
        "accelerate",
        "ag2",
        "agno",
        "ai",
        "ai21",
        "bitsandbytes",
        "browser-use",
        "camel-ai",
        "ctransformers",
        "deepspeed",
        "dspy",
        "e2b",
        "farm-haystack",
        "fireworks-ai",
        "flash-attn",
        "flax",
        "gguf",
        "griptape",
        "groq",
        "groq-sdk",
        "haystack-ai",
        "instructor",
        "jax",
        "jaxlib",
        "js-tiktoken",
        "lancedb",
        "letta",
        "mastra",
        "mcp",
        "mem0ai",
        "mlx",
        "node-llama-cpp",
        "onnx",
        "optimum",
        "paddlepaddle",
        "pyautogen",
        "pymilvus",
        "redisvl",
        "replicate",
        "sentencepiece",
        "together",
        "trl",
        "vertexai",
        "voyageai",
        "xformers",
    }
)
# npm scopes that hold a vendor's agent packages; every package in them matches.
AI_PACKAGE_SCOPES: Final[frozenset[str]] = frozenset(
    {
        "@a2a-js",
        "@ai-sdk",
        "@anthropic-ai",
        "@huggingface",
        "@lancedb",
        "@langchain",
        "@llamaindex",
        "@mastra",
        "@mistralai",
        "@mlc-ai",
        "@modelcontextprotocol",
        "@openai",
        "@pinecone-database",
        "@qdrant",
        "@smithery",
        "@tensorflow",
        "@tensorflow-models",
        "@xenova",
        "@zilliz",
    }
)
AI_PACKAGE_PREFIXES: Final[tuple[str, ...]] = (
    # The families earlier releases matched.
    "anthropic",
    "autogen",
    "chromadb",
    "cohere",
    "crewai",
    "faiss",
    "guardrails",
    "langchain",
    "llama-index",
    "mcp-",
    "nemo-guardrails",
    "openai",
    "pgvector",
    "pinecone",
    "qdrant",
    "rebuff",
    "safetensors",
    "tensorflow",
    "tokenizers",
    "torch",
    "transformers",
    "weaviate",
    # Agent frameworks, model SDKs and runtimes added since.
    "a2a-sdk",
    "agno-",
    "claude-agent-sdk",
    "claude-code-sdk",
    "diffusers",
    "dspy-",
    "e2b-",
    "fastmcp",
    "google-adk",
    "google-cloud-aiplatform",
    "google-genai",
    "google-generativeai",
    "huggingface",
    "keras",
    "langgraph",
    "langsmith",
    "letta-",
    "litellm",
    "llama-cpp",
    "llamaindex",
    "mistralai",
    "mlx-",
    "nemoguardrails",
    "ollama",
    "onnxruntime",
    "peft",
    "pydantic-ai",
    "semantic-kernel",
    "sentence-transformers",
    "smolagents",
    "strands-agents",
    "tiktoken",
    "vllm",
)
AI_PACKAGE_WORDS: Final[frozenset[str]] = frozenset({"llm", "mcp"})

# A container image is inventoried when its reference, in lower case, contains one
# of these strings or has one of the words among its parts.
AI_IMAGE_KEYWORDS: Final[tuple[str, ...]] = (
    # The keywords earlier releases matched.
    "llama",
    "model",
    "ollama",
    "tgi",
    "triton",
    "vllm",
    # Inference servers, vector stores and frameworks added since.
    "chroma",
    "huggingface",
    "litellm",
    "lmdeploy",
    "localai",
    "milvus",
    "onnxruntime",
    "pgvector",
    "pytorch",
    "qdrant",
    "sglang",
    "tensorflow",
    "text-embeddings-inference",
    "text-generation-inference",
    "weaviate",
)
AI_IMAGE_WORDS: Final[frozenset[str]] = frozenset({"mcp", "tei"})

_SEPARATORS = re.compile(r"[-_.]+")
_IMAGE_WORD = re.compile(r"[^a-z0-9]+")


def is_ai_image(reference: str) -> bool:
    """Whether a container image reference is one the collector inventories."""
    lowered = reference.lower()
    return any(keyword in lowered for keyword in AI_IMAGE_KEYWORDS) or not (
        AI_IMAGE_WORDS.isdisjoint(_IMAGE_WORD.split(lowered))
    )


class ImageReference(NamedTuple):
    """An image reference as the distribution reference grammar reads it."""

    domain: str
    path: str
    tag: str | None
    digest: str | None

    @property
    def repository(self) -> str:
        return f"{self.domain}/{self.path}"

    @property
    def pinned(self) -> bool:
        """Whether the digest is one Docker pulls and verifies: sha256, sha384 or
        sha512 in lower-case hex of the algorithm's length. Docker refuses any other
        digest the reference grammar admits."""
        return self.digest is not None and _PULLED_DIGEST.fullmatch(self.digest) is not None


_DOMAIN_COMPONENT = re.compile(r"[A-Za-z0-9]+(?:-+[A-Za-z0-9]+)*")
_PATH_COMPONENT = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*")
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
_DIGEST = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}")
_IPV6 = re.compile(r"\[[0-9A-Fa-f:.]+\]")
_PULLED_DIGEST = re.compile(r"sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96}|sha512:[0-9a-f]{128}")
# docker/distribution's limit on a repository name.
_LONGEST_IMAGE = 255 + 1 + 128 + 1 + 135


def parse_image_reference(text: str) -> ImageReference | None:
    """Split an image reference as Docker does, or None if it is not one.

    The first path component is a registry host when it contains "." or ":", is
    "localhost" or has upper-case letters; otherwise the image is on Docker Hub,
    where a single-component name is in the library namespace.
    """
    if not text or len(text) > _LONGEST_IMAGE or not text.isascii():
        return None
    name, at, digest = text.partition("@")
    if at and _DIGEST.fullmatch(digest) is None:
        return None
    slash, colon = name.rfind("/"), name.rfind(":")
    tag = None
    if colon > slash:
        name, tag = name[:colon], name[colon + 1 :]
        if _TAG.fullmatch(tag) is None:
            return None
    parts = name.split("/")
    first = parts[0]
    if len(parts) > 1 and (
        "." in first or ":" in first or first == "localhost" or first != first.lower()
    ):
        if first.startswith("["):
            close = first.find("]") + 1
            host, rest = first[:close], first[close:]
            if not close or _IPV6.fullmatch(host) is None:
                return None
        else:
            host, separator, port = first.partition(":")
            rest = separator + port
            if not all(_DOMAIN_COMPONENT.fullmatch(label) for label in host.split(".")):
                return None
        if rest and not (rest[0] == ":" and rest[1:].isdigit() and len(rest) <= 6):
            return None
        domain, path = first.lower(), parts[1:]
    else:
        domain, path = "docker.io", parts
    if domain in ("index.docker.io", "registry-1.docker.io"):
        domain = "docker.io"
    if not path or not all(_PATH_COMPONENT.fullmatch(part) for part in path):
        return None
    if domain == "docker.io" and len(path) == 1:
        path = ["library", *path]
    return ImageReference(domain, "/".join(path), tag, digest if at else None)


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


def _recorded_requirement(requirement: Requirement) -> str:
    """A requirement as the inventory records it, with a direct URL reduced to its origin.

    The name and extras are PEP 508 identifiers and are kept as written; free text
    that could hold a credential is redacted, so a name that ends in a word such as
    "token" does not lose the version that follows it.
    """
    extras = f"[{','.join(sorted(requirement.extras))}]" if requirement.extras else ""
    if requirement.url:
        text = f"{requirement.name}{extras} @ {_url_origin(requirement.url)}"
    else:
        text = requirement.name + extras + _unparsed(str(requirement.specifier))
    if requirement.marker:
        text += f" ; {_unparsed(str(requirement.marker))}"
    return text


# Real versions are short. packaging re-parses a clause's version on every
# comparison, so a declaration with a longer one is recorded but not compared.
_LONGEST_VERSION = 128
# All root requirements*.txt files together, in characters.
_REQUIREMENTS_BUDGET = 4 * 1024 * 1024
# shlex builds a token one character at a time, so its cost grows with the square
# of a quoted word's length; option text this long is not read.
_LONGEST_OPTIONS = 16 * 1024
# tomllib keeps every prefix of a dotted key, so its cost grows with the square of
# a key's parts and with the file's size. Real files are tens of kilobytes and
# their keys have a handful of parts.
_PYPROJECT_BUDGET = 256 * 1024
_LONGEST_DOTTED_KEY = 16
# A pnpm lockfile holds about 40 YAML tokens per package, so a lockfile at the 4 MiB
# read limit is about 650,000. The bound refuses denser input before it is parsed.
_MAX_PNPM_LOCK_TOKENS = 1_000_000
_PNPM_NAME_END = re.compile("[@/]")


_TOML_SPECIAL = re.compile(r"""[#"'.=,{}\[\]\n]""")
_TOML_STOPS = {
    ('"', False): re.compile(r'["\\\n]'),
    ("'", False): re.compile(r"['\n]"),
    ('"', True): re.compile(r'["\\]'),
    ("'", True): re.compile(r"'"),
}


def _toml_string_end(text: str, position: int, quote_char: str) -> int:
    """Where a TOML string that opened just before position ends.

    A basic string skips the character after a backslash. A multi-line string ends
    at the last three quotes of the first run of three or more, since up to two
    may end its content; a single-line one also ends at a line break.
    """
    multiline = text.startswith(quote_char * 2, position)
    if multiline:
        position += 2
    stops = _TOML_STOPS[quote_char, multiline]
    while True:
        found = stops.search(text, position)
        if found is None:
            return len(text)
        if found.group() == "\\":
            position = found.end() + 1
            continue
        if found.group() == "\n":
            return found.start()
        if not multiline:
            return found.end()
        run = found.end()
        while run < len(text) and text[run] == quote_char:
            run += 1
        if run - found.start() >= 3:
            return run
        position = run


def _parsed(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def _exact_pin(requirement: Requirement) -> tuple[str, object] | None:
    """A requirement's single exact version and the key pins are compared by.

    The same rule as extract_version_pin, which advisories apply, without its
    rejection of markers: a pin under a marker is still an exact version.
    """
    clauses = list(requirement.specifier)
    if requirement.url or len(clauses) != 1:
        return None
    clause = clauses[0]
    if (
        clause.operator not in ("==", "===")
        or "*" in clause.version
        or len(clause.version) > _LONGEST_VERSION
    ):
        return None
    version = _parsed(clause.version)
    if version is None or not clause.contains(version, prereleases=True):
        return None
    if clause.operator == "===":
        return clause.version, ("===", clause.version.lower())
    return clause.version, version


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


def _satisfies(requirement: Requirement, text: str, version: Version | None) -> bool:
    """Whether a pin meets every clause of a requirement; a clause too long to
    compare is taken as not met."""
    clauses = list(requirement.specifier)
    return all(
        len(clause.version) <= _LONGEST_VERSION and _admits(clause, text, version)
        for clause in clauses
    )


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


@dataclass
class _PipDeclaration:
    """One declaration of an inventoried PyPI package, as read and as recorded."""

    name: str
    source: str
    reference: str
    recorded: str
    spec: str | None
    group: str = ""
    requirement: Requirement | None = None
    # Why the declaration does not state what is installed: a Poetry or uv source,
    # another index, an untranslated condition, an override or invalid input.
    untranslated: str | None = None
    hashes: tuple[str, ...] = ()
    marker: str = ""
    pin: str | None = None
    pin_key: object = None


@dataclass
class _Package:
    """Every declaration of one PyPI package, and whether two of them conflict."""

    declarations: list[_PipDeclaration] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    seen: set[str] = field(default_factory=set)
    states: dict[tuple[str, str], _Declared] = field(default_factory=dict)
    conflict: bool = False

    def add(self, declaration: _PipDeclaration) -> None:
        # One component per package across manifests. Every declaration is kept
        # on it, so a change to any of them changes the inventory and its diff.
        self.sources.add(f"{declaration.source}: {declaration.recorded}")
        first = not self.declarations
        self.declarations.append(declaration)
        requirement = declaration.requirement
        if (
            self.conflict
            or requirement is None
            or declaration.untranslated is not None
            or declaration.reference in self.seen
        ):
            return
        self.seen.add(declaration.reference)
        # Declarations under different markers apply to different environments
        # (uv writes platform splits that way), and so do different optional-
        # dependency groups (uv's cpu and cu121 extras), so only equal ones are
        # compared.
        state = self.states.setdefault((declaration.marker, declaration.group), _Declared())
        if state.add(requirement) and not first:
            self.conflict = True


def _risk(
    severity: RiskSeverity, category: str, detail: str, recommendation: str
) -> RiskAssessment:
    return RiskAssessment(
        severity=severity, category=category, detail=detail, recommendation=recommendation
    )


def _npm_exact(version: str) -> bool:
    return extract_version_pin("package@" + version, ecosystem="npm") == version


_FULL_COMMIT = re.compile(r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?")
_HASH_VALUE = re.compile(r"sha(?:256|384|512):[0-9a-fA-F]{64,128}")


def _vcs_pinned(url: str) -> bool:
    """Whether a VCS reference names a full commit; branch and tag names can move."""
    reference = url.split("#", 1)[0]
    revision = reference.rsplit("@", 1)[1] if "@" in reference.split("//", 1)[-1] else ""
    return _FULL_COMMIT.fullmatch(revision) is not None


# Project files that choose the registry npm, pnpm, Yarn and Bun fetch from, each with
# the setting that names its default registry: npm and pnpm read .npmrc, Yarn 1 .npmrc
# and .yarnrc, later Yarn .yarnrc.yml, and Bun .npmrc and bunfig.toml. Which of them
# installs is not known, so every one is read.
_NPM_REGISTRY_FILES = (
    (".npmrc", "registry"),
    (".yarnrc", "registry"),
    (".yarnrc.yml", "npmRegistryServer"),
    ("bunfig.toml", "registry"),
)
# Letter case is ignored in ASCII only: Unicode case folding would also match dotless
# i and other letters that IDNA turns into another host.
_DEFAULT_NPM_REGISTRY = re.compile(
    r"https://registry\.(?:npmjs\.org|yarnpkg\.com)(?::443)?/?", re.ASCII | re.IGNORECASE
)
_DEFAULT_PYPI_INDEX = re.compile(r"(?i:https://pypi\.org)(?::443)?/simple/?", re.ASCII)
# The pip options and configuration keys that replace or add where packages come from;
# pip reads --pypi-url as --index-url. Index options on a requirement line are ignored.
# pip looks a configuration key up as the long option --<key>, so the long name of each
# of these options is also a key.
_PIP_INDEX_OPTIONS = frozenset({"--index-url", "--pypi-url", "--extra-index-url", "--find-links"})
_PIP_INDEX_KEYS = frozenset(option.removeprefix("--") for option in _PIP_INDEX_OPTIONS)
# pip reads a configuration file that PIP_CONFIG_FILE names or that lies at the root of
# the virtual environment it runs in; a project that keeps one there means it to be used.
_PIP_CONFIG_FILES = ("pip.conf", "pip.ini")
_PIP_CONFIG_LINE = re.compile(r"\r\n|\r|\n")
# A redirect value longer than this is recorded without its origins.
_LONGEST_REDIRECT = 4096
# Package sources one entry lists; one more entry counts the rest.
_MAX_LISTED_SOURCES = 32
# Settings named in a finding's detail; the rest are counted.
_MAX_NAMED_SOURCES = 8
_REDIRECT_ADVICE = (
    "Confirm that each configured registry or index is intended and trusted for this "
    "package, and pin artifact digests or integrity hashes."
)


def _pip_config(text: str) -> list[tuple[str, str]] | None:
    """The index settings of a pip configuration file, read as configparser reads it.

    Keys are lowercased, and pip reads ``_`` as ``-`` and ignores a leading ``--`` and
    an empty value. An indented line continues the value above it, and a comment line
    ends nothing. None when configparser, and so pip, refuses the file: text before the
    first section, a line that is neither a section nor ``key = value`` or
    ``key: value``, or a section or key given twice. Every section counts, because the
    sections pip reads depend on the command it runs and DEFAULT applies to all of them.
    """
    found: list[tuple[str, str]] = []
    sections: set[str] = set()
    keys: set[tuple[str, str]] = set()
    section: str | None = None
    key: str | None = None
    values: list[str] = []
    indent = 0

    def close() -> None:
        if key is not None:
            name = key.replace("_", "-").removeprefix("--")
            value = "\n".join(values).strip()
            if name in _PIP_INDEX_KEYS and value:
                found.append((name, value))

    for line in _PIP_CONFIG_LINE.split(text):
        stripped = line.strip()
        if stripped.startswith(("#", ";")):
            continue
        if not stripped:
            values.append("")
            continue
        level = len(line) - len(line.lstrip())
        if key is not None and level > indent:
            values.append(stripped)
            continue
        close()
        key, values, indent = None, [], level
        end = stripped.rfind("]")
        if stripped.startswith("[") and end > 1:
            section = stripped[1:end]
            if section in sections:
                return None
            if section != "DEFAULT":
                sections.add(section)
            continue
        found_delimiters = [i for i in (stripped.find("="), stripped.find(":")) if i >= 0]
        if section is None or not found_delimiters or min(found_delimiters) == 0:
            return None
        delimiter = min(found_delimiters)
        name = stripped[:delimiter].rstrip().lower()
        if (section, name) in keys:
            return None
        keys.add((section, name))
        key, values = name, [stripped[delimiter + 1 :].strip()]
    close()
    return found


class _SourceLabels:
    """Exported ``setting=origin`` entries for redirecting settings; each value is read once.

    Only a value's origins are exported, never paths or credentials, as for MCP servers.
    """

    def __init__(self) -> None:
        self._origins: dict[str, list[str]] = {}

    def _locations(self, value: str) -> list[str]:
        origins = self._origins.get(value)
        if origins is None:
            origins = (
                ["[not parsed]"]
                if len(value) > _LONGEST_REDIRECT
                else _origin_label(value) or ["[set]"]
            )
            self._origins[value] = origins
        return origins

    def entries(self, redirects: Iterable[tuple[str, str]]) -> list[str]:
        found = {
            f"{label}={location}"
            for label, value in redirects
            for location in self._locations(value)
        }
        listed = sorted(found)
        if len(listed) > _MAX_LISTED_SOURCES:
            more = len(listed) - _MAX_LISTED_SOURCES
            listed = [*listed[:_MAX_LISTED_SOURCES], f"[{more} more not listed]"]
        return listed


def _named(redirects: Iterable[tuple[str, str]]) -> str:
    names = sorted({label for label, _ in redirects})
    shown = ", ".join(names[:_MAX_NAMED_SOURCES])
    more = len(names) - _MAX_NAMED_SOURCES
    return shown + (f" and {more} more" if more > 0 else "")


def _redirect(component: RegistryEntryComponent, sources: list[str], detail: str) -> None:
    """Record the settings that send a package's resolution elsewhere.

    Its name and version then do not identify what is installed, so no package URL
    is claimed for it.
    """
    component.package_url = None
    component.properties["package_sources"] = sources
    component.risks.append(_risk(RiskSeverity.LOW, "registry_origin", detail, _REDIRECT_ADVICE))


class _Resolution(NamedTuple):
    version: str
    origin: str | None
    integrity: str | None
    locator: str
    risks: list[RiskAssessment]
    # The record binds an exact version to a strong integrity value and a tarball
    # that names this package and version, so the declared range is resolved.
    resolved: bool
    consistent: bool


class RegistryScanner(Scanner):
    name = "registry"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        with self._collection(project_root, result) as files:
            entries = files.root_entries()
            npm = self._scan_npm(result, entries)
            pypi = self._scan_pip(result, entries)
            self._note_unread_lockfiles(entries, npm, pypi)
            result.components.extend(npm)
            result.components.extend(pypi)
            result.components.extend(self._scan_docker(result))
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("registry (no AI-related dependencies found)")
        return result

    def _confined(self) -> ConfinedCollection:
        if self._files is None:
            raise RuntimeError("registry files read outside a _collection context")
        return self._files

    def _read(self, name: str, result: ScanResult) -> str | None:
        """A root file by its name, which is also how the inventory records it."""
        content = self._confined().read_text(name, missing_ok=True)
        if content is not None:
            result.surfaces_scanned.append(name)
        return content

    # Lockfiles of other package managers, which the collector does not read; the
    # npm, pnpm, Yarn, uv and Poetry lockfiles are read below.
    _UNREAD_LOCKFILES = {
        "npm": ("bun.lock", "bun.lockb"),
        "pypi": ("Pipfile.lock", "pdm.lock"),
    }

    @classmethod
    def _note_unread_lockfiles(
        cls,
        entries: list[str],
        npm: list[RegistryEntryComponent],
        pypi: list[RegistryEntryComponent],
    ) -> None:
        # A finding, not a coverage gap: the declarations are read, but what the
        # package manager resolves them to is not, and that stays visible per package.
        present = set(entries)
        for ecosystem, components, label in (("npm", npm, "npm"), ("pypi", pypi, "PyPI")):
            unread = [name for name in cls._UNREAD_LOCKFILES[ecosystem] if name in present]
            if not unread:
                continue
            for component in components:
                component.risks.append(
                    _risk(
                        RiskSeverity.LOW,
                        "lockfile_unread",
                        f"{label} package '{component.name}' may be resolved by "
                        f"{', '.join(unread)}, which the collector does not read.",
                        "Review that lockfile's record for this package; the inventory "
                        "records only what the manifests declare.",
                    )
                )

    # Read in npm's order of precedence: a later section's spec replaces an earlier one.
    _NPM_SECTIONS = ("peerDependencies", "dependencies", "optionalDependencies", "devDependencies")
    # npm uses npm-shrinkwrap.json instead of package-lock.json when both exist.
    _NPM_LOCKFILES = ("npm-shrinkwrap.json", "package-lock.json")
    # The lockfiles of npm, pnpm and Yarn. Each package manager installs from its own,
    # so a root that holds more than one of them is resolved ambiguously.
    _NODE_LOCKFILES = (_NPM_LOCKFILES, ("pnpm-lock.yaml",), ("yarn.lock",))
    _NPM_DEFAULT_REGISTRIES = frozenset({"registry.npmjs.org", "registry.yarnpkg.com"})
    _NPM_GAPS = {
        "override": "package.json: dependency override not translated",
        "unclassified": "package.json: git, URL or path dependency not classified",
        "workspaces": "package.json: workspaces not followed",
        # pnpm reads workspace packages, overrides and version catalogs from it.
        "pnpm": "pnpm-workspace.yaml: workspace settings not read",
    }

    def _npm_lock(
        self, result: ScanResult
    ) -> tuple[tuple[str, dict[str, Any], str] | None, tuple[str, bytes] | None]:
        """The lockfile package.json is installed from: npm's packages map with the
        digest of its bytes, or the bytes of a pnpm or Yarn lockfile.

        With the lockfiles of more than one package manager in the root, which one
        installs is unknown, so none is bound and the ambiguity is a coverage gap.
        """
        files = self._confined()
        found: list[tuple[str, bytes | None]] = []
        for names in self._NODE_LOCKFILES:
            for name in names:
                before = files.failures_recorded, files.exclusions_recorded
                # Parse and bind the same bounded bytes; a second open for hashing could
                # associate a swapped lockfile with a previously parsed resolution.
                raw = files.read_bytes(name, missing_ok=True)
                if raw is not None:
                    result.surfaces_scanned.append(name)
                    found.append((name, raw))
                    break
                if (files.failures_recorded, files.exclusions_recorded) != before:
                    # Present but refused or excluded: the package manager still
                    # prefers it, so no other file stands in for it.
                    found.append((name, None))
                    break
        if len(found) > 1:
            listed = ", ".join(name for name, _ in found)
            result.surfaces_excluded.append(
                f"multiple npm lockfiles present ({listed}); resolution is ambiguous"
            )
            return None, None
        if not found:
            return None, None
        name, raw = found[0]
        if raw is None:
            return None, None
        if name not in self._NPM_LOCKFILES:
            return None, (name, raw)
        try:
            lock = parse_json_strict(raw)
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
        except (ValueError, TypeError, UnicodeError, RecursionError):
            result.scan_failures.append(f"{name}: invalid or unsupported lockfile")
            return None, None
        return (name, lock["packages"], hash_bytes(raw)), None

    @staticmethod
    def _npm_spec(spec: str) -> tuple[str, str | None, str]:
        """How npm reads a dependency spec: its kind, an alias's package, and its range.

        The kinds follow npm-package-arg: a file path, an "npm:" alias, a hosted git
        shorthand or URL, another URL scheme, a path with a slash or an archive name,
        and otherwise a registry range, version or tag.
        """
        text = spec.strip()
        lowered = text.lower()
        if lowered.startswith("file:") or re.match(r"(?:[.]|~/|[/\\]|[a-zA-Z]:)", text):
            return "path", None, text
        if lowered.startswith("npm:"):
            target = text[4:]
            at = target.find("@", 1)
            return "alias", target if at < 0 else target[:at], "" if at < 0 else target[at + 1 :]
        if (
            lowered.startswith(("git+", "git:", "github:", "gitlab:", "bitbucket:", "gist:"))
            or re.fullmatch(r"[^@/:\s]+/[^/:\s#]+(?:#\S*)?", text)
            or re.match(r"[\w.-]+@[\w.-]+:", text)
        ):
            return "git", None, text
        if lowered.startswith(("http://", "https://")):
            return "url", None, text
        if lowered.startswith("workspace:"):
            # pnpm and yarn resolve it to the workspace package named by the key.
            return "workspace", None, text
        if lowered.startswith("catalog:"):
            # pnpm reads the version from its workspace catalog; the key names the package.
            return "registry", None, text
        if re.match(r"[a-z]+:", lowered) or "/" in text or "\\" in text:
            return "path", None, text
        if re.search(r"[.](?:tgz|tar[.]gz|tar)$", lowered):
            return "path", None, text
        return "registry", None, text

    def _scan_npm(self, result: ScanResult, entries: list[str]) -> list[RegistryEntryComponent]:
        if "pnpm-workspace.yaml" in entries:
            result.surfaces_excluded.append(self._NPM_GAPS["pnpm"])
        data = self._confined().read_json("package.json", missing_ok=True)
        if data is None:
            return []
        result.surfaces_scanned.append("package.json")
        if not isinstance(data, dict):
            result.scan_failures.append("package.json: expected an object")
            return []
        declared: dict[str, list[tuple[str, str]]] = {}
        for section in self._NPM_SECTIONS:
            deps = data.get(section, {})
            if not isinstance(deps, dict) or not all(
                isinstance(value, str) for value in deps.values()
            ):
                result.scan_failures.append(f"package.json: invalid {section} map")
                continue
            for key, spec in deps.items():
                declared.setdefault(key, []).append((section, spec))
        workspaces = data.get("workspaces")
        if (isinstance(workspaces, list) and workspaces) or (
            isinstance(workspaces, dict) and workspaces.get("packages")
        ):
            # Each workspace's package.json declares dependencies npm installs.
            result.surfaces_excluded.append(self._NPM_GAPS["workspaces"])
        lock, other_lock = self._npm_lock(result)
        resolutions: dict[str, Any] = lock[1] if lock else {}
        overrides = self._npm_overrides(data)
        components: list[RegistryEntryComponent] = []
        # Each package fetched from a registry, by the name the registry knows it by.
        fetched: list[tuple[RegistryEntryComponent, str]] = []
        gaps: dict[str, None] = {}
        for key, specs in sorted(declared.items()):
            spec = specs[-1][1]
            kind, target, version_range = self._npm_spec(spec)
            record = resolutions.get("node_modules/" + key)
            installed = self._installed_name(key, record, resolutions)
            package = target if kind == "alias" and target else key
            if not (
                self._is_ai_package(key)
                or self._is_ai_package(package)
                or (installed is not None and self._is_ai_package(installed))
            ):
                if kind in ("git", "url", "path") and installed is None:
                    # npm installs such a source under the key whatever package it
                    # holds; without a lock record naming it, it is not classified.
                    gaps[self._NPM_GAPS["unclassified"]] = None
                continue
            overridden = overrides is None or bool({key.lower(), package.lower()} & overrides[0])
            if overridden:
                gaps[self._NPM_GAPS["override"]] = None
            components.append(
                self._npm_component(
                    key, package, kind, version_range, specs, record, lock, overridden, result
                )
            )
            if kind in ("registry", "alias"):
                fetched.append((components[-1], package))
        if overrides is None or any(self._is_ai_package(t) for t in overrides[1]):
            # Too many overrides to read, or one that installs an AI package under
            # another package's name.
            gaps[self._NPM_GAPS["override"]] = None
        for replaced in sorted(overrides[2]) if overrides is not None else ():
            # As for a dependency: a git, URL or path source is installed under the
            # name whatever package it holds, and only a lock record names that.
            record = resolutions.get("node_modules/" + replaced)
            if not self._is_ai_package(replaced) and (
                self._installed_name(replaced, record, resolutions) is None
            ):
                gaps[self._NPM_GAPS["unclassified"]] = None
        result.surfaces_excluded.extend(gaps)
        if components and other_lock is not None:
            lock_name, raw_lock = other_lock
            if lock_name == "pnpm-lock.yaml":
                self._resolve_pnpm_lockfile(raw_lock, components, result)
            else:
                self._resolve_yarn_lockfile(raw_lock, components, result)
        if fetched:
            self._redirect_npm(result, fetched)
        return components

    def _npm_registries(
        self, result: ScanResult
    ) -> list[tuple[str, dict[str, str], str, str | None]]:
        """Each project file's registry settings, the setting that names its default
        registry, and for .npmrc the scope its ``scope`` setting selects.

        The files are read with the MCP collector's readers. An empty value selects
        nothing, as npm reads it. A .npmrc key that names an environment variable may
        be any setting, so its registries are a coverage gap.
        """
        found: list[tuple[str, dict[str, str], str, str | None]] = []
        for name, default in _NPM_REGISTRY_FILES:
            scope: str | None = None
            if name == "bunfig.toml":
                data = self._toml(name, result)
                if data is None:
                    continue
                install = data.get("install")
                settings = (
                    _registries(install, default, "scopes") if isinstance(install, dict) else []
                )
            elif name == ".yarnrc.yml":
                mapping = self._read_mapping(Path(name), result)
                if mapping is None:
                    continue
                result.surfaces_scanned.append(name)
                settings = _registries(mapping, default, "npmScopes")
            else:
                text = self._read(name, result)
                if text is None:
                    continue
                if name == ".yarnrc":
                    settings = list(_yarnrc(text))
                else:
                    parsed = _npmrc(text)
                    if parsed.unresolved:
                        result.surfaces_excluded.append(
                            ".npmrc: a setting name depends on the environment; registries "
                            "not resolved"
                        )
                    settings = list(parsed.settings)
                    scope = dict(parsed.settings).get("scope")
            found.append((name, {key: value for key, value in settings if value}, default, scope))
        return found

    def _redirect_npm(
        self, result: ScanResult, fetched: list[tuple[RegistryEntryComponent, str]]
    ) -> None:
        """Record on every package fetched from a registry the project settings that may
        choose another registry for it.

        Every package manager takes the registry of the package's own scope. For a
        package without one, npm takes the registry of the scope that .npmrc ``scope``
        names, and pnpm, Yarn 1 and Bun, which ignore ``scope``, the default registry;
        which of them installs is not known, so both count. A ``scope`` that npm fills
        in from the environment counts as ``.npmrc:scope=[unresolved]`` when the file
        gives some scope a registry other than the default one.
        """
        registries: list[tuple[str, dict[str, str], str, str | None]] = []
        for name, settings, default, scope in self._npm_registries(result):
            if expands(scope or "") and not any(
                npm_scope_registry(key) and not _DEFAULT_NPM_REGISTRY.fullmatch(value)
                for key, value in settings.items()
            ):
                # No scope the environment can name has a registry here but the default.
                scope = None
            registries.append((name, settings, default, scope))
        labels = _SourceLabels()
        for component, package in fetched:
            found: list[tuple[str, str]] = []
            for name, settings, default, scope in registries:
                selected = dict.fromkeys(
                    [
                        *npm_registry_settings(settings, package, default, scope),
                        *npm_registry_settings(settings, package, default),
                    ]
                )
                found.extend(
                    (f"{name}:{_setting_name(key, set())}", settings[key])
                    for key in selected
                    if not _DEFAULT_NPM_REGISTRY.fullmatch(settings[key])
                )
            if found:
                _redirect(
                    component,
                    labels.entries(found),
                    f"npm package '{component.name}' may resolve from a registry that the project "
                    f"configures ({_named(found)}), not the default npm registry; its name and "
                    "version do not establish identity.",
                )

    @staticmethod
    def _installed_name(key: str, record: Any, resolutions: dict[str, Any]) -> str | None:
        """The package a lock record says is installed under a key: its name, the key
        when it has none, or for a link the name of the entry it links to."""
        if not isinstance(record, dict):
            return None
        if record.get("link") is True:
            resolved = record.get("resolved")
            target = resolutions.get(resolved) if isinstance(resolved, str) else None
            name = target.get("name") if isinstance(target, dict) else None
            return name if isinstance(name, str) else None
        name = record.get("name", key)
        return name if isinstance(name, str) else None

    def _npm_component(
        self,
        key: str,
        package: str,
        kind: str,
        version_range: str,
        specs: list[tuple[str, str]],
        record: Any,
        lock: tuple[str, dict[str, Any], str] | None,
        overridden: bool,
        result: ScanResult,
    ) -> RegistryEntryComponent:
        spec = specs[-1][1]
        name = redact_text(package)
        properties: dict[str, Any] = {
            "collection_mode": "manifest-reference",
            "registry_origin_verified": False,
            "requested_version": redact_text(spec),
        }
        if kind == "alias":
            # npm installs the package under the key, which the code imports.
            properties["npm_alias"] = redact_text(key)
        if len({value for _, value in specs}) > 1:
            properties["declarations"] = sorted(
                f"{section}: {redact_text(value)}" for section, value in specs
            )
        claims: dict[str, ClaimEvidence] = {}
        registry = kind in ("registry", "alias")
        version = redact_text(version_range if registry and version_range else spec)
        source = "package.json"
        resolution = None
        if lock is not None and record is not None:
            lock_name, _, lock_digest = lock
            locator = f"{lock_name}#/packages/" + ("node_modules/" + key).replace(
                "~", "~0"
            ).replace("/", "~1")
            if registry:
                resolution = self._npm_resolution(
                    lock_name, key, package, version_range, record, locator, result
                )
            properties["lockfile_sha256"] = lock_digest
            properties["lockfile_record"] = locator
            if resolution is not None:
                version, source = resolution.version, lock_name
                properties.update(
                    {
                        "collection_mode": "lockfile-resolution-claim",
                        "artifact_verified": False,
                    }
                )
                if resolution.integrity is not None:
                    properties["lockfile_integrity"] = resolution.integrity
                claims["package_resolution"] = ClaimEvidence(
                    assurance=AssuranceLevel.DECLARED,
                    method="npm-lockfile",
                    scope="dependency-resolution",
                    collector="registry",
                    locator=locator,
                )
            elif registry:
                # A record that was not taken binds nothing; the failure or gap says why.
                del properties["lockfile_sha256"], properties["lockfile_record"]
        risks = list(resolution.risks) if resolution else []
        if kind == "alias":
            risks.append(
                _risk(
                    RiskSeverity.LOW,
                    "package_alias",
                    f"npm dependency '{redact_text(key)}' installs '{name}' under another name.",
                    "Check that the aliased package is the one the code expects to import.",
                )
            )
        if registry and not _npm_exact(version_range) and not (resolution and resolution.resolved):
            risks.append(
                _risk(
                    RiskSeverity.MEDIUM,
                    "version_pinning",
                    f"npm package '{name}' has a nonexact declared reference: {redact_text(spec)}",
                    "Resolve and verify an immutable artifact with lockfile integrity evidence.",
                )
            )
        elif not registry:
            risks.append(self._npm_source_risk(name, kind, spec))
        package_url = None
        if resolution is not None and resolution.consistent:
            package_url = self._npm_purl(package, resolution.version, resolution.origin)
        elif registry and record is None and not overridden and _npm_exact(version_range):
            # A lock record that was not taken leaves the identity in doubt.
            package_url = self._npm_purl(package, version_range, None)
        return RegistryEntryComponent(
            bom_ref=f"registry:npm/{redact_text(key)}",
            name=name,
            version=version or None,
            package_url=package_url,
            registry_type="npm",
            registry_uri=resolution.origin if resolution else None,
            source_path=source,
            trust_tier=TrustTier.UNKNOWN,
            assurance_level=AssuranceLevel.DECLARED,
            risks=risks,
            properties=properties,
            claims=claims,
        )

    @classmethod
    def _npm_purl(cls, package: str, version: str, origin: str | None) -> str | None:
        if re.fullmatch(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*", package) is None:
            return None
        purl = f"pkg:npm/{quote(package, safe='/')}@{quote(version, safe='')}"
        if origin is not None and not cls._default_registry(origin):
            # The package URL names the registry it was resolved from, so it is not
            # mistaken for the public package of the same name.
            purl += f"?repository_url={origin}"
        return purl

    @classmethod
    def _default_registry(cls, origin: str) -> bool:
        return origin.removeprefix("https://") in cls._NPM_DEFAULT_REGISTRIES

    @staticmethod
    def _npm_source_risk(name: str, kind: str, spec: str) -> RiskAssessment:
        lowered = spec.strip().lower()
        mutable = (kind == "git" and not _FULL_COMMIT.fullmatch(lowered.rsplit("#", 1)[-1])) or (
            lowered.startswith("http://")
        )
        label = {
            "git": "git",
            "url": "URL",
            "path": "local path or other",
            "workspace": "workspace",
        }[kind]
        return _risk(
            RiskSeverity.HIGH if mutable else RiskSeverity.MEDIUM,
            "nonregistry_source",
            f"npm package '{name}' is declared from a {label} source, not a registry.",
            "Install it from a registry with an exact version and lockfile integrity, "
            "or review the source and pin it to a full commit.",
        )

    def _npm_resolution(
        self,
        lock_name: str,
        key: str,
        package: str,
        version_range: str,
        record: Any,
        locator: str,
        result: ScanResult,
    ) -> _Resolution | None:
        """A lock record's resolution of a registry dependency, checked for consistency.

        None, with a failure or gap recorded, when the record is not taken.
        """
        if not isinstance(record, dict):
            result.scan_failures.append(f"{lock_name}: invalid selected package record")
            return None
        if record.get("name", key) != package:
            result.surfaces_excluded.append(f"{lock_name}: aliased package identity is unresolved")
            return None
        if record.get("link") is True:
            result.surfaces_excluded.append(f"{lock_name}: local link resolution is unverified")
            return None
        version = record.get("version")
        if not (
            isinstance(version, str) and len(version) <= _LONGEST_VERSION and _npm_exact(version)
        ):
            result.scan_failures.append(f"{lock_name}: selected package lacks an exact version")
            return None
        if _npm_exact(version_range) and version_range != version:
            # npm ci refuses a lockfile that does not satisfy package.json.
            result.scan_failures.append(
                f"{lock_name}: selected package version disagrees with package.json"
            )
            return None
        origin = None
        consistent = True
        resolved = record.get("resolved")
        if resolved is not None:
            parsed = self._https_resolution(resolved)
            if parsed is None:
                result.scan_failures.append(
                    f"{lock_name}: selected package has an unsupported resolved URL"
                )
                return None
            origin, path = parsed
            consistent = self._tarball_matches(origin, path, package, version)
        integrity = record.get("integrity")
        if integrity is not None and not self._validate_sri_integrity(integrity):
            result.scan_failures.append(f"{lock_name}: invalid selected package integrity")
            return None
        name = redact_text(package)
        risks: list[RiskAssessment] = []
        if not consistent:
            risks.append(
                _risk(
                    RiskSeverity.HIGH,
                    "lockfile_resolution_mismatch",
                    f"npm package '{name}' has a lockfile record whose tarball URL names "
                    "another package or version.",
                    "Regenerate the lockfile from the registry and review the change.",
                )
            )
        if integrity is None:
            risks.append(
                _risk(
                    RiskSeverity.MEDIUM,
                    "missing_lockfile_integrity",
                    f"npm package '{name}' has a lockfile record without an integrity value.",
                    "Regenerate the lockfile so that it records a sha512 integrity value.",
                )
            )
        if origin is not None and not self._default_registry(origin):
            risks.append(
                _risk(
                    RiskSeverity.LOW,
                    "registry_origin",
                    f"npm package '{name}' is resolved from {origin}, not the default npm "
                    "registry.",
                    "Confirm that this registry is intended and trusted for this package.",
                )
            )
        return _Resolution(
            version=version,
            origin=origin,
            integrity=integrity,
            locator=locator,
            risks=risks,
            resolved=integrity is not None and consistent,
            consistent=consistent,
        )

    @staticmethod
    def _https_resolution(resolved: Any) -> tuple[str, str] | None:
        """The origin and path of a resolved https URL, or None if a WHATWG parser,
        which npm uses, could read it differently.

        Control characters, white space, backslashes and percent signs in the host
        are such cases, and so is any character outside ASCII. User information is
        dropped, never recorded.
        """
        if not isinstance(resolved, str) or len(resolved) > 4096 or not resolved.isascii():
            return None
        if any(c <= " " or c in "\\\x7f" for c in resolved):
            return None
        try:
            parts = urlsplit(resolved)
            port = parts.port
        except ValueError:
            return None
        host = parts.hostname
        if parts.scheme.lower() != "https" or not host or "%" in parts.netloc.rpartition("@")[2]:
            return None
        host = f"[{host}]" if ":" in host else host
        origin = f"https://{host}" + (f":{port}" if port is not None and port != 443 else "")
        return origin, parts.path

    @classmethod
    def _tarball_matches(cls, origin: str, path: str, package: str, version: str) -> bool:
        """Whether a registry tarball path names this package and version.

        npm registries serve /<name>/-/<unscoped name>-<version>.tgz. Another layout,
        such as GitHub Packages' download paths, is not checked.
        """
        try:
            decoded = unquote(path, errors="strict")
        except UnicodeDecodeError:
            return False
        tail = f"/{package}/-/{package.rsplit('/', 1)[-1]}-{version}.tgz"
        if cls._default_registry(origin):
            return decoded == tail
        return "/-/" not in decoded or decoded.endswith(tail)

    @staticmethod
    def _validate_sri_integrity(integrity: Any) -> bool:
        """Whether an SRI value binds the artifact as npm, pnpm and Yarn check it.

        Every hash in it must decode to its algorithm's length, and one must be
        SHA-256, SHA-384 or SHA-512: the package managers check the strongest, so a
        value with only SHA-1 is refused, as is anything else.
        """
        if not isinstance(integrity, str) or not integrity or len(integrity) > 1024:
            return False
        algorithms: set[str] = set()
        for item in integrity.split():
            algorithm, separator, encoded = item.partition("-")
            size = {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}.get(algorithm)
            if not separator or size is None:
                return False
            try:
                if len(base64.b64decode(encoded, validate=True)) != size:
                    return False
            except (ValueError, binascii.Error):
                return False
            algorithms.add(algorithm)
        return bool(algorithms - {"sha1"})

    def _bind_npm_resolution(
        self,
        component: RegistryEntryComponent,
        lock_name: str,
        method: str,
        version: str,
        resolved: Any,
        integrity: Any,
        locator: str,
        lock_digest: str,
        result: ScanResult,
    ) -> None:
        """Bind a pnpm or Yarn record's exact version to a component, checked as an npm
        record is: an exact spec must agree with it, a download URL is read as a
        WHATWG parser reads it, and an integrity value must be strong. Nothing is
        bound, and a failure says why, when a check fails."""
        requested = str(component.properties.get("requested_version", "")).strip()
        if _npm_exact(requested) and requested != version:
            result.scan_failures.append(
                f"{lock_name}: selected package version disagrees with package.json"
            )
            return
        origin = None
        consistent = True
        if resolved is not None:
            parsed = self._https_resolution(resolved)
            if parsed is None:
                result.scan_failures.append(
                    f"{lock_name}: selected package has an unsupported resolved URL"
                )
                return
            origin, path = parsed
            consistent = self._tarball_matches(origin, path, component.name, version)
        if integrity is not None and not self._validate_sri_integrity(integrity):
            result.scan_failures.append(f"{lock_name}: invalid selected package integrity")
            return
        if not consistent:
            component.risks.append(
                _risk(
                    RiskSeverity.HIGH,
                    "lockfile_resolution_mismatch",
                    f"npm package '{component.name}' has a lockfile record whose tarball URL "
                    "names another package or version.",
                    "Regenerate the lockfile from the registry and review the change.",
                )
            )
        component.version = version
        component.package_url = (
            self._npm_purl(component.name, version, origin) if consistent else None
        )
        component.registry_uri = origin
        component.source_path = lock_name
        component.assurance_level = AssuranceLevel.DECLARED
        component.properties.update(
            {
                "collection_mode": "lockfile-resolution-claim",
                "lockfile_sha256": lock_digest,
                "lockfile_record": locator,
                "artifact_verified": False,
            }
        )
        if integrity is not None:
            component.properties["lockfile_integrity"] = integrity
        component.claims["package_resolution"] = ClaimEvidence(
            assurance=AssuranceLevel.DECLARED,
            method=method,
            scope="dependency-resolution",
            collector="registry",
            locator=locator,
        )

    @staticmethod
    def _pnpm_selections(
        packages: dict[Any, Any], names: set[str]
    ) -> dict[str, tuple[str, str] | None]:
        """The `packages` record each of these names selects: its key and version
        reference, or None when records of more than one version make the choice
        ambiguous. A name without a record, or with several records of one version,
        selects none.

        A key is the record of one name: its text up to the first "@" or "/" after the
        first character, or after a scope's "/". So each key is read once and the cost
        is linear in the lockfile: matching every name against every key cost their
        product, and indexing a key under the text before each separator would cost
        the square of its length.
        """
        if not names:
            return {}
        found: dict[str, list[tuple[str, str]]] = {}
        for key in packages:
            if not isinstance(key, str):
                continue
            clean = key.lstrip("/")
            start = clean.find("/", 1) + 1 if clean.startswith("@") else 1
            end = _PNPM_NAME_END.search(clean, start) if start else None
            if end is None:
                continue
            name = clean[: end.start()]
            if name not in names:
                continue
            suffix = clean[end.end() :]
            if suffix and not suffix.startswith("/"):
                found.setdefault(name, []).append((key, suffix))
        selections: dict[str, tuple[str, str] | None] = {}
        for name, records in found.items():
            if len({suffix.split("(", 1)[0] for _, suffix in records}) > 1:
                selections[name] = None
            elif len(records) == 1:
                selections[name] = records[0]
        return selections

    def _resolve_pnpm_lockfile(
        self,
        lock_bytes: bytes,
        components: list[RegistryEntryComponent],
        result: ScanResult,
    ) -> None:
        try:
            import yaml

            from nexus_symbiote.policy import PolicyError, parse_yaml_mapping

            text = lock_bytes.decode("utf-8")
            for index, token in enumerate(yaml.scan(text)):
                if index >= _MAX_PNPM_LOCK_TOKENS or isinstance(
                    token, (yaml.AliasToken, yaml.AnchorToken, yaml.TagToken)
                ):
                    raise ValueError("unsupported YAML graph")
            lock_doc = parse_yaml_mapping(text)
            lock_ver = lock_doc.get("lockfileVersion")
            if (
                not isinstance(lock_doc, dict)
                or lock_ver is None
                or isinstance(lock_ver, bool)
                or not isinstance(lock_ver, (str, int, float))
            ):
                raise ValueError("unsupported pnpm lockfile structure")
            packages = lock_doc.get("packages", {})
            if packages is not None and not isinstance(packages, dict):
                raise ValueError("unsupported pnpm packages structure")
        except (ImportError, ValueError, UnicodeError, PolicyError, RecursionError, yaml.YAMLError):
            result.scan_failures.append("pnpm-lock.yaml: invalid or unsupported lockfile")
            return
        lock_digest = hash_bytes(lock_bytes)
        packages = packages or {}
        importers = lock_doc.get("importers")
        root_importer = (
            importers.get(".", {})
            if isinstance(importers, dict) and isinstance(importers.get("."), dict)
            else lock_doc
        )
        importer_specs: dict[str, str] = {}
        for dep_key in ("dependencies", "devDependencies", "optionalDependencies"):
            dep_map = root_importer.get(dep_key, {})
            if isinstance(dep_map, dict):
                for pkg_name, entry in dep_map.items():
                    if isinstance(entry, dict) and isinstance(entry.get("version"), str):
                        importer_specs[pkg_name] = entry["version"]
                    elif isinstance(entry, str):
                        importer_specs[pkg_name] = entry
        counts = Counter(c.name for c in components if c.properties.get("npm_alias") is None)
        selections = self._pnpm_selections(packages, set(counts).difference(importer_specs))
        for comp in components:
            alias = comp.properties.get("npm_alias")
            if alias is not None:
                # Only npm's own lockfile record is resolved against an alias's package.
                if alias in importer_specs:
                    comp.package_url = None
                    result.surfaces_excluded.append(
                        "pnpm-lock.yaml: aliased package identity is unresolved"
                    )
                continue
            ver_ref = importer_specs.get(comp.name)
            matched_pkg_key: str | None = None
            if ver_ref is None and comp.name in selections:
                selected = selections[comp.name]
                if selected is None:
                    comp.package_url = None
                    result.surfaces_excluded.append(
                        f"pnpm-lock.yaml: multiple package resolutions for {comp.name} are ambiguous"
                    )
                    continue
                matched_pkg_key, ver_ref = selected
            if ver_ref is None:
                continue
            # A record the lockfile holds decides the identity, or nothing does: one
            # that is not taken leaves the version an exact spec names in doubt.
            comp.package_url = None
            if counts[comp.name] > 1:
                # Redaction gave several dependencies this name, so which of them the
                # record belongs to is unknown; binding it to each would also copy its
                # key, however long, into every one.
                result.surfaces_excluded.append(
                    f"pnpm-lock.yaml: packages whose names redact to {comp.name} are unresolved"
                )
                continue
            if ver_ref.startswith("npm:"):
                result.surfaces_excluded.append(
                    "pnpm-lock.yaml: aliased package identity is unresolved"
                )
                continue
            if ver_ref.startswith(("link:", "file:", "workspace:", "git+", "http:", "https:")):
                result.surfaces_excluded.append(
                    "pnpm-lock.yaml: local or non-registry resolution is unverified"
                )
                continue
            base_ver = ver_ref.split("(", 1)[0]
            if base_ver.startswith("/"):
                pkg_prefix, _, base_ver = base_ver.lstrip("/").rpartition("@")
                if pkg_prefix and pkg_prefix != comp.name:
                    result.surfaces_excluded.append(
                        "pnpm-lock.yaml: aliased package identity is unresolved"
                    )
                    continue
            if len(base_ver) > _LONGEST_VERSION or not _npm_exact(base_ver):
                result.scan_failures.append(
                    "pnpm-lock.yaml: selected package lacks an exact version"
                )
                continue
            candidates = (
                (matched_pkg_key,)
                if matched_pkg_key is not None
                else (
                    f"{comp.name}@{ver_ref}",
                    f"/{comp.name}@{ver_ref}",
                    f"{comp.name}@{base_ver}",
                    f"/{comp.name}@{base_ver}",
                    f"/{comp.name}/{base_ver}",
                )
            )
            pkg_key = next((c for c in candidates if c in packages), None)
            tarball: Any = None
            integrity: Any = None
            if pkg_key is not None:
                pkg_record = packages[pkg_key]
                if not isinstance(pkg_record, dict):
                    result.scan_failures.append("pnpm-lock.yaml: invalid selected package record")
                    continue
                resolution = pkg_record.get("resolution")
                if resolution is not None and not isinstance(resolution, dict):
                    result.scan_failures.append("pnpm-lock.yaml: invalid selected package record")
                    continue
                if isinstance(resolution, dict):
                    tarball = resolution.get("tarball")
                    if resolution.get("type") in {"directory", "git"} or (
                        isinstance(tarball, str) and tarball.startswith(("file:", "link:"))
                    ):
                        result.surfaces_excluded.append(
                            "pnpm-lock.yaml: local or non-registry resolution is unverified"
                        )
                        continue
                    integrity = resolution.get("integrity")
                locator = "pnpm-lock.yaml#/packages/" + pkg_key.replace("~", "~0").replace(
                    "/", "~1"
                )
            else:
                locator = "pnpm-lock.yaml#/importers/./" + comp.name.replace("~", "~0").replace(
                    "/", "~1"
                )
            self._bind_npm_resolution(
                comp,
                "pnpm-lock.yaml",
                "pnpm-lockfile",
                base_ver,
                tarball,
                integrity,
                locator,
                lock_digest,
                result,
            )

    def _resolve_yarn_lockfile(
        self,
        lock_bytes: bytes,
        components: list[RegistryEntryComponent],
        result: ScanResult,
    ) -> None:
        try:
            text = lock_bytes.decode("utf-8")
            lines = text.splitlines()
            if len(lines) > 100_000:
                raise ValueError("yarn.lock line limit exceeded")
            stanzas: list[tuple[list[str], dict[str, str]]] = []
            current_selectors: list[str] | None = None
            current_fields: dict[str, str] = {}
            for raw_line in lines:
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not raw_line[0].isspace():
                    if not stripped.endswith(":"):
                        raise ValueError("invalid yarn.lock header")
                    if current_selectors is not None and current_selectors != ["__metadata"]:
                        stanzas.append((current_selectors, current_fields))
                    header = stripped[:-1].strip()
                    current_selectors = [
                        s.strip().strip('"').strip("'") for s in header.split(",") if s.strip()
                    ]
                    if not current_selectors:
                        raise ValueError("empty yarn.lock selector")
                    current_fields = {}
                else:
                    if current_selectors is None:
                        raise ValueError("orphan yarn.lock field")
                    if raw_line.startswith("  ") and not raw_line.startswith("   "):
                        match = re.match(r"^([A-Za-z0-9_]+)(?::\s*|\s+)(.+)$", stripped)
                        if match:
                            key = match.group(1)
                            val = match.group(2).strip().strip('"').strip("'")
                            if key in current_fields:
                                raise ValueError("duplicate key in yarn.lock stanza")
                            current_fields[key] = val
            if current_selectors is not None and current_selectors != ["__metadata"]:
                stanzas.append((current_selectors, current_fields))
            if not stanzas:
                raise ValueError("empty yarn.lock")
        except (ValueError, UnicodeError):
            result.scan_failures.append("yarn.lock: invalid or unsupported lockfile")
            return
        lock_digest = hash_bytes(lock_bytes)
        by_pkg: dict[str, list[tuple[str, dict[str, str], str]]] = {}
        for selectors, fields in stanzas:
            first_sel = selectors[0]
            for sel in selectors:
                at_idx = sel.find("@", 1) if sel.startswith("@") else sel.find("@")
                if at_idx <= 0:
                    continue
                sel_name, sel_spec = sel[:at_idx], sel[at_idx + 1 :]
                by_pkg.setdefault(sel_name, []).append((sel_spec, fields, first_sel))
        for comp in components:
            alias = comp.properties.get("npm_alias")
            if alias is not None:
                # Only npm's own lockfile record is resolved against an alias's package.
                if alias in by_pkg:
                    comp.package_url = None
                    result.surfaces_excluded.append(
                        "yarn.lock: aliased package identity is unresolved"
                    )
                continue
            entries = by_pkg.get(comp.name)
            if not entries:
                continue
            # As for pnpm: the record decides the identity, or nothing does.
            comp.package_url = None
            req = str(comp.properties.get("requested_version", ""))
            exact_matches = [e for e in entries if e[0] in (req, f"npm:{req}")]
            chosen = exact_matches or entries
            distinct_versions = {e[1].get("version") for e in chosen}
            if len(distinct_versions) > 1:
                result.surfaces_excluded.append(
                    f"yarn.lock: multiple package resolutions for {comp.name} are ambiguous"
                )
                continue
            sel_spec, fields, locator_key = chosen[0]
            resolution_val = fields.get("resolution", "")
            resolved_val = fields.get("resolved", "")
            if sel_spec.startswith("npm:") and "@" in sel_spec[4:]:
                alias_pkg = sel_spec[4:].rsplit("@", 1)[0]
                if alias_pkg and alias_pkg != comp.name:
                    result.surfaces_excluded.append(
                        "yarn.lock: aliased package identity is unresolved"
                    )
                    continue
            if "@npm:" in resolution_val and not resolution_val.startswith(f"{comp.name}@npm:"):
                result.surfaces_excluded.append("yarn.lock: aliased package identity is unresolved")
                continue
            non_registry_prefixes = (
                "workspace:",
                "link:",
                "portal:",
                "file:",
                "patch:",
                "git+",
                "git:",
            )
            if (
                sel_spec.startswith(non_registry_prefixes)
                or resolved_val.startswith(non_registry_prefixes)
                or any(f"@{p}" in resolution_val for p in non_registry_prefixes)
                or fields.get("linkType") == "soft"
            ):
                result.surfaces_excluded.append(
                    "yarn.lock: local or non-registry resolution is unverified"
                )
                continue
            resolved_version = fields.get("version")
            if (
                not isinstance(resolved_version, str)
                or len(resolved_version) > _LONGEST_VERSION
                or not _npm_exact(resolved_version)
            ):
                result.scan_failures.append("yarn.lock: selected package lacks an exact version")
                continue
            locator = "yarn.lock#/" + locator_key.replace("~", "~0").replace("/", "~1")
            self._bind_npm_resolution(
                comp,
                "yarn.lock",
                "yarn-lockfile",
                resolved_version,
                resolved_val or None,
                fields.get("integrity"),
                locator,
                lock_digest,
                result,
            )

    _OVERRIDE_FIELDS = (("overrides",), ("resolutions",), ("pnpm", "overrides"))
    _OVERRIDE_ENTRIES = 10_000

    @classmethod
    def _npm_overrides(cls, data: dict[str, Any]) -> tuple[set[str], set[str], set[str]] | None:
        """The package names npm, yarn and pnpm override fields name, the alias
        targets they install, and the packages they replace with a git, URL or path
        source; None when there are too many entries to read."""
        names: set[str] = set()
        targets: set[str] = set()
        sources: set[str] = set()
        stack: list[tuple[Any, int, list[str]]] = []
        for path in cls._OVERRIDE_FIELDS:
            node: Any = data
            for part in path:
                node = node.get(part) if isinstance(node, dict) else None
            if node is not None:
                stack.append((node, 0, []))
        remaining = cls._OVERRIDE_ENTRIES
        while stack:
            node, depth, parent = stack.pop()
            if not isinstance(node, dict):
                continue
            for selector, value in node.items():
                remaining -= 1
                if remaining < 0 or depth > 32:
                    return None
                selected = cls._override_names(str(selector))
                names.update(name.lower() for name in selected)
                if isinstance(value, dict):
                    stack.append((value, depth + 1, selected or parent))
                elif isinstance(value, str):
                    kind, target, _ = cls._npm_spec(value)
                    if kind == "alias" and target:
                        targets.add(target)
                    elif kind in ("git", "url", "path"):
                        # The last name is the package replaced; "." replaces the
                        # package of the enclosing selector.
                        sources.update((selected or parent)[-1:])
        return names, targets, sources

    @staticmethod
    def _override_names(selector: str) -> list[str]:
        """Package names in an override selector: "name@range" (npm), "a/**/name"
        (yarn resolutions) or "a>name" (pnpm), with scoped names kept whole."""
        names: list[str] = []
        for part in selector.split(">"):
            segments = part.split("/")
            index = 0
            while index < len(segments):
                segment = segments[index]
                index += 1
                if segment.startswith("@") and index < len(segments):
                    segment += "/" + segments[index]
                    index += 1
                at = segment.find("@", 1)
                segment = segment[:at] if at > 0 else segment
                if segment not in ("", "**", "*", "."):
                    names.append(segment)
        return names

    _PIP_NAME = re.compile(r"[a-zA-Z0-9_.-]+")

    def _pip_declaration(
        self,
        reference: str,
        source: str,
        result: ScanResult | None = None,
        group: str = "",
        hashes: tuple[str, ...] = (),
        untranslated: str | None = None,
    ) -> _PipDeclaration | None:
        """A declaration of an inventoried PyPI package, or None for any other name."""
        match = self._PIP_NAME.match(reference)
        if not match or not self._is_ai_package(match.group()):
            return None
        name = str(canonicalize_name(match.group()))
        if untranslated is not None:
            # The bare name, never compared: what it leaves out is unknown.
            return _PipDeclaration(
                name, source, reference, match.group(), None, group, untranslated=untranslated
            )
        try:
            requirement = Requirement(reference)
            name = str(canonicalize_name(requirement.name))
            # Retain markers and URLs as declared, unresolved conditions; they
            # must not silently turn into an unconditional exact package URL.
            marker = str(requirement.marker) if requirement.marker else ""
            if requirement.url:
                spec = "@ " + _url_origin(requirement.url)
            else:
                spec = _unparsed(str(requirement.specifier))
            if marker:
                spec += "; " + _unparsed(marker)
            recorded = _recorded_requirement(requirement)
            pin = _exact_pin(requirement)
        except (InvalidRequirement, RecursionError):
            # packaging parses markers by recursion; a deeply nested one is invalid
            # input for this line, not the end of the collection.
            if result is not None:
                message = f"{source}: invalid or unsupported PyPI requirement"
                if message not in result.scan_failures:
                    result.scan_failures.append(message)
            spec = _unparsed(reference[len(match.group()) :].strip())
            return _PipDeclaration(
                name=name,
                source=source,
                reference=reference,
                recorded=_unparsed(reference),
                spec=redact_text(spec) or None,
                group=group,
                untranslated="invalid",
                hashes=hashes,
            )
        return _PipDeclaration(
            name=name,
            source=source,
            reference=reference,
            recorded=recorded,
            spec=redact_text(spec) or None,
            group=group,
            requirement=requirement,
            hashes=hashes,
            marker=marker,
            pin=pin[0] if pin else None,
            pin_key=pin[1] if pin else None,
        )

    def _pip_component(
        self, line: str, path: Path, result: ScanResult | None = None
    ) -> RegistryEntryComponent | None:
        """The component one requirement line alone declares."""
        reference = line.strip().split(" #", 1)[0].strip()
        declaration = self._pip_declaration(reference, str(path), result)
        if declaration is None:
            return None
        package = _Package()
        package.add(declaration)
        return self._pypi_component(package)

    @staticmethod
    def _pypi_component(package: _Package) -> RegistryEntryComponent:
        """One component from every declaration of a package, in the order read.

        The version, package URL and findings follow from all of them, whichever file
        is read first. The first exact pin without a marker is the version reported,
        and it resolves the ranges it satisfies in every file, as a compiled
        requirements file resolves the ranges of pyproject.toml; a range it does not
        satisfy, under any marker or group, is a version_pinning finding. A URL or VCS
        declaration anywhere is a finding and no PyPI package URL. A package URL is
        emitted only when every exact pin names the same version, every other
        declaration admits it, and nothing conflicts or is left untranslated.
        """
        declarations = package.declarations
        name = declarations[0].name
        urls: list[_PipDeclaration] = []
        others: list[_PipDeclaration] = []
        for declaration in declarations:
            requirement = declaration.requirement
            (urls if requirement is not None and requirement.url else others).append(declaration)
        exact = [d for d in others if d.pin is not None]
        unconditional = [d for d in exact if not d.marker]
        chosen = unconditional[0] if unconditional else declarations[0]
        loose: list[_PipDeclaration] = []
        if chosen.pin is not None and unconditional:
            pinned = _parsed(chosen.pin)
            loose = [
                d
                for d in others
                if d.pin is None
                and d.requirement is not None
                and not _satisfies(d.requirement, chosen.pin, pinned)
            ]
        risks: list[RiskAssessment] = []
        if urls:
            files = ", ".join(dict.fromkeys(d.source for d in urls))
            mutable = any(
                d.requirement is not None
                and d.requirement.url
                and re.match(r"(?:git|hg|svn|bzr)\+", d.requirement.url, re.I)
                and not _vcs_pinned(d.requirement.url)
                for d in urls
            )
            risks.append(
                _risk(
                    RiskSeverity.HIGH if mutable else RiskSeverity.MEDIUM,
                    "nonregistry_source",
                    f"PyPI package '{name}' is declared from a URL, VCS or path source in {files}.",
                    "Install it from the package index with an exact version and verified "
                    "hashes, or review the source and pin it to a full commit.",
                )
            )
        if others and not unconditional:
            if all(d.pin is not None for d in others):
                risks.append(
                    _risk(
                        RiskSeverity.LOW,
                        "version_pinning",
                        f"PyPI package '{name}' is pinned only under environment markers.",
                        "Check that every environment the project supports has a pin, and "
                        "verify artifact hashes.",
                    )
                )
            else:
                risks.append(
                    _risk(
                        RiskSeverity.MEDIUM,
                        "version_pinning",
                        f"PyPI package '{name}' has an unresolved or nonexact declared reference.",
                        "Resolve the declared conditions, pin the version and verify artifact "
                        "hashes.",
                    )
                )
        elif loose and not package.conflict:
            files = ", ".join(dict.fromkeys(d.source for d in loose))
            risks.append(
                _risk(
                    RiskSeverity.MEDIUM,
                    "version_pinning",
                    f"PyPI package '{name}' has a nonexact declaration in {files} that its "
                    "exact pin does not satisfy.",
                    "Make every declaration admit the pinned version, pin it where it floats, "
                    "and verify artifact hashes.",
                )
            )
        if package.conflict:
            risks.append(
                _risk(
                    RiskSeverity.MEDIUM,
                    "version_pinning",
                    f"PyPI package '{name}' is declared more than once with requirements that "
                    "conflict.",
                    "Check that each declaration is intended, make them agree where possible, "
                    "and verify artifact hashes.",
                )
            )
        package_url = None
        if (
            unconditional
            and not urls
            and not loose
            and not package.conflict
            and all(d.untranslated is None for d in declarations)
            and len({d.pin_key for d in exact}) == 1
            and chosen.pin is not None
        ):
            package_url = f"pkg:pypi/{quote(name, safe='')}@{quote(chosen.pin, safe='')}"
        origins = {
            _url_origin(d.requirement.url)
            for d in urls
            if d.requirement is not None and d.requirement.url
        }
        registry_uri: str | None = "https://pypi.org"
        if urls or any(d.untranslated in ("source", "index", "override") for d in declarations):
            registry_uri = origins.pop() if not others and len(origins) == 1 else None
        properties: dict[str, Any] = {
            "collection_mode": "manifest-reference",
            "registry_origin_verified": False,
            "requested_requirement": chosen.recorded,
        }
        if len(package.sources) > 1:
            properties["declarations"] = sorted(package.sources)
        hashes = sorted({f"{d.source}: {value}" for d in declarations for value in d.hashes})
        if hashes:
            # pip checks the artifact against these; a changed or removed hash is drift.
            properties["requirement_hashes"] = hashes
        return RegistryEntryComponent(
            bom_ref=f"registry:pypi/{name}",
            name=name,
            version=chosen.spec,
            package_url=package_url,
            registry_type="pypi",
            registry_uri=registry_uri,
            source_path=chosen.source,
            trust_tier=TrustTier.UNKNOWN,
            risks=risks,
            properties=properties,
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
        if cls._unsplittable(text):
            return [], ["option line not parsed"]
        quoted = any(c in text for c in "\"'\\")
        try:
            words = shlex.split(text) if quoted else [w for w in cls._SHLEX_SPACE.split(text) if w]
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

    @staticmethod
    def _unsplittable(text: str) -> bool:
        """Whether option text is too long for shlex, whose cost grows with the square
        of a quoted word's length."""
        return len(text) > _LONGEST_OPTIONS and any(c in text for c in "\"'\\")

    @classmethod
    def _option_gaps(
        cls, options: list[tuple[str, str]], names: set[str], entries: set[str]
    ) -> list[str]:
        """What the options of a line add or pin that the collector does not read.

        The gap never names the target, which can be a URL carrying a credential.
        """
        gaps: list[str] = []
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

    # The format characters HFS+ ignores when it compares names.
    _IGNORED_IN_NAMES = dict.fromkeys(
        [*range(0x200C, 0x2010), *range(0x202A, 0x202F), *range(0x206A, 0x2070), 0xFEFF]
    )

    @classmethod
    def _fold(cls, name: str) -> str:
        """A name as file systems may compare it.

        Case and Unicode normalisation are folded, as on APFS, HFS+ and NTFS; so are
        the format characters HFS+ ignores and the trailing dots and spaces Windows
        drops.
        """
        folded = unicodedata.normalize("NFD", unicodedata.normalize("NFD", name).casefold())
        return folded.translate(cls._IGNORED_IN_NAMES).rstrip(". ")

    @classmethod
    def _editable_covered(cls, target: str, entries: set[str]) -> bool:
        """Whether -e installs the project itself, whose pyproject.toml is read."""
        # One trailing extras group, as pip strips it from a local path.
        match = re.fullmatch(r"([^\[\]]+)(?:\[[^\[\]]+\])?", target)
        if match is None:
            return False
        path = match.group(1)
        if path[:5].lower() == "file:":
            # pip installs a directory with that name instead, if there is one.
            if cls._fold(path.split("/", 1)[0]) in entries:
                return False
            path = path[5:]
        return (
            bool(path)
            and not path.startswith("/")
            and all(part in ("", ".") for part in path.split("/"))
        )

    @staticmethod
    def _without_extras(path: str) -> str:
        """pip's strip_extras in linear time: the text before a last bracketed group
        that runs to the end and holds no "]", without the white space before it."""
        end = len(path) - 1
        if end < 0 or path[end] != "]":
            return path
        start = path.rfind("[", path.rfind("]", 0, end) + 1, end - 1)
        return path[:start].rstrip() if start >= 0 else path

    @staticmethod
    def _normalised(parts: list[str]) -> list[str] | None:
        """Path parts as normpath leaves them, or None if they leave the directory."""
        kept: list[str] = []
        for part in parts:
            if part == "..":
                if not kept:
                    return None
                kept.pop()
            elif part not in ("", "."):
                kept.append(part)
        return kept

    @classmethod
    def _local_paths(cls, target: str) -> Iterator[list[str] | None]:
        """The paths pip 26.3 may read a requirement as, relative to where it runs.

        pip normalises the whole text as a path, with "/" as the only separator on
        POSIX and with "\\" as well on Windows, and then takes the extras off; the
        file system resolves a "." or ".." this leaves. None stands for a path that
        leaves the directory.
        """
        for separators in ("/", r"[/\\]"):
            parts = cls._normalised(re.split(separators, target))
            if parts is not None:
                rest = cls._without_extras("/".join(parts))
                parts = cls._normalised(re.split(separators, rest))
            yield parts

    @classmethod
    def _unnamed(cls, reference: str, entries: set[str]) -> bool:
        """Whether pip installs a requirement from a URL, an archive or a path other
        than the project itself, where the collector reads no package name.

        pip 26.3 takes a URL by its scheme, then a path with a separator or a leading
        ".", then a name ending in an archive extension once the extras are off;
        only then a PEP 508 requirement. Whether such a directory or file exists is
        known only where pip runs, so it is taken to exist.
        """
        named = cls._NAMED_URL.match(reference) is not None
        url = not named and cls._URL_SCHEME.match(reference.translate(cls._URL_DROPPED))
        # pip's marker separator, which a URL may contain without a space.
        target = reference.split("; " if url else ";", 1)[0].strip()
        if named:
            return cls._shadowed(target, entries)
        if url:
            # pip takes extras off a path but not off a URL: "file:.[dev]" is a
            # directory named ".[dev]".
            return "[" in target or not cls._editable_covered(target, entries)
        if not (
            any(c in target for c in "/\\")
            or target.startswith(".")
            or cls._without_extras(target).lower().endswith(cls._ARCHIVES)
        ):
            return False
        return any(path != [] for path in cls._local_paths(target))

    @classmethod
    def _shadowed(cls, target: str, entries: set[str]) -> bool:
        """Whether pip may install "name @ URL" from a local path instead.

        pip first reads the whole text as a path and installs a directory or archive
        it finds there. Such a path can exist where pip runs only if it leaves that
        directory or starts with an entry of the project root. A "~" may make the
        entry's Windows short name, and a ":" may start an NTFS stream name.
        """
        for path in cls._local_paths(target):
            if path is None:
                return True
            if path:
                first = cls._fold(path[0])
                if "~" in first or {first, first.partition(":")[0].rstrip(". ")} & entries:
                    return True
        return False

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

    def _scan_pip(self, result: ScanResult, entries: list[str]) -> list[RegistryEntryComponent]:
        packages: dict[str, _Package] = {}
        redirects: set[tuple[str, str]] = set()

        def declare(
            source: str,
            reference: str,
            group: str = "",
            hashes: tuple[str, ...] = (),
            untranslated: str | None = None,
        ) -> None:
            declaration = self._pip_declaration(
                reference, source, result, group, hashes, untranslated
            )
            if declaration is not None:
                packages.setdefault(declaration.name, _Package()).add(declaration)

        self._scan_requirements(result, entries, declare, redirects)
        for text, group, untranslated in self._pyproject_declarations(result, redirects):
            # Compare the text the requirement is parsed from, without a trailing comment.
            declare(
                "pyproject.toml", text.strip().split(" #", 1)[0].strip(), group, (), untranslated
            )
        if "Pipfile" in entries:
            # pipenv installs what Pipfile declares; it is not read.
            result.surfaces_excluded.append("Pipfile: dependencies not read")
        components = [self._pypi_component(package) for package in packages.values()]
        if components:
            # A lockfile records a registry resolution, so it does not stand for a
            # package that a URL, VCS or path declaration installs, in any file.
            from_urls = {
                name
                for name, package in packages.items()
                if any(
                    d.requirement is not None and d.requirement.url for d in package.declarations
                )
            }
            self._resolve_python_lockfiles(components, result, from_urls)
            indexed = [
                component
                for component, package in zip(components, packages.values(), strict=True)
                if not all(
                    d.requirement is not None and d.requirement.url for d in package.declarations
                )
            ]
            if indexed:
                self._redirect_python(result, indexed, redirects)
        return components

    def _redirect_python(
        self,
        result: ScanResult,
        components: list[RegistryEntryComponent],
        redirects: set[tuple[str, str]],
    ) -> None:
        """Record on every package installed from an index the settings that redirect it.

        pip applies index options and its configuration to every package of a run, and
        uv, Poetry and PDM their sources to every package they resolve; which files one
        install reads is not known, so each such setting may apply to each package.
        """
        for name in _PIP_CONFIG_FILES:
            text = self._read(name, result)
            if text is None:
                continue
            settings = _pip_config(text)
            if settings is None:
                result.surfaces_excluded.append(
                    f"{name}: not read as pip reads it; index settings not resolved"
                )
                continue
            redirects.update((f"{name}:{key}", value) for key, value in settings)
        uv = self._toml("uv.toml", result)
        if uv is not None:
            redirects.update(self._uv_redirects(uv, "uv.toml:"))
        found = sorted(
            (label, value) for label, value in redirects if not _DEFAULT_PYPI_INDEX.fullmatch(value)
        )
        if not found:
            return
        sources = _SourceLabels().entries(found)
        named = _named(found)
        for component in components:
            if "package_resolution" not in component.claims:
                # PyPI was assumed, not recorded; a lockfile record names its index.
                component.registry_uri = None
            _redirect(
                component,
                list(sources),
                f"PyPI package '{component.name}' may resolve from an index or location that "
                f"the project configures ({named}); its name and version do not establish "
                "identity.",
            )

    def _resolve_python_lockfiles(
        self,
        components: list[RegistryEntryComponent],
        result: ScanResult,
        from_urls: set[str],
    ) -> None:
        files = self._confined()
        found_locks: list[tuple[str, str, bytes]] = []
        for lock_name, method in (("uv.lock", "uv-lockfile"), ("poetry.lock", "poetry-lockfile")):
            raw = files.read_bytes(lock_name, missing_ok=True)
            if raw is not None:
                result.surfaces_scanned.append(lock_name)
                found_locks.append((lock_name, method, raw))
        if not found_locks:
            return
        if len(found_locks) > 1:
            result.surfaces_excluded.append(
                "multiple Python lockfiles present (uv.lock and poetry.lock); resolution is ambiguous"
            )
            return
        lock_name, method, lock_bytes = found_locks[0]
        try:
            text = lock_bytes.decode("utf-8")
            if self._longest_dotted_key(text) > _LONGEST_DOTTED_KEY:
                # As for pyproject.toml: tomllib's cost grows with the square of a
                # dotted key's parts, and lockfile keys have one or two.
                raise ValueError("dotted key exceeds the length limit")
            lock_doc = tomllib.loads(text)
            packages = lock_doc.get("package", [])
            if (
                not isinstance(lock_doc, dict)
                or not isinstance(packages, list)
                or len(packages) > 10_000
                or not all(isinstance(item, dict) for item in packages)
            ):
                raise ValueError("unsupported Python lockfile structure")
        except (ValueError, UnicodeError, RecursionError, MemoryError):
            # TOMLDecodeError is a ValueError, as is a decimal integer past CPython's
            # limit on digits it converts.
            result.scan_failures.append(f"{lock_name}: invalid or unsupported lockfile")
            return
        lock_digest = hash_bytes(lock_bytes)
        indexed: dict[str, list[tuple[int, dict[str, Any]]]] = {}
        for index, entry in enumerate(packages):
            raw_name = entry.get("name")
            if not isinstance(raw_name, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", raw_name
            ):
                result.scan_failures.append(f"{lock_name}: invalid package entry name")
                continue
            indexed.setdefault(str(canonicalize_name(raw_name)), []).append((index, entry))
        for comp in components:
            matches = indexed.get(comp.name)
            if not matches or comp.name in from_urls:
                continue
            if comp.version and (";" in comp.version or comp.version.startswith("@ ")):
                continue
            if len(matches) > 1:
                result.surfaces_excluded.append(
                    f"{lock_name}: multiple package resolutions for {comp.name} are ambiguous"
                )
                continue
            index, record = matches[0]
            source = record.get("source")
            if source is not None and not isinstance(source, dict):
                result.scan_failures.append(f"{lock_name}: invalid selected package source")
                continue
            if isinstance(source, dict):
                non_registry_keys = {"editable", "directory", "path", "git", "virtual", "url"}
                if (method == "uv-lockfile" and non_registry_keys.intersection(source)) or (
                    method == "poetry-lockfile"
                    and source.get("type") in {"directory", "file", "git", "url"}
                ):
                    result.surfaces_excluded.append(
                        f"{lock_name}: non-registry package source is unverified"
                    )
                    continue
            resolved_version = record.get("version")
            pinned = (
                extract_version_pin(f"{comp.name}=={resolved_version}", ecosystem="python")
                if isinstance(resolved_version, str) and len(resolved_version) <= _LONGEST_VERSION
                else None
            )
            if pinned is None or pinned != resolved_version:
                result.scan_failures.append(f"{lock_name}: selected package lacks an exact version")
                continue
            registry_origin: str | None = "https://pypi.org"
            if isinstance(source, dict):
                raw_url = source.get("registry") if method == "uv-lockfile" else source.get("url")
                if isinstance(raw_url, str) and raw_url.startswith(("https://", "http://")):
                    origin = sanitized_origin(raw_url)
                    registry_origin = origin if origin != "[redacted]" else None
            locator = f"{lock_name}#/package/{index}"
            comp.version = resolved_version
            comp.package_url = (
                f"pkg:pypi/{quote(comp.name, safe='')}@{quote(resolved_version, safe='')}"
            )
            comp.registry_uri = registry_origin
            comp.source_path = lock_name
            comp.assurance_level = AssuranceLevel.DECLARED
            comp.properties.update(
                {
                    "collection_mode": "lockfile-resolution-claim",
                    "lockfile_sha256": lock_digest,
                    "lockfile_record": locator,
                    "artifact_verified": False,
                }
            )
            comp.claims["package_resolution"] = ClaimEvidence(
                assurance=AssuranceLevel.DECLARED,
                method=method,
                scope="dependency-resolution",
                collector="registry",
                locator=locator,
            )

    def _scan_requirements(
        self,
        result: ScanResult,
        entries: list[str],
        declare: Callable[[str, str, str, tuple[str, ...]], None],
        redirects: set[tuple[str, str]],
    ) -> None:
        filenames = self._requirement_files(entries)
        names = {n.casefold() for n in filenames}
        folded = {self._fold(n) for n in entries}
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
            content = self._read(filename, result)
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
                    # that reaches beyond what is read here is a coverage gap. Index
                    # options add no package, but pip applies them to every package
                    # of the run that reads them.
                    options, gaps = self._options(text)
                    gaps += self._option_gaps(options, names, folded)
                    redirects.update(
                        (f"{filename}:{option}", value)
                        for option, value in options
                        if option in _PIP_INDEX_OPTIONS
                    )
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
                    option_text = " ".join(tokens[split:])
                    options, _ = self._options(option_text)
                    if self._unsplittable(option_text):
                        # Too long to split: an -e among them would go unseen.
                        gaps = ["option line not parsed"]
                    # pip accepts only these; other text after --hash is not recorded.
                    hashes = tuple(
                        sorted(
                            {v for o, v in options if o == "--hash" and _HASH_VALUE.fullmatch(v)}
                        )
                    )
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
                        declare(filename, reference, "", hashes)
                for gap in gaps:
                    message = f"{filename}: {gap}"
                    if message not in noted:
                        noted.add(message)
                        result.surfaces_excluded.append(message)

    @staticmethod
    def _longest_dotted_key(text: str) -> int:
        """The most dots between two TOML structure characters outside strings and
        comments, in one linear pass: a dotted key or table name has that many.

        A string is skipped without ending the count, since a quoted part such as
        "" or 'a' is still one part of a dotted key.
        """
        longest = dots = 0
        position = 0
        while True:
            found = _TOML_SPECIAL.search(text, position)
            if found is None:
                return max(longest, dots)
            char, position = found.group(), found.end()
            if char == ".":
                dots += 1
            elif char in "\"'":
                position = _toml_string_end(text, position, char)
            else:
                longest, dots = max(longest, dots), 0
                if char == "#":
                    newline = text.find("\n", position)
                    position = len(text) if newline < 0 else newline

    def _toml(self, name: str, result: ScanResult) -> dict[str, Any] | None:
        """A root TOML file read within the bounds that keep tomllib's work linear."""
        content = self._read(name, result)
        if content is None:
            return None
        if len(content) > _PYPROJECT_BUDGET:
            result.scan_failures.append(f"{name}: exceeds the size limit: not read")
            return None
        if self._longest_dotted_key(content) > _LONGEST_DOTTED_KEY:
            result.scan_failures.append(f"{name}: dotted key exceeds the length limit: not read")
            return None
        try:
            return tomllib.loads(content)
        except (ValueError, RecursionError, MemoryError):
            # TOMLDecodeError is a ValueError; tomllib raises a plain one for a decimal
            # integer past CPython's limit on digits it converts.
            result.scan_failures.append(f"{name}: invalid TOML")
            return None

    def _pyproject_declarations(
        self, result: ScanResult, redirects: set[tuple[str, str]]
    ) -> list[tuple[str, str, str | None]]:
        """Each declaration with its group ("" for none) and, when it is not translated,
        why. The index settings of uv, Poetry and PDM go to ``redirects``."""
        data = self._toml("pyproject.toml", result)
        if data is None:
            return []
        declarations: list[tuple[str, str, str | None]] = []
        project = data.get("project", {})
        if not isinstance(project, dict):
            result.scan_failures.append("pyproject.toml: invalid project table")
            return []
        failures: dict[str, None] = {}
        gaps: dict[str, None] = {}

        def strings(value: Any, group: str, failure: str) -> None:
            if isinstance(value, list) and all(isinstance(item, str) for item in value):
                declarations.extend((item, group, None) for item in value)
            else:
                failures[failure] = None

        strings(project.get("dependencies", []), "", "pyproject.toml: invalid project dependencies")
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for extra, values in optional.items():
                strings(values, str(extra), "pyproject.toml: invalid optional dependencies")
        build = data.get("build-system", {})
        strings(
            build.get("requires", []) if isinstance(build, dict) else None,
            "build-system",
            "pyproject.toml: invalid build-system requires",
        )
        self._dependency_groups(data.get("dependency-groups", {}), declarations, failures)
        tool = data.get("tool", {})
        tool = tool if isinstance(tool, dict) else {}
        self._uv_declarations(tool.get("uv", {}), declarations, failures, gaps, strings)
        self._pdm_declarations(tool.get("pdm", {}), declarations, failures, gaps, strings)
        self._poetry_declarations(tool.get("poetry", {}), declarations, failures, gaps)
        redirects.update(self._uv_redirects(tool.get("uv"), "pyproject.toml:tool.uv."))
        for name, shown in (("poetry", "Poetry"), ("pdm", "PDM")):
            found = self._source_redirects(tool.get(name), name)
            if found is None:
                failures[f"pyproject.toml: invalid {shown} source"] = None
            else:
                redirects.update(found)
        result.scan_failures.extend(failures)
        result.surfaces_excluded.extend(gaps)
        return declarations

    @staticmethod
    def _dependency_groups(
        groups: Any, declarations: list[tuple[str, str, str | None]], failures: dict[str, None]
    ) -> None:
        """PEP 735 groups. An included group is read as a group of its own; group
        names are compared in their normal form, as PEP 735 requires."""
        failure = "pyproject.toml: invalid dependency groups"
        if not isinstance(groups, dict):
            failures[failure] = None
            return
        names = {canonicalize_name(str(name)) for name in groups}
        for name, values in groups.items():
            if not isinstance(values, list):
                failures[failure] = None
                continue
            for value in values:
                if isinstance(value, str):
                    declarations.append((value, f"group:{canonicalize_name(str(name))}", None))
                elif not (
                    isinstance(value, dict)
                    and set(value) == {"include-group"}
                    and isinstance(value["include-group"], str)
                    and canonicalize_name(value["include-group"]) in names
                ):
                    failures[failure] = None

    _UV_GAPS = {
        "source": "pyproject.toml: uv source not translated",
        "override": "pyproject.toml: uv override or constraint not followed",
        "workspace": "pyproject.toml: uv workspace members not followed",
    }

    @classmethod
    def _uv_declarations(
        cls,
        uv: Any,
        declarations: list[tuple[str, str, str | None]],
        failures: dict[str, None],
        gaps: dict[str, None],
        strings: Callable[[Any, str, str], None],
    ) -> None:
        """uv's development dependencies, and the sources, overrides and constraints
        that change what an inventoried package resolves to."""
        failure = "pyproject.toml: invalid uv table"
        if not isinstance(uv, dict):
            failures[failure] = None
            return
        strings(uv.get("dev-dependencies", []), "uv:dev", failure)
        workspace = uv.get("workspace", {})
        if not isinstance(workspace, dict):
            failures[failure] = None
        elif workspace.get("members"):
            # uv sync installs what each member's pyproject.toml declares.
            gaps[cls._UV_GAPS["workspace"]] = None
        sources = uv.get("sources", {})
        if not isinstance(sources, dict):
            failures[failure] = None
            sources = {}
        for name in sources:
            if cls._is_ai_package(str(name)):
                # A git, URL, path, workspace or index source replaces the package.
                declarations.append((str(name), "", "source"))
                gaps[cls._UV_GAPS["source"]] = None
        for key in ("override-dependencies", "constraint-dependencies"):
            values = uv.get(key, [])
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                failures[failure] = None
                continue
            for value in values:
                name = cls._PIP_NAME.match(value)
                if name is not None and cls._is_ai_package(name.group()):
                    gaps[cls._UV_GAPS["override"]] = None
                    if key == "override-dependencies":
                        declarations.append((name.group(), "", "override"))

    @staticmethod
    def _uv_redirects(settings: Any, label: str) -> list[tuple[str, str]]:
        """The index settings of a uv table and of its pip table: every index but an
        explicit one, which serves only the packages a source names and is a gap there."""
        if not isinstance(settings, dict):
            return []
        found: list[tuple[str, str]] = []
        for table, prefix in ((settings, label), (settings.get("pip"), label + "pip.")):
            if not isinstance(table, dict):
                continue
            chosen = {
                key: table[key]
                for key in ("index-url", "extra-index-url", "find-links")
                if key in table
            }
            if "index" in table:
                indexes = table["index"] if isinstance(table["index"], list) else [table["index"]]
                chosen["index"] = [
                    index
                    for index in indexes
                    if not (isinstance(index, dict) and index.get("explicit") is True)
                ]
            found += [(prefix + key, value) for key, value in _uv_settings(chosen).settings]
        return found

    @staticmethod
    def _source_redirects(table: Any, tool: str) -> list[tuple[str, str]] | None:
        """The package sources of a Poetry or PDM table that may serve any package.

        A Poetry source with ``priority = "explicit"`` serves only the dependencies that
        name it, which are gaps already. A source without a URL other than Poetry's
        ``PyPI`` cannot be read, and neither can a source list that is not a list of
        tables: None.
        """
        sources = table.get("source", []) if isinstance(table, dict) else []
        if not isinstance(sources, list) or not all(isinstance(item, dict) for item in sources):
            return None
        found: list[tuple[str, str]] = []
        for source in sources:
            if tool == "poetry" and source.get("priority") == "explicit":
                continue
            url = source.get("url")
            if isinstance(url, str):
                found.append((f"pyproject.toml:tool.{tool}.source", url))
            elif not (
                url is None and tool == "poetry" and str(source.get("name")).lower() == "pypi"
            ):
                return None
        return found

    @classmethod
    def _pdm_declarations(
        cls,
        pdm: Any,
        declarations: list[tuple[str, str, str | None]],
        failures: dict[str, None],
        gaps: dict[str, None],
        strings: Callable[[Any, str, str], None],
    ) -> None:
        failure = "pyproject.toml: invalid PDM table"
        if not isinstance(pdm, dict):
            failures[failure] = None
            return
        groups = pdm.get("dev-dependencies", {})
        if not isinstance(groups, dict):
            failures[failure] = None
            groups = {}
        for group, values in groups.items():
            strings(values, f"pdm:{group}", failure)
        resolution = pdm.get("resolution", {})
        overrides = resolution.get("overrides", {}) if isinstance(resolution, dict) else None
        if not isinstance(overrides, dict):
            failures[failure] = None
            return
        for name in overrides:
            if cls._is_ai_package(str(name)):
                declarations.append((str(name), "", "override"))
                gaps["pyproject.toml: PDM override not followed"] = None

    def _poetry_declarations(
        self,
        poetry: Any,
        declarations: list[tuple[str, str, str | None]],
        failures: dict[str, None],
        gaps: dict[str, None],
    ) -> None:
        if not isinstance(poetry, dict):
            failures[self._POETRY_PROBLEMS["table"]] = None
            return
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
                        declarations.append((text, group_label, None))
                        continue
                    declarations.append((name, group_label, problem))
                    record = failures if problem == "invalid" else gaps
                    record[self._POETRY_PROBLEMS[problem]] = None

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

    # Containerfile is the name Podman and Buildah read by default.
    _DOCKERFILES = ("Dockerfile", "Dockerfile.agent", "Containerfile")
    # Compose reads the first of the four base names that exists and merges the
    # first override file; every one of them is read, so none can hide an image.
    _COMPOSE_FILES = (
        "compose.yaml",
        "compose.yml",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.override.yml",
        "compose.override.yaml",
        "docker-compose.override.yml",
        "docker-compose.override.yaml",
    )

    def _scan_docker(self, result: ScanResult) -> list[RegistryEntryComponent]:
        environment = self._confined().read_bytes(".env", missing_ok=True)
        if environment is not None:
            # Read as bytes, so that no encoding fails the collector; nothing in it
            # is recorded.
            result.surfaces_scanned.append(".env")
            if self._names_compose_file(environment):
                # Compose reads the files it names instead of the default ones.
                result.surfaces_excluded.append(".env: COMPOSE_FILE not followed")
        # One component per image, with every file that names it.
        found: dict[str, list[str]] = {}
        unresolved: set[str] = set()
        models: set[str] = set()

        def collect(image: str, filename: str, gaps: Iterable[str]) -> None:
            files = found.setdefault(image, [])
            if filename not in files:
                files.append(filename)
            if gaps:
                unresolved.add(image)

        for filename in self._DOCKERFILES:
            content = self._read(filename, result)
            if content is None:
                continue
            images, gaps = self._dockerfile_images(content)
            result.surfaces_excluded.extend(f"{filename}: {gap}" for gap in gaps)
            for image in images:
                collect(image, filename, self._image_gaps(image))
        for filename in self._COMPOSE_FILES:
            content = self._read(filename, result)
            if content is None:
                continue
            read = self._compose_images(content)
            if read is None:
                result.scan_failures.append(f"{filename}: YAML mapping parse failed or unsupported")
                continue
            images, model_references, gaps = read
            result.surfaces_excluded.extend(f"{filename}: {gap}" for gap in gaps)
            for image in images:
                collect(image, filename, self._image_gaps(image))
            for reference in model_references:
                # A model Docker Model Runner pulls is AI-related whatever its name.
                models.add(reference)
                collect(reference, filename, self._image_gaps(reference))
        components: list[RegistryEntryComponent] = []
        noted: set[str] = set()
        for raw, files in found.items():
            if not (is_ai_image(raw) or raw in models):
                continue
            component = self._image_component(raw, files, raw in unresolved, raw in models)
            if component is None:
                for filename in files:
                    message = f"{filename}: image reference not parsed"
                    if message not in noted:
                        noted.add(message)
                        result.surfaces_excluded.append(message)
                continue
            components.append(component)
        return components

    @staticmethod
    def _names_compose_file(environment: bytes) -> bool:
        """Whether a .env mentions COMPOSE_FILE, in any letter case.

        Compose's dotenv parser reads statements, not lines: it skips any Unicode
        space before a name and before "=", and a statement can start right after a
        closing quote. No line pattern finds every setting, so any mention counts; one
        in a comment or a value costs only a false gap.
        """
        return "COMPOSE_FILE" in environment.decode("utf-8", "replace").upper()

    @staticmethod
    def _image_gaps(image: str) -> list[str]:
        """Why an image as written is not the image pulled; the parsers record the gap."""
        return ["unresolved"] if "$" in image or any(c in image for c in "\"'\\") else []

    @staticmethod
    def _image_component(
        raw: str, files: list[str], unresolved: bool, model: bool = False
    ) -> RegistryEntryComponent | None:
        properties: dict[str, Any] = {
            "collection_mode": "manifest-reference",
            "registry_origin_verified": False,
        }
        if model:
            properties["artifact_type"] = "model"
        if len(files) > 1:
            properties["source_paths"] = sorted(files)
        registry_type: str | None = None
        registry_uri = None
        package_url = None
        if unresolved:
            # Kept as written, with the gap that says why it is not the image pulled.
            name = redact_text(raw)
            has_digest = "@" in raw and _PULLED_DIGEST.fullmatch(raw.rpartition("@")[2]) is not None
            has_tag = ":" in raw.rsplit("/", 1)[-1] and not raw.endswith(":latest")
        else:
            reference = parse_image_reference(raw)
            if reference is None:
                return None
            # A valid reference holds no credential, so it is recorded exactly: a
            # redacted one could give two tags the same name.
            name = raw
            has_digest = reference.pinned
            has_tag = reference.tag not in (None, "latest")
            registry_type = "docker-hub" if reference.domain == "docker.io" else "oci"
            registry_uri = f"https://{reference.domain}"
            properties["image_repository"] = reference.repository
            if reference.digest is not None and has_digest:
                qualifiers = {"repository_url": reference.repository}
                if reference.tag is not None:
                    qualifiers["tag"] = reference.tag
                package_url = PackageURL(
                    type="oci",
                    name=reference.path.rsplit("/", 1)[-1],
                    version=reference.digest,
                    qualifiers=qualifiers,
                ).to_string()
        risks: list[RiskAssessment] = []
        if not has_digest:
            risks.append(
                _risk(
                    RiskSeverity.MEDIUM if has_tag else RiskSeverity.HIGH,
                    "mutable_image_tag" if has_tag else "version_pinning",
                    f"Docker image '{name}' lacks an immutable digest pin.",
                    "Pin to a SHA256 artifact digest and verify its provenance.",
                )
            )
        return RegistryEntryComponent(
            bom_ref=f"registry:docker/{name}",
            name=name,
            package_url=package_url,
            registry_type=registry_type,
            registry_uri=registry_uri,
            source_path=files[0],
            trust_tier=TrustTier.UNKNOWN,
            risks=risks,
            properties=properties,
        )

    # The pre-scan bounds YAML's work as Scanner._read_mapping does; the walk below
    # bounds what merge keys add.
    _COMPOSE_TOKENS = 20_000
    _COMPOSE_STEPS = 100_000

    @classmethod
    def _compose_images(cls, text: str) -> tuple[list[str], list[str], list[str]] | None:
        """Service images and top-level models in a Compose file, and what was not followed.

        The YAML is composed into nodes, never constructed: an alias is the node it
        names, not a copy, and values keep the text Compose reads. Merge keys are
        followed as YAML defines them, once per mapping and within a step budget.
        None when the file is not a YAML mapping read this way.
        """
        try:
            import yaml
        except ImportError:
            return None
        try:
            for index, _ in enumerate(yaml.scan(text, Loader=yaml.SafeLoader)):
                if index >= cls._COMPOSE_TOKENS:
                    return None
            root = yaml.compose(text, Loader=yaml.SafeLoader)
            if root is None:
                return [], [], []
            return _ComposeWalk(cls._COMPOSE_STEPS).images(root)
        except (yaml.YAMLError, RecursionError, ValueError):
            return None

    # BuildKit's word separators; a no-break space is part of a word.
    _DOCKER_WORD = re.compile(r"[^\t\v\f\r ]+")
    # Go's unicode.IsSpace, which BuildKit trims lines with and splits shell words on;
    # str.strip() would also take \x1c-\x1f.
    _GO_SPACE = (
        "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008"
        "\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
    )
    # Go's \s, which has no \v.
    _GO_REGEX_SPACE = "\t\n\f\r "
    _DIRECTIVE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9]*")
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
    def _directive(cls, line: str) -> tuple[str, str] | None:
        """A parser directive as BuildKit's ^#\\s*([a-zA-Z][a-zA-Z0-9]*)\\s*=\\s*(.+?)\\s*$
        matches it, in linear time.

        The value is the rest of the line without the white space around it; when
        the rest is only white space, the lazy group still takes its last character.
        """
        if not line.startswith("#"):
            return None
        rest = line[1:].lstrip(cls._GO_REGEX_SPACE)
        name = cls._DIRECTIVE_NAME.match(rest)
        if name is None:
            return None
        rest = rest[name.end() :].lstrip(cls._GO_REGEX_SPACE)
        if not rest.startswith("="):
            return None
        rest = rest[1:]
        value = rest.strip(cls._GO_REGEX_SPACE) or rest[-1:]
        return (name.group(), value) if value else None

    @staticmethod
    def _heredoc_word(word: str) -> tuple[bool, str] | None:
        """A raw word as [0-9]*<<(-?)[\\t\\n\\f\\r ]*([^<]*) matches it whole, in linear
        time: whether leading tabs are removed, and the terminator as written."""
        start = len(word) - len(word.lstrip("0123456789"))
        if not word.startswith("<<", start):
            return None
        rest = word[start + 2 :]
        chomp = rest.startswith("-")
        rest = rest[chomp:].lstrip("\t\n\f\r ")
        return None if "<" in rest else (chomp, rest)

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
            directive = cls._directive(line.rstrip("\r").lstrip(cls._GO_SPACE))
            if directive is None:
                break
            if directive[0].lower() == "escape" and directive[1] != "\\":
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
        return word.replace("İ", "i").lower()

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
            match = cls._heredoc_word(word)
            if match is None or not match[1]:
                continue
            name = cls._shell_words(match[1], raw=False)
            if name is None:
                return None
            if len(name) == 1:
                heredocs.append((name[0], match[0]))
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
        except (InvalidRequirement, RecursionError):
            return False
        if str(first.marker or "") != str(second.marker or ""):
            return False
        state = _Declared()
        state.add(first)
        return state.add(second)

    @staticmethod
    def _is_ai_package(name: str) -> bool:
        """Whether a PyPI or npm package name is in the catalog, after normalisation.

        pip, uv and Poetry treat "Llama.Index", "llama_index" and "llama-index" as
        one package, so every spelling matches as its normal form does.
        """
        normal = _SEPARATORS.sub("-", name).lower()
        base = normal
        scope, slash, rest = normal.partition("/")
        if slash and scope.startswith("@"):
            if scope in AI_PACKAGE_SCOPES:
                return True
            base = rest
        return (
            normal in AI_PACKAGE_NAMES
            or base.startswith(AI_PACKAGE_PREFIXES)
            or not AI_PACKAGE_WORDS.isdisjoint(base.split("-"))
        )


class _ComposeWalk:
    """Service images found by walking a Compose file's YAML nodes.

    A mapping's keys are its own keys, then those of the mappings its merge keys
    name, earlier ones first, as YAML's merge key type defines. Each mapping's keys
    are worked out once; a mapping that merges itself, directly or through
    others, is a gap rather than a loop. An alias is the node it names, so each
    image, model, build, inline Dockerfile and build path node is read once,
    however many services share it, through aliases or merge keys.
    """

    _STR = "tag:yaml.org,2002:str"
    _NULL = "tag:yaml.org,2002:null"
    # The scalars YAML 1.1 and 1.2 both read as null.
    _NULL_TEXT = frozenset({"", "~", "null", "Null", "NULL"})
    # Linux's PATH_MAX. A longer build path is not followed, even one that names the
    # project root, and is never split.
    _LONGEST_PATH = 4_096

    def __init__(self, budget: int) -> None:
        self.budget = budget
        self.gaps: dict[str, None] = {}
        self._keys: dict[int, dict[str, Any]] = {}
        self._open: set[int] = set()
        self._read: set[tuple[str, int]] = set()
        self._paths: dict[int, list[str] | None] = {}

    def _spend(self, steps: int = 1) -> None:
        self.budget -= steps
        if self.budget < 0:
            raise ValueError("compose walk budget exhausted")

    def _first(self, role: str, node: Any) -> bool:
        """Whether a node is read in this role for the first time."""
        read = (role, id(node))
        if read in self._read:
            return False
        self._read.add(read)
        return True

    def keys(self, node: Any) -> dict[str, Any]:
        import yaml

        known = self._keys.get(id(node))
        if known is not None:
            return known
        if not isinstance(node, yaml.MappingNode):
            raise ValueError("expected a mapping")
        if id(node) in self._open:
            self.gaps["YAML merge key cycle not followed"] = None
            return {}
        self._open.add(id(node))
        own: dict[str, Any] = {}
        merged: list[Any] = []
        for key, value in node.value:
            self._spend()
            if key.tag == "tag:yaml.org,2002:merge":
                merged.extend(value.value if isinstance(value, yaml.SequenceNode) else [value])
            elif isinstance(key, yaml.ScalarNode):
                if key.tag == "tag:yaml.org,2002:binary" or not key.tag.startswith(
                    "tag:yaml.org,2002:"
                ):
                    # Compose would read another key than the text, such as the
                    # base64-decoded name of a !!binary key.
                    raise ValueError("tagged key")
                if key.value in own:
                    # Compose refuses a mapping with a repeated key.
                    raise ValueError("duplicate key")
                own[key.value] = value
            else:
                raise ValueError("complex key")
        result = dict(own)
        for source in merged:
            inherited = self.keys(source)
            self._spend(len(inherited))
            for name, value in inherited.items():
                result.setdefault(name, value)
        self._open.discard(id(node))
        self._keys[id(node)] = result
        return result

    def images(self, root: Any) -> tuple[list[str], list[str], list[str]]:
        """Service images, the references of top-level models, and the gaps."""
        import yaml

        top = self.keys(root)
        if "include" in top:
            self.gaps["include not followed"] = None
        images: list[str] = []
        models: list[str] = []
        declared = top.get("models")
        if declared is not None and not self._empty(declared):
            for model in self.keys(declared).values():
                reference = (
                    model if isinstance(model, yaml.ScalarNode) else self.keys(model).get("model")
                )
                if reference is not None and self._first("model", reference):
                    models.extend(self._image(reference))
        services = top.get("services")
        if services is None or self._empty(services):
            return images, models, list(self.gaps)
        for service in self.keys(services).values():
            fields = self.keys(service)
            image = fields.get("image")
            if image is not None and self._first("image", image):
                images.extend(self._image(image))
            build = fields.get("build")
            if build is not None and self._first("build", build):
                images.extend(self._build(build))
            extends = fields.get("extends")
            if isinstance(extends, yaml.MappingNode) and "file" in self.keys(extends):
                self.gaps["extends not followed"] = None
        return images, models, list(self.gaps)

    def _empty(self, node: Any) -> bool:
        import yaml

        return isinstance(node, yaml.ScalarNode) and (
            node.value in self._NULL_TEXT and node.tag in (self._NULL, self._STR, "!reset")
        )

    def _text(self, node: Any, gap: str) -> str | None:
        """The text Compose reads from a scalar: "" when it holds none, None after
        recording the gap.

        An untagged or !!str scalar, or one with Compose's !override, is read as
        written, and !reset or null hold no value. Any other tag can make Compose
        read other text, such as base64-decoded !!binary, or nothing at all.
        """
        if node.tag == "!reset" or (node.tag == self._NULL and node.value in self._NULL_TEXT):
            return ""
        if node.tag not in (self._STR, "!override"):
            self.gaps[gap] = None
            return None
        return str(node.value)

    def _image(self, node: Any) -> list[str]:
        import yaml

        if not isinstance(node, yaml.ScalarNode):
            self.gaps["image not parsed"] = None
            return []
        value = (self._text(node, "tagged image value not resolved") or "").strip()
        if not value:
            # No image, such as an override file's !reset, or a gap recorded.
            return []
        if "$" in value:
            # Compose fills ${NAME} from the environment and .env.
            self.gaps["image substitution not resolved"] = None
        return [value]

    def _build(self, node: Any) -> list[str]:
        """A build's FROM images when its Dockerfile is inline or is a root Dockerfile
        the collector reads; otherwise a gap."""
        import yaml

        unread = "build context not followed"
        context: list[str] | None
        dockerfile: list[str] | None
        if isinstance(node, yaml.ScalarNode):
            text = self._text(node, "build not followed")
            if not text:
                # No build, such as an override file's !reset, or a gap recorded.
                return []
            context, dockerfile = self._parts(node, text), ["Dockerfile"]
        elif isinstance(node, yaml.MappingNode):
            fields = self.keys(node)
            if self._named_contexts(fields):
                # BuildKit uses a named context in place of the image that a FROM
                # line of that name pulls.
                self.gaps[unread] = None
            if "dockerfile_inline" in fields:
                return self._inline(fields["dockerfile_inline"])
            context = self._path(fields.get("context"), ".")
            dockerfile = self._path(fields.get("dockerfile"), "Dockerfile")
        else:
            self.gaps["build not followed"] = None
            return []
        if not (
            context == []
            and dockerfile is not None
            and len(dockerfile) == 1
            and dockerfile[0] in RegistryScanner._DOCKERFILES
        ):
            # The Dockerfile it builds from is not one the collector reads.
            self.gaps[unread] = None
        return []

    def _named_contexts(self, fields: dict[str, Any]) -> bool:
        """Whether a build names contexts: Compose's additional_contexts, or the
        contexts that docker buildx bake reads from x-bake in the same file."""
        import yaml

        bake = fields.get("x-bake")
        if isinstance(bake, yaml.MappingNode):
            bake = self.keys(bake).get("contexts")
        return any(
            node is not None and not self._unset(node)
            for node in (fields.get("additional_contexts"), bake)
        )

    def _unset(self, node: Any) -> bool:
        """Whether a node holds no entries: null, empty, or Compose's !reset."""
        import yaml

        if node.tag == "!reset":
            return True
        return self._empty(node) if isinstance(node, yaml.ScalarNode) else not node.value

    def _path(self, node: Any, default: str) -> list[str] | None:
        """A build path setting's parts, its default's when unset, or None when the
        collector does not follow it."""
        import yaml

        if node is None:
            return self._local(default)
        if not isinstance(node, yaml.ScalarNode):
            return None
        text = self._text(node, "build context not followed")
        if text is None:
            return None
        return self._parts(node, text) if text else self._local(default)

    def _parts(self, node: Any, text: str) -> list[str] | None:
        """A scalar's path parts, worked out once however many builds share it."""
        if id(node) not in self._paths:
            self._paths[id(node)] = self._local(text)
        return self._paths[id(node)]

    @classmethod
    def _local(cls, path: str) -> list[str] | None:
        """A relative path's parts as Compose resolves it, None for any other path.

        An absolute path, such as "/" for the root of the host, is not the project
        root; a backslash separates paths on Windows. A path too long to open is not
        split at all.
        """
        if len(path) > cls._LONGEST_PATH or path.startswith("/") or "\\" in path:
            return None
        return RegistryScanner._normalised(path.split("/"))

    def _inline(self, node: Any) -> list[str]:
        """The FROM images of an inline Dockerfile, parsed once however many builds
        share it."""
        import yaml

        text = self._text(node, "build not followed") if isinstance(node, yaml.ScalarNode) else None
        if not text:
            self.gaps["build not followed"] = None
            return []
        if not self._first("dockerfile_inline", node):
            return []
        images, gaps = RegistryScanner._dockerfile_images(text)
        for gap in gaps:
            self.gaps[f"dockerfile_inline {gap}"] = None
        return images
