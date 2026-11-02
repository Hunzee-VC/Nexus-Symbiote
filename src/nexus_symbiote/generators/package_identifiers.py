"""Project declared package URLs into ordinary standards fields without upgrading trust."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import parse_qsl, unquote

from packageurl import PackageURL
from packaging.specifiers import Specifier
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from nexus_symbiote.core.hashing import extract_version_pin
from nexus_symbiote.core.models import AnyComponent, RegistryEntryComponent


@dataclass(frozen=True)
class PackageIdentifierProjection:
    value: str | None
    status: Literal["declared", "unknown", "unavailable-invalid"]
    version: str | None = None


def package_identifier(component: AnyComponent) -> PackageIdentifierProjection:
    """Validate and canonicalize a declared identifier, not its publisher or artifact.

    The parser normalizes casing and escaping. Reject ambiguous or damaged input
    before that normalization; otherwise a newline or malformed escape could be
    silently repaired into an apparently usable identifier. PyPI/npm identities
    also agree with the component's declared ecosystem, name and exact version.
    Unsupported or invalid claims remain available in the native extension only.
    """
    if not isinstance(component, RegistryEntryComponent) or component.package_url is None:
        return PackageIdentifierProjection(None, "unknown")
    value = component.package_url
    invalid = PackageIdentifierProjection(None, "unavailable-invalid")
    if (
        not value
        or len(value) > 2048
        or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
        or re.match(r"^pkg:[a-z][a-z0-9.+-]*/", value) is None
        or re.search(r"%(?![0-9A-Fa-f]{2})", value)
    ):
        return invalid
    try:
        decoded = unquote(value, errors="strict")
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in decoded):
            return invalid
        # PackageURL normalizes dot segments in subpaths. Never silently discard
        # a supplied traversal segment when projecting a producer's declaration.
        main, _, raw_fragment = value.partition("#")
        raw_path, _, raw_query = main.partition("?")
        path = unquote(raw_path, errors="strict")
        fragment = unquote(raw_fragment, errors="strict")
        segments = [*path.split("/"), *(fragment.split("/") if fragment else [])]
        if any(part in {"", ".", ".."} for part in segments):
            return invalid
        if raw_query:
            qualifiers = parse_qsl(
                raw_query, keep_blank_values=True, strict_parsing=True, errors="strict"
            )
            keys = [key.lower() for key, _ in qualifiers]
            if len(keys) != len(set(keys)) or any(not content for _, content in qualifiers):
                return invalid
        parsed = PackageURL.from_string(value)
        if not _agrees_with_component(parsed, component):
            return invalid
        return PackageIdentifierProjection(parsed.to_string(), "declared", parsed.version)
    except (ValueError, TypeError, UnicodeError):
        return invalid


def _agrees_with_component(package: PackageURL, component: RegistryEntryComponent) -> bool:
    if component.registry_type in {"pypi", "npm"} and package.type != component.registry_type:
        return False
    if package.type == "pypi":
        if (
            package.namespace
            or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", package.name) is None
            or canonicalize_name(package.name) != canonicalize_name(component.name)
        ):
            return False
        if package.version is not None:
            try:
                Version(package.version)
            except InvalidVersion:
                return False
        if component.version:
            declaration = component.version
            reference = declaration if declaration.startswith("==") else "package==" + declaration
            expected = extract_version_pin(reference, ecosystem="python")
            if expected is None or package.version is None:
                return False
            if declaration.startswith("==="):
                # Arbitrary equality compares the declared spelling, so PEP 440
                # normalization must not equate ===1.0 with a PURL version 1.
                if not Specifier("===" + expected).contains(package.version, prereleases=True):
                    return False
            elif Version(expected) != Version(package.version):
                return False
    elif package.type == "npm":
        if re.fullmatch(r"[a-z0-9][a-z0-9._-]*", package.name) is None or (
            package.namespace is not None
            and re.fullmatch(r"@[a-z0-9][a-z0-9._-]*", package.namespace) is None
        ):
            return False
        name = f"{package.namespace}/{package.name}" if package.namespace else package.name
        if name != component.name:
            return False
        if (
            package.version is not None
            and extract_version_pin(name + "@" + package.version, ecosystem="npm") is None
        ):
            return False
        if component.version:
            expected = extract_version_pin(name + "@" + component.version, ecosystem="npm")
            if expected is None or package.version != expected:
                return False
    return True


def package_identifier_properties(component: AnyComponent) -> list[dict[str, str]]:
    if not isinstance(component, RegistryEntryComponent):
        return []
    return [
        {
            "name": "nexus-symbiote:packageIdentifierProjection",
            "value": package_identifier(component).status,
        }
    ]
