"""npm registry advisor: the full packument of one package (``registry.npmjs.org/<name>``).

From the packument it derives, per version, the publish time (``time``), build provenance (``dist.attestations``
present => ``True``, absent => ``False``), lifecycle install scripts (``preinstall``/``install``/``postinstall``,
``hasInstallScript`` or ``gypfile``), the publishing account (``_npmUser.name``) and any deprecation message.
Versions that appear in ``time`` but not in ``versions`` were unpublished.

Nothing is downloaded or executed: only the registry's JSON metadata is read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final
from urllib.parse import quote

from symbiote.advisories.http import HttpClient, MalformedResponse
from symbiote.advisories.types import ReleaseInfo

__all__ = [
    "NPM_REGISTRY",
    "InvalidPackageName",
    "NpmPackage",
    "fetch_npm",
    "npm_package_url",
    "parse_packument",
    "parse_time",
    "semver_key",
    "semver_major",
    "semver_prerelease",
    "validate_npm_name",
    "validate_version",
]

NPM_REGISTRY: Final = "https://registry.npmjs.org"

#: npm names: optional ``@scope/``, lowercase URL-safe characters, at most 214 characters. Legacy packages may
#: contain capitals, so they are accepted; anything else (path separators, ``..``, unicode, spaces) is refused.
_NPM_NAME: Final = re.compile(r"(?:@[A-Za-z0-9][A-Za-z0-9._~-]{0,213}/)?[A-Za-z0-9_][A-Za-z0-9._~-]{0,213}")
_VERSION: Final = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,127}")
_SEMVER: Final = re.compile(
    r"v?(0|[1-9][0-9]{0,15})\.(0|[1-9][0-9]{0,15})\.(0|[1-9][0-9]{0,15})"
    r"(?:-([0-9A-Za-z-]{1,64}(?:\.[0-9A-Za-z-]{1,64}){0,16}))?(?:\+[0-9A-Za-z.-]{1,128})?"
)
_INSTALL_SCRIPTS: Final = ("preinstall", "install", "postinstall")
_MAX_TEXT: Final = 500
_TIME_META: Final = frozenset({"created", "modified", "unpublished"})


class InvalidPackageName(ValueError):  # noqa: N818 - reads naturally at call sites
    """A dependency name or version that is not a valid identifier for its registry (refused, never sent)."""


def validate_npm_name(name: str) -> str:
    if len(name) > 214 or not _NPM_NAME.fullmatch(name) or ".." in name:
        raise InvalidPackageName(f"not a valid npm package name: {name[:80]!r}")
    return name


def validate_version(version: str) -> str:
    if not _VERSION.fullmatch(version):
        raise InvalidPackageName(f"not a valid version string: {version[:80]!r}")
    return version


def npm_package_url(name: str, *, registry: str = NPM_REGISTRY) -> str:
    """Packument URL; a scoped name is encoded as ``@scope%2Fname``."""
    validate_npm_name(name)
    return f"{registry}/{quote(name, safe='@')}"


# --------------------------------------------------------------------------------------------- semver


SemverKey = tuple[int, int, int, int, tuple[tuple[int, int, str], ...]]


def semver_key(version: str) -> SemverKey | None:
    """Precedence key for a SemVer 2.0 version (build metadata ignored); ``None`` when not SemVer."""
    m = _SEMVER.fullmatch(version)
    if m is None:
        return None
    pre = m.group(4)
    ids: tuple[tuple[int, int, str], ...] = ()
    if pre:
        ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1, ids)


def semver_major(version: str) -> int | None:
    key = semver_key(version)
    return None if key is None else key[0]


def semver_prerelease(version: str) -> bool:
    key = semver_key(version)
    return key is not None and key[3] == 0


# --------------------------------------------------------------------------------------------- packument


def parse_time(value: object) -> datetime | None:
    """An ISO-8601 timestamp from a registry; naive values are taken as UTC. Malformed values are ``None``."""
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00") if value.endswith("Z") else value)
    except ValueError:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _text(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value[:_MAX_TEXT]
    return None


@dataclass(slots=True)
class NpmPackage:
    name: str
    source: str
    releases: list[ReleaseInfo] = field(default_factory=list)
    latest: str | None = None
    #: Versions recorded in ``time`` that are no longer in ``versions`` (unpublished).
    removed_versions: frozenset[str] = frozenset()
    #: The whole package was unpublished (``time.unpublished``).
    unpublished: bool = False

    def release(self, version: str) -> ReleaseInfo | None:
        for r in self.releases:
            if r.version == version:
                return r
        return None


def _install_script(manifest: dict[str, Any]) -> bool:
    if manifest.get("hasInstallScript") is True or manifest.get("gypfile") is True:
        return True
    scripts = manifest.get("scripts")
    if isinstance(scripts, dict):
        return any(isinstance(scripts.get(k), str) and scripts.get(k) for k in _INSTALL_SCRIPTS)
    return False


def parse_packument(name: str, data: object, *, source: str) -> NpmPackage:
    """Turn a packument (already size- and depth-checked JSON) into :class:`NpmPackage`."""
    if not isinstance(data, dict):
        raise MalformedResponse("packument is not a JSON object", url=source)
    times_raw = data.get("time")
    times: dict[str, Any] = times_raw if isinstance(times_raw, dict) else {}
    versions = data.get("versions")
    if versions is None and "unpublished" in times:
        return NpmPackage(name=name, source=source, unpublished=True)
    if not isinstance(versions, dict):
        raise MalformedResponse("packument has no 'versions' object", url=source)
    releases: list[ReleaseInfo] = []
    for version, manifest in versions.items():
        if not isinstance(version, str) or not _VERSION.fullmatch(version) or not isinstance(manifest, dict):
            continue
        dist = manifest.get("dist")
        attestations = dist.get("attestations") if isinstance(dist, dict) else None
        npm_user = manifest.get("_npmUser")
        publisher = _text(npm_user.get("name")) if isinstance(npm_user, dict) else None
        releases.append(
            ReleaseInfo(
                version=version,
                published_at=parse_time(times.get(version)),
                has_provenance=isinstance(attestations, dict) and bool(attestations),
                has_install_script=_install_script(manifest),
                publisher=publisher,
                deprecated=_text(manifest.get("deprecated")),
            )
        )
    tags = data.get("dist-tags")
    latest = tags.get("latest") if isinstance(tags, dict) else None
    known = {r.version for r in releases}
    removed = frozenset(
        v
        for v in times
        if isinstance(v, str) and v not in _TIME_META and v not in known and _VERSION.fullmatch(v)
    )
    return NpmPackage(
        name=name,
        source=source,
        releases=releases,
        latest=latest if isinstance(latest, str) and latest in known else None,
        removed_versions=removed,
    )


def fetch_npm(client: HttpClient, name: str) -> NpmPackage:
    """Fetch and parse the packument of ``name``. Raises :class:`InvalidPackageName` or an HTTP error."""
    url = npm_package_url(name)
    return parse_packument(name, client.get_json(url), source=url)
