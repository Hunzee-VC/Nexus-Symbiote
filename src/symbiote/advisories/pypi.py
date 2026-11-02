"""PyPI advisor: the JSON API (``pypi.org/pypi/<name>/json``) and the JSON Simple API (``pypi.org/simple/<name>/``).

The JSON API gives every release with its files' upload times and yank state. The Simple API (PEP 691) adds,
per file, a ``provenance`` URL when the file carries a PEP 740 attestation, and the project's PEP 792 status
(``active``/``archived``/``quarantined``/``deprecated``). Provenance is taken from the *presence* of that URL; the
attestation itself is not fetched or verified here. When the Simple API cannot be read, provenance stays
``None`` (unknown).

``has_install_script`` approximates "installing this release runs the project's build code": ``True`` when a
release ships only source distributions, ``False`` when it ships a wheel, ``None`` when it has no files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from symbiote.advisories.http import HttpClient, HttpError, MalformedResponse
from symbiote.advisories.npm import InvalidPackageName, parse_time, validate_version
from symbiote.advisories.types import ReleaseInfo

__all__ = [
    "PYPI",
    "PypiProject",
    "apply_simple_index",
    "fetch_pypi",
    "normalize_pypi_name",
    "parse_pypi_json",
    "pep440_key",
    "pep440_major",
    "pep440_prerelease",
]

PYPI: Final = "https://pypi.org"
SIMPLE_ACCEPT: Final = "application/vnd.pypi.simple.v1+json"

_NAME: Final = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,198}[A-Za-z0-9])?")
_PEP440: Final = re.compile(
    r"v?(?:(?P<epoch>[0-9]{1,6})!)?(?P<release>[0-9]{1,16}(?:\.[0-9]{1,16}){0,15})"
    r"(?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]{0,16}))?"
    r"(?:-(?P<post_n1>[0-9]{1,16})|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]{0,16}))?"
    r"(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]{0,16}))?"
    r"(?:\+[a-z0-9]{1,32}(?:[-_.][a-z0-9]{1,32}){0,16})?",
    re.IGNORECASE,
)
_PRE_ORDER: Final = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
_MAX_TEXT: Final = 500
_STATUS: Final = frozenset({"active", "archived", "quarantined", "deprecated"})

Pep440Key = tuple[int, tuple[int, ...], tuple[int, int], tuple[int, int], tuple[int, int]]


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalised name; refuses anything that is not a valid distribution name."""
    if not _NAME.fullmatch(name):
        raise InvalidPackageName(f"not a valid PyPI project name: {name[:80]!r}")
    return re.sub(r"[-_.]+", "-", name).lower()


def pep440_key(version: str) -> Pep440Key | None:
    """A sort key implementing PEP 440 ordering for the common forms; ``None`` when not PEP 440."""
    m = _PEP440.fullmatch(version.strip())
    if m is None:
        return None
    release = [int(x) for x in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    inf = 1 << 62
    if m.group("pre_l"):
        pre = (_PRE_ORDER[m.group("pre_l").lower()], int(m.group("pre_n") or 0))
    elif m.group("dev_l") and not (m.group("post_l") or m.group("post_n1")):
        pre = (-1, 0)  # 1.0.dev1 sorts before 1.0a1
    else:
        pre = (inf, 0)
    if m.group("post_l") or m.group("post_n1"):
        post = (1, int(m.group("post_n1") or m.group("post_n2") or 0))
    else:
        post = (-1, 0)
    dev = (0, int(m.group("dev_n") or 0)) if m.group("dev_l") else (1, 0)
    return (int(m.group("epoch") or 0), tuple(release), pre, post, dev)


def pep440_prerelease(version: str) -> bool:
    m = _PEP440.fullmatch(version.strip())
    return m is not None and bool(m.group("pre_l") or m.group("dev_l"))


def pep440_major(version: str) -> int | None:
    key = pep440_key(version)
    return None if key is None else key[1][0]


@dataclass(slots=True)
class PypiProject:
    name: str
    source: str
    releases: list[ReleaseInfo] = field(default_factory=list)
    latest: str | None = None
    yank_reasons: dict[str, str] = field(default_factory=dict)
    #: PEP 792 project status from the Simple API, when read.
    status: str | None = None
    status_reason: str | None = None
    #: filename -> version, used to attach Simple API provenance to releases.
    files: dict[str, str] = field(default_factory=dict)
    #: True once the Simple API was read and applied.
    provenance_checked: bool = False

    def release(self, version: str) -> ReleaseInfo | None:
        key = pep440_key(version)
        for r in self.releases:
            if r.version == version or (key is not None and pep440_key(r.version) == key):
                return r
        return None


def parse_pypi_json(name: str, data: object, *, source: str) -> PypiProject:
    if not isinstance(data, dict) or not isinstance(data.get("info"), dict):
        raise MalformedResponse("PyPI JSON has no 'info' object", url=source)
    releases_raw = data.get("releases")
    if not isinstance(releases_raw, dict):
        raise MalformedResponse("PyPI JSON has no 'releases' object", url=source)
    project = PypiProject(name=name, source=source)
    for version, files in releases_raw.items():
        if not isinstance(version, str) or not isinstance(files, list):
            continue
        try:
            validate_version(version)
        except InvalidPackageName:
            continue
        uploads: list[datetime] = []
        yanked: list[bool] = []
        reason: str | None = None
        has_wheel = has_sdist = False
        for f in files:
            if not isinstance(f, dict):
                continue
            ts = parse_time(f.get("upload_time_iso_8601") or f.get("upload_time"))
            if ts is not None:
                uploads.append(ts)
            yanked.append(f.get("yanked") is True)
            if f.get("yanked") is True and isinstance(f.get("yanked_reason"), str) and f["yanked_reason"]:
                reason = str(f["yanked_reason"])[:_MAX_TEXT]
            fname = f.get("filename")
            if isinstance(fname, str) and len(fname) <= 512:
                project.files[fname] = version
            ptype = f.get("packagetype")
            has_wheel = has_wheel or ptype == "bdist_wheel"
            has_sdist = has_sdist or ptype == "sdist"
        is_yanked = bool(yanked) and all(yanked)
        if is_yanked and reason:
            project.yank_reasons[version] = reason
        install: bool | None = None
        if has_wheel:
            install = False
        elif has_sdist:
            install = True
        project.releases.append(
            ReleaseInfo(
                version=version,
                published_at=min(uploads) if uploads else None,
                has_provenance=None,
                has_install_script=install,
                yanked=is_yanked,
            )
        )
    info: dict[str, Any] = data["info"]
    latest = info.get("version")
    if isinstance(latest, str) and project.release(latest) is not None:
        project.latest = latest
    return project


def apply_simple_index(project: PypiProject, data: object) -> None:
    """Attach PEP 740 provenance presence and the PEP 792 status from a Simple API JSON response."""
    if not isinstance(data, dict) or not isinstance(data.get("files"), list):
        raise MalformedResponse("Simple API response has no 'files' list", url=project.source)
    with_prov: dict[str, list[bool]] = {}
    for f in data["files"]:
        if not isinstance(f, dict):
            continue
        version = project.files.get(str(f.get("filename")))
        if version is None:
            continue
        prov = f.get("provenance")
        with_prov.setdefault(version, []).append(isinstance(prov, str) and bool(prov))
    status = data.get("project-status")
    if isinstance(status, dict) and status.get("status") in _STATUS:
        project.status = str(status["status"])
        reason = status.get("reason")
        project.status_reason = str(reason)[:_MAX_TEXT] if isinstance(reason, str) and reason else None
    updated: list[ReleaseInfo] = []
    for r in project.releases:
        flags = with_prov.get(r.version)
        if flags:
            # One attested file is enough to say the release carries provenance.
            updated.append(
                ReleaseInfo(
                    version=r.version,
                    published_at=r.published_at,
                    has_provenance=any(flags),
                    has_install_script=r.has_install_script,
                    publisher=r.publisher,
                    deprecated=r.deprecated,
                    yanked=r.yanked,
                )
            )
        else:
            updated.append(r)
    project.releases = updated
    project.provenance_checked = True


def fetch_pypi(client: HttpClient, name: str) -> tuple[PypiProject, list[str]]:
    """Fetch the JSON API and (best effort) the Simple API. Returns the project and Simple API errors."""
    norm = normalize_pypi_name(name)
    url = f"{PYPI}/pypi/{norm}/json"
    project = parse_pypi_json(norm, client.get_json(url), source=url)
    errors: list[str] = []
    simple = f"{PYPI}/simple/{norm}/"
    try:
        apply_simple_index(project, client.get_json(simple, accept=SIMPLE_ACCEPT))
    except HttpError as exc:  # provenance is best effort: record, do not fail the lookup
        errors.append(f"{simple}: provenance and project status unavailable ({type(exc).__name__}: {exc})")
    return project, errors
