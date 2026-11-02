"""Directory manifests with OpenSSF model-signing compatible roots (``spec/digests.md §3.6``)."""

from __future__ import annotations

import fnmatch
import hashlib
from collections.abc import Iterable, Sequence
from pathlib import Path

from symbiote.digest.envelope import envelope_digest, strip_prefix
from symbiote.digest.files import file_digest
from symbiote.digest.jcs import UndigestableError
from symbiote.model.common import DigestResult
from symbiote.model.entities import DirManifest, ManifestItem

DEFAULT_IGNORE: tuple[str, ...] = (".git/**",)


def _ignored(rel: str, patterns: Sequence[str]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat):
            return True
        if pat.endswith("/**") and (rel == pat[:-3] or rel.startswith(pat[:-3] + "/")):
            return True
    return False


def manifest_root(items: Iterable[ManifestItem]) -> str:
    """SHA-256 over the concatenated per-file digests in name order — model-signing's directory subject digest."""
    h = hashlib.sha256()
    for item in sorted(items, key=lambda i: i.name.encode("utf-8")):
        h.update(bytes.fromhex(strip_prefix(item.digest)))
    return "sha256:" + h.hexdigest()


def build_dir_manifest(
    root: Path, *, ignore: Sequence[str] = DEFAULT_IGNORE, allow_symlinks: bool = False
) -> DirManifest:
    """Hash every regular file under ``root``; symlinks are rejected unless ``allow_symlinks``."""
    root = Path(root)
    if not root.is_dir():
        raise UndigestableError("not-a-directory", str(root))
    items: list[ManifestItem] = []
    paths = list(root.rglob("*"))
    for path in paths:
        rel = path.relative_to(root).as_posix()
        try:
            rel.encode("utf-8")
        except UnicodeEncodeError:
            # A file name that is not valid UTF-8 has no canonical manifest name: fail closed (I5), never crash.
            raise UndigestableError("non-utf8-file-name", repr(rel)) from None
    for path in sorted(paths, key=lambda p: p.relative_to(root).as_posix().encode("utf-8")):
        rel = path.relative_to(root).as_posix()
        if _ignored(rel, ignore):
            continue
        if path.is_symlink():
            if not allow_symlinks:
                raise UndigestableError("symlink", rel)
            digest = "sha256:" + hashlib.sha256(str(path.readlink()).encode("utf-8")).hexdigest()
            items.append(ManifestItem(name=rel, digest=digest, size=None))
            continue
        if path.is_file():
            digest, size = file_digest(path)
            items.append(ManifestItem(name=rel, digest=digest, size=size))
    items.sort(key=lambda i: i.name.encode("utf-8"))
    return DirManifest(
        method="files",
        hash_type="sha256",
        allow_symlinks=allow_symlinks,
        ignore=list(ignore),
        resources=items,
        root=manifest_root(items),
    )


def dirmanifest_digest(manifest: DirManifest) -> DigestResult:
    """``dirmanifest/v1`` envelope digest over the manifest (distinct from the OMS-compatible ``root``)."""
    payload = {
        "method": manifest.method,
        "hashType": manifest.hash_type,
        "allowSymlinks": manifest.allow_symlinks,
        "ignore": list(manifest.ignore),
        "resources": [
            {"name": i.name, "algorithm": "sha256", "digest": strip_prefix(i.digest)}
            for i in manifest.resources
        ],
    }
    return envelope_digest("dirmanifest/v1", payload)


__all__ = ["DEFAULT_IGNORE", "build_dir_manifest", "dirmanifest_digest", "manifest_root"]
