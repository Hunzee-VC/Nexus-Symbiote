"""Load explicitly selected operator signature policies without discovery.

Version 1: {"version": 1, "artifacts": [{"artifact_path": "models/model.bin",
"bundle_path": "models/model.sigstore", "expected_identity": "publisher@example.test",
"expected_issuer": "https://issuer.example.test"}]}; every entry is a Sigstore
message signature.

Version 2 names a kind on every entry: {"version": 2, "artifacts": [
{"kind": "sigstore-message-signature", "artifact_path": ..., "bundle_path": ...,
"expected_identity": ..., "expected_issuer": ..., "expected_sha256": optional},
{"kind": "digest-pin", "artifact_path": ..., "expected_sha256": "sha256:<hex>"}]}.

The operator policy must live outside the inspected project. Artifact and bundle
references are forward-slash paths beneath the supplied project root. Loading a
policy neither verifies a signature nor authorizes artifact execution.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote.core.hashing import normalize_digest, open_regular_file, parse_json_strict
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.crypto import (
    MAX_BUNDLE_BYTES,
    MAX_SIGNED_ARTIFACT_BYTES,
    ArtifactPolicy,
    DigestPinPolicy,
    SignaturePolicySet,
    SigstoreArtifactPolicy,
)

MAX_POLICY_BYTES = 4 * 1024 * 1024
MAX_POLICY_ARTIFACTS = 1000
SIGSTORE_KIND = "sigstore-message-signature"
DIGEST_PIN_KIND = "digest-pin"
_FIELDS = frozenset({"artifact_path", "bundle_path", "expected_identity", "expected_issuer"})
# Version 2: required fields and optional fields for each kind.
_KINDS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    SIGSTORE_KIND: (_FIELDS | {"kind"}, frozenset({"expected_sha256"})),
    DIGEST_PIN_KIND: (frozenset({"kind", "artifact_path", "expected_sha256"}), frozenset()),
}


class SignaturePolicyError(ValueError):
    """The selected policy cannot be used safely; messages omit input values."""


def _required_string(record: dict[str, Any], field: str) -> str:
    value = record[field]
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise SignaturePolicyError(f"Signature policy {field} must be a nonempty clean string")
    return value


def _relative_path(value: str) -> Path:
    path = Path(value)
    if (
        not path.parts
        or path.is_absolute()
        or PureWindowsPath(value).drive
        or "\\" in value
        or ".." in path.parts
        or "://" in value
    ):
        raise SignaturePolicyError(
            "Signature policy paths must be relative beneath the project root"
        )
    return path


def _issuer(record: dict[str, Any]) -> str:
    issuer = _required_string(record, "expected_issuer")
    try:
        parsed_issuer = urlsplit(issuer)
        if (
            parsed_issuer.scheme != "https"
            or not parsed_issuer.hostname
            or parsed_issuer.username is not None
            or parsed_issuer.password is not None
            or parsed_issuer.query
            or parsed_issuer.fragment
        ):
            raise ValueError
    except ValueError:
        raise SignaturePolicyError(
            "Expected OIDC issuer must be an HTTPS issuer URL without credentials"
        ) from None
    return issuer


def _pin(record: dict[str, Any]) -> str | None:
    value = record.get("expected_sha256")
    if value is None:
        return None
    try:
        if not isinstance(value, str):
            raise ValueError
        algorithm, digest = normalize_digest(value, "sha256")
    except ValueError:
        raise SignaturePolicyError(
            "Signature policy expected_sha256 must be a SHA-256 digest"
        ) from None
    return f"{algorithm}:{digest}"


def _record(record: object, version: int) -> tuple[str, dict[str, Any]]:
    """Return the entry kind and the record, refusing unknown kinds and fields."""
    if not isinstance(record, dict):
        raise SignaturePolicyError("Each signature policy artifact must be an object")
    if version == 1:
        if set(record) != _FIELDS:
            raise SignaturePolicyError(
                "Each artifact requires exactly the four signature policy fields"
            )
        return SIGSTORE_KIND, record
    kind = record.get("kind")
    if not isinstance(kind, str) or kind not in _KINDS:
        raise SignaturePolicyError("Unsupported signature policy entry kind")
    required, optional = _KINDS[kind]
    if not required <= set(record) <= required | optional:
        raise SignaturePolicyError("Signature policy entry has missing or unknown fields")
    return kind, record


def _identity(path: Path) -> tuple[int, int]:
    info = os.stat(path)
    return info.st_dev, info.st_ino


def _enclosing_working_trees(directory: Path) -> list[Path]:
    """Every directory at or above ``directory`` holding a ``.git`` entry."""
    return [
        candidate
        for candidate in (directory, *directory.parents)
        if os.path.lexists(candidate / ".git")
    ]


def _read_policy(policy_path: Path, root: Path) -> tuple[bytes, str]:
    inside = "Signature policy must be provisioned outside the scanned project"
    trees = _enclosing_working_trees(root)
    resolved_policy = policy_path.resolve()
    if resolved_policy.is_relative_to(root) or any(
        resolved_policy.is_relative_to(tree) for tree in trees
    ):
        raise SignaturePolicyError(inside)
    from nexus_symbiote.utils.crypto import _trusted_ancestor_uids

    uid = getattr(os, "geteuid", lambda: None)()
    trusted_uids = _trusted_ancestor_uids(uid) if uid is not None else set()
    try:
        from nexus_symbiote.core.hashing import open_directory_nofollow

        parent_fd = open_directory_nofollow(policy_path.parent)
        try:
            parent_info = os.fstat(parent_fd)
        finally:
            os.close(parent_fd)
        with open_regular_file(policy_path) as stream:
            info = os.fstat(stream.fileno())
            if info.st_size > MAX_POLICY_BYTES:
                raise SignaturePolicyError("Signature policy exceeds the byte limit")
            # Another name for the file could live inside the project it gates.
            if info.st_nlink != 1:
                raise SignaturePolicyError("Signature policy must not have other hard links")
            if uid is not None and info.st_uid not in trusted_uids:
                raise SignaturePolicyError("Signature policy must be owned by the current user")
            parent_world_writable = bool(parent_info.st_mode & 0o002) and not (
                bool(parent_info.st_mode & stat.S_ISVTX)
                and (uid is None or parent_info.st_uid in trusted_uids)
            )
            if (info.st_mode & 0o002) or parent_world_writable:
                raise SignaturePolicyError(
                    "Signature policy and its directory must not be world-writable"
                )
            raw = stream.read(MAX_POLICY_BYTES + 1)
            # The open followed no symlink, so these are the file's real ancestors.
            # Their device and inode also reveal the project behind a name that the
            # lexical check misses: a case variant or a bind mount.
            ancestors = {_identity(parent) for parent in Path(os.path.abspath(policy_path)).parents}
    except OSError:
        raise SignaturePolicyError(
            "Selected signature policy is unavailable or invalid strict JSON"
        ) from None
    try:
        untrusted = {_identity(root), *(_identity(tree) for tree in trees)}
    except OSError:
        raise SignaturePolicyError("Project root is unavailable") from None
    if untrusted & ancestors:
        raise SignaturePolicyError(inside)
    if len(raw) > MAX_POLICY_BYTES:
        raise SignaturePolicyError("Signature policy exceeds the byte limit")
    return raw, f"sha256:{hashlib.sha256(raw).hexdigest()}"


def load_signature_policies(policy_path: Path, project_root: Path) -> SignaturePolicySet:
    """Read one bounded strict JSON policy selected by the trusted operator.

    Each artifact has one entry. Unknown fields and kinds, duplicate object keys,
    duplicate artifacts, missing files and symlinks are rejected, as is a policy
    stored inside the project or hard-linked from elsewhere. No ambient policy,
    repository configuration, signer hint or adjacent signature is trusted. The
    project root is resolved first, so every command accepts the same path.
    """
    root = Path(project_root).resolve()
    raw, digest = _read_policy(Path(policy_path), root)
    try:
        document = parse_json_strict(raw, max_bytes=MAX_POLICY_BYTES)
    except (ValueError, RecursionError):
        raise SignaturePolicyError(
            "Selected signature policy is unavailable or invalid strict JSON"
        ) from None
    if not isinstance(document, dict) or set(document) != {"version", "artifacts"}:
        raise SignaturePolicyError("Signature policy requires only version and artifacts fields")
    version = document["version"]
    if type(version) is not int or version not in (1, 2):
        raise SignaturePolicyError("Unsupported signature policy version")
    records = document["artifacts"]
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_POLICY_ARTIFACTS:
        raise SignaturePolicyError("Signature policy requires a bounded nonempty artifacts list")
    entries: list[ArtifactPolicy] = []
    seen: set[Path] = set()
    identities: set[tuple[int, int]] = set()
    failures: list[str] = []
    with ConfinedCollection(root, failures) as files:
        for item in records:
            kind, record = _record(item, version)
            artifact = _relative_path(_required_string(record, "artifact_path"))
            pin = _pin(record)
            entry: ArtifactPolicy
            bundle: Path | None = None
            if kind == SIGSTORE_KIND:
                bundle = _relative_path(_required_string(record, "bundle_path"))
                entry = SigstoreArtifactPolicy(
                    files.root / artifact,
                    files.root / bundle,
                    _required_string(record, "expected_identity"),
                    _issuer(record),
                    expected_sha256=pin,
                    policy_digest=digest,
                )
            elif pin is not None:
                entry = DigestPinPolicy(files.root / artifact, pin, digest)
            else:
                raise SignaturePolicyError("A digest pin requires expected_sha256")
            if artifact in seen:
                raise SignaturePolicyError("Duplicate artifact in signature policy")
            seen.add(artifact)
            try:
                # Open only to validate root containment, file kind and bounds.
                # Artifact bytes and signature authenticity are checked later.
                with files.open_regular(artifact, max_bytes=MAX_SIGNED_ARTIFACT_BYTES):
                    pass
                if bundle is not None:
                    with files.open_regular(bundle, max_bytes=MAX_BUNDLE_BYTES):
                        pass
            except (OSError, ValueError):
                raise SignaturePolicyError(
                    "Policy artifact or bundle is unavailable beneath the project root"
                ) from None
            # Another name for the same file, such as a hard link, is a duplicate too.
            same_file = files.path_identity(artifact)
            if same_file is None or same_file in identities:
                raise SignaturePolicyError("Duplicate artifact in signature policy")
            identities.add(same_file)
            entries.append(entry)
    if failures:
        raise SignaturePolicyError("Signature policy references could not be safely inspected")
    return SignaturePolicySet(
        [entry for entry in entries if isinstance(entry, SigstoreArtifactPolicy)],
        [entry for entry in entries if isinstance(entry, DigestPinPolicy)],
        digest=digest,
    )
