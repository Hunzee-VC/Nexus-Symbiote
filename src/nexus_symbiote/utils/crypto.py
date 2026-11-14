"""Artifact-bound integrity verification under an explicit signer trust policy."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nexus_symbiote.core.hashing import (
    descriptor_binding,
    normalize_digest,
    open_directory_nofollow,
    open_regular_file,
    pathname_identity,
)

if TYPE_CHECKING:
    from sigstore.models import TrustedRoot

    from nexus_symbiote.core.models import ClaimEvidence

MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_TRUST_ROOT_BYTES = 4 * 1024 * 1024
MAX_SIGNED_ARTIFACT_BYTES = 5 * 1024 * 1024 * 1024
# A fixed message, so callers can report it instead of a generic signature failure.
SIGSTORE_MISSING = "sigstore package not installed; install nexus-symbiote[sigstore]"
DSSE_UNSUPPORTED = (
    "Bundle carries a DSSE envelope (an OpenSSF Model Signing signature or an attestation); "
    "only Sigstore message-signature bundles are verified"
)


class SigningStatus(str, Enum):
    """What the model collector established about a model's weight files."""

    SIGSTORE_SIGNED = "sigstore-signed"
    DIGEST_PINNED = "digest-pinned"
    PARTIALLY_VERIFIED = "partially-verified"
    VERIFICATION_FAILED = "verification-failed"
    VERIFICATION_UNAVAILABLE = "verification-unavailable"
    SIGNATURE_PRESENT_UNVERIFIED = "signature-present-unverified"
    SIGNATURE_NOT_FOUND = "signature-not-found"


VERIFIED_SIGNING_STATUSES = frozenset(
    {SigningStatus.SIGSTORE_SIGNED.value, SigningStatus.DIGEST_PINNED.value}
)
# The claim on a model component that records how its signing status was established.
SIGNING_EVIDENCE_CLAIM = "signing_status"
# An evidence reference that names the digest of the operator policy file a run used.
POLICY_REF_PREFIX = "policy:"


def component_evidence_refs(refs: Iterable[Any]) -> list[Any]:
    """``refs`` without policy-file digests, to compare one component across runs.

    The digest identifies the run's policy file, not the component: equivalent
    policies with other bytes, or one more entry for another artifact, must not
    make the same verified component look changed or mismatched.
    """
    return [ref for ref in refs if not (isinstance(ref, str) and ref.startswith(POLICY_REF_PREFIX))]


def comparable_claim(claim: ClaimEvidence) -> dict[str, Any]:
    """A claim as two runs compare it: without its observation time or policy-file digest."""
    dumped = claim.model_dump(exclude={"observed_at"})
    dumped["evidence_refs"] = component_evidence_refs(dumped["evidence_refs"])
    return dumped


def _sha256(value: str | None) -> str | None:
    if value is None:
        return None
    algorithm, digest = normalize_digest(value, "sha256")
    return f"{algorithm}:{digest}"


# Explicit Sigstore trust-root override. A flag value wins over the environment;
# when neither is set, the sigstore-python TUF cache is used after the private
# cache check and single read in _read_sigstore_cache.
TRUST_ROOT_ENV = "NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT"
TRUST_ROOT_SHA256_ENV = "NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT_SHA256"


@dataclass(frozen=True)
class SigstoreArtifactPolicy:
    """Trusted caller input, never inferred from a BOM or adjacent signature file.

    This policy authorizes verification of one artifact with one exact identity
    and OIDC issuer, and with ``expected_sha256`` also pins its exact bytes, so
    another artifact signed by the same identity cannot take its place. It does
    not grant execution authority to the artifact.
    """

    artifact_path: Path
    bundle_path: Path
    expected_identity: str
    expected_issuer: str
    expected_sha256: str | None = None
    policy_digest: str | None = None

    def __post_init__(self) -> None:
        if not self.expected_identity.strip() or not self.expected_issuer.strip():
            raise ValueError("Both an expected signer identity and OIDC issuer are required")
        object.__setattr__(self, "expected_sha256", _sha256(self.expected_sha256))


@dataclass(frozen=True)
class DigestPinPolicy:
    """An operator-pinned SHA-256 for one artifact; the operator is the trust root."""

    artifact_path: Path
    expected_sha256: str
    policy_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_sha256", _sha256(self.expected_sha256))


ArtifactPolicy = SigstoreArtifactPolicy | DigestPinPolicy


class SignaturePolicySet(list[SigstoreArtifactPolicy]):
    """The Sigstore entries of one operator policy, plus its digest pins and digest.

    It is a list of the Sigstore entries so every consumer that verifies
    signatures keeps working; consumers that accept digest pins read
    ``digest_pins`` as well.
    """

    def __init__(
        self,
        signatures: Iterable[SigstoreArtifactPolicy] = (),
        digest_pins: Iterable[DigestPinPolicy] = (),
        *,
        digest: str | None = None,
    ) -> None:
        super().__init__(signatures)
        self.digest_pins: tuple[DigestPinPolicy, ...] = tuple(digest_pins)
        self.digest = digest


def policy_entries(
    signature_policies: Iterable[SigstoreArtifactPolicy],
    digest_pins: Iterable[DigestPinPolicy] = (),
) -> list[ArtifactPolicy]:
    """Every entry of a policy set or plain sequence, rejecting duplicate artifacts."""
    entries: list[ArtifactPolicy] = [*signature_policies, *digest_pins]
    if isinstance(signature_policies, SignaturePolicySet):
        entries.extend(signature_policies.digest_pins)
    if len({entry.artifact_path.resolve() for entry in entries}) != len(entries):
        raise ValueError("Duplicate artifact signature policies")
    return entries


@dataclass
class VerificationResult:
    """Outcome of a signature or hash verification."""

    verified: bool
    identity: str | None = None
    issuer: str | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


def _current_uid() -> int | None:
    """Current user id, or None on platforms without user ids."""
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid):
        uid: int = geteuid()
        return uid
    return None


# What an operator can do about a shared cache entry, and about a shared explicit root.
_CACHE_REMEDY = (
    "point XDG_CACHE_HOME at a directory you own, or use an explicit trust root "
    f"({TRUST_ROOT_ENV} or --trust-root)"
)
_EXPLICIT_REMEDY = (
    f"or pin the trust root's SHA-256 ({TRUST_ROOT_SHA256_ENV} or --trust-root-sha256)"
)


def _owner_error(info: os.stat_result, path: Path, *, what: str) -> str | None:
    """Return an error when a trust entry is not owned by the current user."""
    uid = _current_uid()
    if uid is not None and info.st_uid != uid:
        return f"{what} {path} is not owned by the current user"
    return None


def _private_dir_error(path: Path, *, what: str, remedy: str) -> str | None:
    """Return an error unless a path is a user-owned private directory, not a symlink."""
    try:
        info = os.lstat(path)
    except OSError:
        return f"{what} {path} cannot be inspected"
    return _private_dir_info_error(info, path, what=what, remedy=remedy)


def _private_dir_info_error(
    info: os.stat_result, path: Path, *, what: str, remedy: str
) -> str | None:
    if stat.S_ISLNK(info.st_mode):
        return f"{what} {path} must not be a symlink"
    if not stat.S_ISDIR(info.st_mode):
        return f"{what} {path} is not a directory"
    if (error := _owner_error(info, path, what=what)) is not None:
        return error
    if info.st_mode & 0o022:
        return f"{what} {path} is group/world-writable; make it private, {remedy}"
    return None


_SEEDED_ROOT_SIDECAR = ".trusted_root.seeded.sha256"


def _private_file_info_error(
    info: os.stat_result, parent_mode: int | None, path: Path, *, what: str, remedy: str
) -> str | None:
    """Return an error unless a trust file is user-owned, unlinked elsewhere, and private.

    A group/world-writable file is accepted only when its parent directory
    keeps everyone else from traversing to it: sigstore-python seeds
    trusted_root.json with the ambient umask, so under umask 002/007 the file
    is group-writable and only the private directory (mode 0700, as
    _check_sigstore_cache_dirs creates) protects it.
    """
    if (error := _owner_error(info, path, what=what)) is not None:
        return error
    if info.st_nlink != 1:
        return f"{what} {path} must not have other hard links; {remedy}"
    if info.st_mode & 0o022:
        if parent_mode is None or parent_mode & 0o011:
            return (
                f"{what} {path} is group/world-writable and its directory lets "
                f"others reach it; make the file private, make its directory private, {remedy}"
            )
    return None


def _trusted_ancestor_uids(uid: int) -> set[int]:
    """Caller and system UIDs, including unmapped host-root overflowuid in rootless userns."""
    allowed = {0, uid}
    try:
        uid_map = Path("/proc/self/uid_map").read_text(encoding="utf-8")
        if not any(line.split()[0] == "0" for line in uid_map.splitlines() if line.split()):
            overflow = int(Path("/proc/sys/kernel/overflowuid").read_text(encoding="utf-8").strip())
            allowed.add(overflow)
    except (OSError, ValueError):
        pass
    return allowed


def _ancestor_error(directory: Path, *, dir_what: str, remedy: str) -> str | None:
    """Reject non-sticky world-writable or foreign non-root ancestors above an unpinned root."""
    uid = _current_uid()
    trusted_uids = _trusted_ancestor_uids(uid) if uid is not None else set()
    for ancestor in Path(os.path.abspath(directory)).parents:
        try:
            info = os.lstat(ancestor)
        except OSError:
            return f"{dir_what} {ancestor} cannot be inspected"
        if stat.S_ISLNK(info.st_mode):
            return f"{dir_what} {ancestor} must not be a symlink"
        if uid is not None and info.st_uid not in trusted_uids:
            return f"{dir_what} {ancestor} is not owned by the current user"
        if (info.st_mode & 0o002) and not (info.st_mode & stat.S_ISVTX):
            return f"{dir_what} {ancestor} is world-writable without sticky protection; {remedy}"
    return None


def _sigstore_cache_targets_dir() -> Path:
    """Resolve the TUF targets directory exactly as sigstore-python does.

    sigstore-python exposes no public API for this path, so this uses the same
    resolver its TrustUpdater uses. If that private API moves, verification
    fails closed instead of checking the wrong directory.
    """
    from sigstore._internal.tuf import DEFAULT_TUF_URL, _get_dirs

    _metadata_dir, targets_dir = _get_dirs(DEFAULT_TUF_URL)
    return targets_dir


def _check_sigstore_cache_dirs() -> tuple[Path | None, str | None]:
    """Ensure the offline TUF cache directories are private, creating them mode 0700.

    Offline, sigstore-python reads ``trusted_root.json`` from its user cache
    without verifying it, so anyone who can write to the cache (or rename a
    component above it) chooses the accepted certificate authorities and
    transparency logs. This checks the TUF targets directory and every ancestor
    up to the Sigstore cache directory and fails closed on any symlink, foreign
    owner, or group/world write bit; ``_read_sigstore_cache`` checks the file.
    The ownership and mode of the cache home above the Sigstore directory, which
    other applications share, are not checked; on a shared machine point
    XDG_CACHE_HOME at a private directory instead. The cache is then opened
    without following symlinks, so no directory on its path may be one.

    Returns (targets_dir, error); exactly one of them is set.
    """
    try:
        import platformdirs

        targets_dir = _sigstore_cache_targets_dir()
        sigstore_dir = Path(platformdirs.user_cache_dir("sigstore-python", "sigstore"))
    except Exception:
        return None, "Cannot resolve the Sigstore trust-root cache location"
    missing: list[Path] = []
    probe = targets_dir
    while not probe.exists():
        missing.append(probe)
        if probe == probe.parent:
            break
        probe = probe.parent
    for component in reversed(missing):
        try:
            os.mkdir(component, 0o700)
        except FileExistsError:
            continue  # Created concurrently; the chain check below vets it.
        except OSError:
            return None, f"Cannot create the private Sigstore trust-root cache at {component}"
    current = targets_dir
    while True:
        error = _private_dir_error(
            current, what="Sigstore trust-root cache directory", remedy=_CACHE_REMEDY
        )
        if error is not None:
            return None, error
        if current == sigstore_dir:
            break
        if sigstore_dir not in current.parents:
            return None, (
                "Sigstore trust-root cache "
                f"{targets_dir} is outside the Sigstore cache directory {sigstore_dir}"
            )
        current = current.parent
    return targets_dir, None


def _read_sigstore_cache() -> tuple[Path | None, bytes | None, str | None]:
    """Check the offline TUF cache and read its trusted root once.

    After the directory chain passes ``_check_sigstore_cache_dirs``, a missing
    ``trusted_root.json`` is seeded mode 0600 from the root embedded in
    sigstore-python, as sigstore-python itself would. The file is then opened
    once without following symlinks, must be user-owned and not group/world
    writable where anyone else can reach it (a file sigstore-python seeded
    under a group-writable umask is accepted only inside a private directory),
    judged by fstat on that descriptor and its directory's, and read. The
    caller must build the verifier from the returned bytes and never let
    sigstore-python re-read the path, which a process running as the same user
    could replace in between.

    Returns (trusted_root_path, content, error); the error is set alone on failure.
    """
    targets_dir, error = _check_sigstore_cache_dirs()
    if error is not None or targets_dir is None:
        return None, None, error or "Sigstore trust-root cache could not be checked"
    trusted_root = targets_dir / "trusted_root.json"
    error = _seed_sigstore_cache(trusted_root)
    if error is not None:
        return None, None, error
    content, error = _read_checked_trust_root(
        trusted_root,
        private=True,
        what="Sigstore trusted root",
        dir_what="Sigstore trust-root cache directory",
        remedy=_CACHE_REMEDY,
    )
    if content is None:
        return None, None, error or f"Sigstore trusted root {trusted_root} cannot be inspected"
    content = _refresh_seeded_sigstore_cache(trusted_root, content)
    return trusted_root, content, None


def _write_raw_nofollow(dir_fd: int, name: str, payload: bytes) -> None:
    """Write ``payload`` to ``name`` in ``dir_fd`` via raw OS calls without os.fdopen."""
    cloexec = getattr(os, "O_CLOEXEC", 0)
    temp_name = f".{name}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | cloexec
    fd = os.open(temp_name, flags, 0o600, dir_fd=dir_fd)
    try:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
    except BaseException:
        os.close(fd)
        try:
            os.unlink(temp_name, dir_fd=dir_fd)
        except OSError:
            pass
        raise
    os.close(fd)
    os.replace(temp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)


def _refresh_seeded_sigstore_cache(trusted_root: Path, content: bytes) -> bytes:
    """Refresh an unmodified previously seeded cache root when sigstore-python upgrades."""
    try:
        from sigstore._internal.tuf import DEFAULT_TUF_URL
        from sigstore._utils import read_embedded

        embedded = read_embedded("trusted_root.json", DEFAULT_TUF_URL)
    except Exception:
        return content
    if content == embedded:
        return content
    cloexec = getattr(os, "O_CLOEXEC", 0)
    try:
        dir_fd = open_directory_nofollow(trusted_root.parent)
    except OSError:
        return content
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | cloexec
        sidecar_fd = os.open(_SEEDED_ROOT_SIDECAR, flags, dir_fd=dir_fd)
        try:
            info = os.fstat(sidecar_fd)
            uid = _current_uid()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or (uid is not None and info.st_uid != uid)
                or info.st_size > 128
            ):
                return content
            recorded = os.read(sidecar_fd, 129).strip().decode("ascii")
        finally:
            os.close(sidecar_fd)
        current_digest = hashlib.sha256(content).hexdigest()
        if not hmac.compare_digest(recorded, current_digest):
            return content
        new_digest = hashlib.sha256(embedded).hexdigest().encode("ascii")
        _write_raw_nofollow(dir_fd, trusted_root.name, embedded)
        _write_raw_nofollow(dir_fd, _SEEDED_ROOT_SIDECAR, new_digest)
        return embedded
    except (OSError, UnicodeDecodeError):
        return content
    finally:
        os.close(dir_fd)


def _seed_sigstore_cache(trusted_root: Path) -> str | None:
    """Create a missing cached trusted root from sigstore-python's embedded copy.

    The file is created exclusively and without following symlinks, so an
    existing entry of any kind is left in place for the checked read to vet. A
    file that could not be written whole, including when closing it fails, is
    removed, so a later run does not read a truncated root.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    failure = f"Cannot seed the Sigstore trusted root {trusted_root}"
    try:
        dir_fd = open_directory_nofollow(trusted_root.parent)
    except OSError:
        return (
            f"Cannot open the Sigstore trust-root cache directory {trusted_root.parent} "
            "without following symlinks; no directory on its path may be a symlink"
        )
    try:
        try:
            fd = os.open(trusted_root.name, flags, 0o600, dir_fd=dir_fd)
        except FileExistsError:
            return None
        try:
            with os.fdopen(fd, "wb") as stream:
                from sigstore._internal.tuf import DEFAULT_TUF_URL
                from sigstore._utils import read_embedded

                embedded = read_embedded("trusted_root.json", DEFAULT_TUF_URL)
                stream.write(embedded)
        except Exception:
            os.unlink(trusted_root.name, dir_fd=dir_fd)
            return failure
        try:
            digest_bytes = hashlib.sha256(embedded).hexdigest().encode("ascii")
            _write_raw_nofollow(dir_fd, _SEEDED_ROOT_SIDECAR, digest_bytes)
        except OSError:
            pass
    except OSError:
        return failure
    finally:
        os.close(dir_fd)
    return None


def _read_explicit_trust_root(
    trust_root: str | Path | None, expected_sha256: str | None
) -> tuple[Path | None, bytes | None, str | None, str | None]:
    """Resolve an explicit trust root from a flag value or the environment and read it once.

    A flag value wins over ``NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT``. The path
    names a ``trusted_root.json`` file, or a directory holding one. With a
    pinned SHA-256 (flag or ``NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT_SHA256``)
    the file bytes must match it; without one, the file and its parent
    directory must be user-owned and private. The file is opened once without
    following symlinks, the checks run against that descriptor, and the bytes
    returned are exactly the bytes checked, so the caller must load the trust
    root from them and never re-open the path.

    Returns (path, content, source, error); source is "flag" or "environment".
    """
    raw = trust_root
    source = "flag"
    if raw is None:
        raw = os.environ.get(TRUST_ROOT_ENV) or None
        source = "environment"
    digest = expected_sha256
    if digest is None:
        digest = os.environ.get(TRUST_ROOT_SHA256_ENV) or None
    if raw is None:
        if digest is not None:
            return (
                None,
                None,
                None,
                "A pinned Sigstore trust-root SHA-256 was supplied without a trust root; "
                f"set {TRUST_ROOT_ENV} or pass --trust-root",
            )
        return None, None, None, None
    path = Path(raw)
    if path.is_dir():
        path = path / "trusted_root.json"
    expected: str | None = None
    if digest is not None:
        try:
            _algorithm, expected = normalize_digest(digest, "sha256")
        except ValueError:
            return (
                None,
                None,
                None,
                "Pinned Sigstore trust-root SHA-256 must be sha256:<64 lowercase hex characters>",
            )
    content, error = _read_checked_trust_root(
        path, private=expected is None, check_ancestors=expected is None
    )
    if content is None:
        return None, None, None, error
    if expected is not None and not hmac.compare_digest(
        hashlib.sha256(content).hexdigest(), expected
    ):
        return None, None, None, "Explicit Sigstore trust root does not match the pinned SHA-256"
    return path, content, source, None


def _read_checked_trust_root(
    path: Path,
    *,
    private: bool,
    check_ancestors: bool = False,
    what: str = "Explicit Sigstore trust root",
    dir_what: str = "Explicit Sigstore trust-root directory",
    remedy: str = _EXPLICIT_REMEDY,
) -> tuple[bytes | None, str | None]:
    """Read a trust-root file once through a no-follow descriptor, bounded.

    With ``private``, the file and its parent directory must be user-owned and
    private, judged by fstat on the very descriptors the bytes come from.
    """
    try:
        dir_fd = open_directory_nofollow(path.parent)
    except OSError:
        fallback = (
            _private_dir_error(path.parent, what=dir_what, remedy=remedy) if private else None
        )
        return None, fallback or f"{what} {path} cannot be inspected"
    try:
        try:
            linked = os.stat(path.name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError:
            return None, f"{what} {path} cannot be inspected"
        if stat.S_ISLNK(linked.st_mode):
            return None, f"{what} {path} must not be a symlink"
        if not stat.S_ISREG(linked.st_mode):
            return None, f"{what} {path} is not a regular file"
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path.name, flags, dir_fd=dir_fd)
        except OSError:
            return None, f"{what} {path} cannot be inspected"
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                return None, f"{what} {path} is not a regular file"
            if private:
                dir_info = os.fstat(dir_fd)
                error = _private_file_info_error(
                    info, dir_info.st_mode, path, what=what, remedy=remedy
                )
                if error is None:
                    error = _private_dir_info_error(
                        dir_info, path.parent, what=dir_what, remedy=remedy
                    )
                if error is None and check_ancestors:
                    error = _ancestor_error(path.parent, dir_what=dir_what, remedy=remedy)
                if error is not None:
                    return None, error
            if info.st_size > MAX_TRUST_ROOT_BYTES:
                return None, f"{what} {path} exceeds the {MAX_TRUST_ROOT_BYTES}-byte limit"
            content = stream.read(MAX_TRUST_ROOT_BYTES + 1)
            if len(content) > MAX_TRUST_ROOT_BYTES:
                return None, f"{what} {path} exceeds the {MAX_TRUST_ROOT_BYTES}-byte limit"
            return content, None
    except OSError:
        return None, f"{what} {path} cannot be inspected"
    finally:
        os.close(dir_fd)


def _trusted_root_from_bytes(content: bytes) -> TrustedRoot:
    """Build a sigstore TrustedRoot from bytes already read, as ``from_file`` does by path."""
    from sigstore.models import TrustedRoot
    from sigstore_models.trustroot import v1 as trustroot_v1

    return TrustedRoot(trustroot_v1.TrustedRoot.from_json(content))


def verify_file_hash(
    path: Path,
    expected_hash: str,
    algorithm: str | None = None,
) -> VerificationResult:
    """Verify a regular file against a well-formed SHA-2 digest."""
    try:
        algorithm, expected_digest = normalize_digest(expected_hash, algorithm)
    except ValueError as exc:
        return VerificationResult(verified=False, error=str(exc))
    actual = compute_file_hash(path, algorithm)
    if actual is None:
        return VerificationResult(verified=False, error="Failed to read a regular artifact file")
    actual_digest = actual.split(":", 1)[1]
    if hmac.compare_digest(actual_digest, expected_digest):
        return VerificationResult(
            verified=True,
            details={"algorithm": algorithm, "digest": actual_digest},
        )
    return VerificationResult(
        verified=False,
        error="Hash mismatch against the expected artifact digest",
        details={"algorithm": algorithm, "expected": expected_digest, "actual": actual_digest},
    )


def _carries_dsse_envelope(bundle_json: bytes) -> bool:
    from nexus_symbiote.core.hashing import MAX_JSON_NESTING, json_nesting_exceeds

    try:
        decoded = bundle_json.decode("utf-8")
        if json_nesting_exceeds(decoded, MAX_JSON_NESTING):
            return False
        document = json.loads(decoded)
    except (ValueError, RecursionError):
        return False
    return isinstance(document, dict) and (
        "dsseEnvelope" in document or "dsse_envelope" in document
    )


def verify_sigstore_digest(
    digest_hex: str,
    bundle_json: bytes,
    expected_identity: str,
    expected_issuer: str,
    *,
    trust_root: str | Path | None = None,
    trust_root_sha256: str | None = None,
) -> VerificationResult:
    """Verify a caller-inspected SHA-256 subject without a network refresh.

    The caller must bind this digest to the inspected artifact. This function
    verifies a message signature over the artifact digest. A DSSE envelope signs
    an in-toto statement instead, so such a bundle is refused with a fixed reason.

    The trust root comes from an explicit ``--trust-root``/``NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT``
    override when one is set (verified against a pinned SHA-256 when one is
    supplied, otherwise required to be a user-owned private file); otherwise
    from the sigstore-python TUF cache, which must be user-owned and private
    (created mode 0700 when missing) or verification fails closed. The path
    actually trusted is reported in ``details["trust_root_path"]``.
    """
    if (
        not expected_identity
        or not expected_identity.strip()
        or not expected_issuer
        or not expected_issuer.strip()
    ):
        return VerificationResult(
            False, error="Expected signer identity and OIDC issuer are both required"
        )
    override_path, override_content, override_source, override_error = _read_explicit_trust_root(
        trust_root, trust_root_sha256
    )
    if override_error is not None:
        return VerificationResult(False, error=override_error)
    try:
        _, digest = normalize_digest(digest_hex, "sha256")
        if len(bundle_json) > MAX_BUNDLE_BYTES:
            raise ValueError("bundle byte limit exceeded")
        if _carries_dsse_envelope(bundle_json):
            return VerificationResult(False, error=DSSE_UNSUPPORTED)
        from sigstore.hashes import Hashed
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity
        from sigstore_models.common.v1 import HashAlgorithm

        bundle = Bundle.from_json(bundle_json)
        policy = Identity(identity=expected_identity, issuer=expected_issuer)
        if override_path is not None and override_content is not None:
            trust_root_path = override_path
            trust_root_source = override_source or "explicit"
            verifier = Verifier(trusted_root=_trusted_root_from_bytes(override_content))
        else:
            cached_path, cached_content, cache_error = _read_sigstore_cache()
            if cache_error is not None or cached_path is None or cached_content is None:
                return VerificationResult(
                    False,
                    error=cache_error or "Sigstore trust-root cache could not be checked",
                    details={"trust_root_path": None},
                )
            trust_root_path = cached_path
            trust_root_source = "cache"
            verifier = Verifier(trusted_root=_trusted_root_from_bytes(cached_content))
        verifier.verify_artifact(
            Hashed(algorithm=HashAlgorithm.SHA2_256, digest=bytes.fromhex(digest)), bundle, policy
        )
        return VerificationResult(
            True,
            identity=expected_identity,
            issuer=expected_issuer,
            details={
                "artifact_digest": f"sha256:{digest}",
                "bundle_digest": f"sha256:{hashlib.sha256(bundle_json).hexdigest()}",
                "method": "sigstore-python.verify_artifact",
                "trust_root_path": str(trust_root_path),
                "trust_root_source": trust_root_source,
            },
        )
    except ImportError:
        return VerificationResult(False, error=SIGSTORE_MISSING)
    except Exception as exc:
        return VerificationResult(
            False, error=f"Sigstore artifact verification failed ({type(exc).__name__})"
        )


def verify_sigstore_bundle(
    artifact_path: Path,
    bundle_path: Path,
    expected_identity: str | None = None,
    expected_issuer: str | None = None,
    *,
    trust_root: str | Path | None = None,
    trust_root_sha256: str | None = None,
) -> VerificationResult:
    """Verify an exact local artifact under an explicitly selected signer policy.

    Inputs are bounded, regular files with no symlink traversal. Streaming hash
    verification uses the supported public sigstore-python 4.x API and offline
    trust material. Missing trust material fails; no network refresh is initiated.
    An explicit trust root (``trust_root``/``NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT``,
    optionally pinned by ``trust_root_sha256``) bypasses the user cache; otherwise
    the cache must pass the private-cache check in ``_read_sigstore_cache``.
    """
    if (
        not expected_identity
        or not expected_identity.strip()
        or not expected_issuer
        or not expected_issuer.strip()
    ):
        return VerificationResult(
            False, error="Expected signer identity and OIDC issuer are both required"
        )
    try:
        with open_regular_file(bundle_path) as stream:
            bundle_bytes = stream.read(MAX_BUNDLE_BYTES + 1)
        if len(bundle_bytes) > MAX_BUNDLE_BYTES:
            return VerificationResult(False, error="Sigstore bundle exceeds byte limit")
        digest = compute_file_hash(artifact_path, "sha256")
        if digest is None:
            return VerificationResult(
                False, error="Artifact is unavailable, changed, or exceeds verification limit"
            )
        return verify_sigstore_digest(
            digest,
            bundle_bytes,
            expected_identity,
            expected_issuer,
            trust_root=trust_root,
            trust_root_sha256=trust_root_sha256,
        )
    except (OSError, ValueError):
        return VerificationResult(
            False, error="Signature verification inputs could not be read safely"
        )


def compute_file_hash(path: Path, algorithm: str = "sha256") -> str | None:
    """Compute a file's SHA-2 digest, returning None when it cannot be checked."""
    try:
        algorithm = algorithm.lower()
        normalize_digest("0" * hashlib.new(algorithm).digest_size * 2, algorithm)
        h = hashlib.new(algorithm)
        total = 0
        with open_regular_file(path) as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > MAX_SIGNED_ARTIFACT_BYTES:
                return None
            while chunk := stream.read(8192):
                total += len(chunk)
                if total > MAX_SIGNED_ARTIFACT_BYTES:
                    return None
                h.update(chunk)
            after = os.fstat(stream.fileno())
            if descriptor_binding(before) != descriptor_binding(after) or pathname_identity(
                path
            ) != (after.st_dev, after.st_ino):
                return None
        return f"{algorithm}:{h.hexdigest()}"
    except (OSError, ValueError):
        return None
