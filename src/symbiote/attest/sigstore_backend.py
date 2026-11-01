"""Sigstore keyless signing and bundle verification with identity constraints (``spec/attestation.md §2-3``).

Requires the ``[sign]`` extra (``sigstore``). Verification implements k8s-aibom Design 002 as code: ``verified``
requires a satisfied signer identity constraint; ``UnsafeNoOp`` is refused unless explicitly requested, and then
the outcome is ``signature-valid-unconstrained``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pydantic import Field

from symbiote.model.base import SymbioteModel
from symbiote.model.enums import SignatureOutcome

try:  # optional dependency
    from sigstore.models import Bundle, ClientTrustConfig
    from sigstore.oidc import IdentityToken, Issuer, detect_credential
    from sigstore.sign import SigningContext
    from sigstore.verify import Verifier
    from sigstore.verify import policy as sp

    HAVE_SIGSTORE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    HAVE_SIGSTORE = False


class IdentityConstraint(SymbioteModel):
    """A signer identity the verifier trusts. ``identity`` is exact, or ``re:<pattern>`` for an anchored regex."""

    identity: str
    issuer: str


class VerifyPolicySpec(SymbioteModel):
    identities: list[IdentityConstraint] = Field(default_factory=list)
    staging: bool = False
    trusted_root: str | None = None
    insecure_unconstrained: bool = False

    @classmethod
    def from_yaml(cls, path: Path) -> VerifyPolicySpec:
        import yaml

        return cls.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})


class SigstoreVerification(SymbioteModel):
    outcome: SignatureOutcome
    payload_type: str | None = None
    payload: bytes | None = None
    identity: str | None = None
    issuer: str | None = None
    log_index: int | None = None
    reason: str | None = None

    @property
    def statement(self) -> dict[str, Any] | None:
        return json.loads(self.payload) if self.payload else None


def _require() -> None:
    if not HAVE_SIGSTORE:
        raise RuntimeError("Sigstore support requires the [sign] extra: pip install 'symbiote[sign]'")


class _RegexIdentity:
    """Sigstore ``VerificationPolicy`` matching the certificate's SAN against an anchored regular expression."""

    def __init__(self, pattern: str, issuer: str) -> None:
        self._re = re.compile(pattern if pattern.startswith("^") else f"^(?:{pattern})$")
        self._issuer = sp.OIDCIssuerV2(issuer)

    def verify(self, cert: Any) -> None:
        from cryptography import x509

        self._issuer.verify(cert)
        try:
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound as exc:
            raise sp.VerificationError("certificate has no SubjectAlternativeName") from exc
        values: list[str] = []
        values += sans.get_values_for_type(x509.RFC822Name)
        values += sans.get_values_for_type(x509.UniformResourceIdentifier)
        for other in sans.get_values_for_type(x509.OtherName):
            values.append(other.value.decode("utf-8", "replace"))
        if not any(self._re.match(v) for v in values):
            raise sp.VerificationError(f"no SAN matches {self._re.pattern!r} (saw {values})")


def build_policy(spec: VerifyPolicySpec) -> Any:
    """Translate the YAML policy into a sigstore ``VerificationPolicy``; refuses to be unconstrained by accident."""
    _require()
    if not spec.identities:
        if spec.insecure_unconstrained:
            return sp.UnsafeNoOp()
        raise ValueError(
            "verification policy has no identity constraints; pass insecure_unconstrained to accept signature-valid-unconstrained outcomes"
        )
    parts: list[Any] = []
    for c in spec.identities:
        if c.identity.startswith("re:"):
            parts.append(_RegexIdentity(c.identity[3:], c.issuer))
        else:
            parts.append(sp.Identity(identity=c.identity, issuer=c.issuer))
    return parts[0] if len(parts) == 1 else sp.AnyOf(parts)


def _trust_config(spec: VerifyPolicySpec) -> Any:
    if spec.trusted_root:
        return ClientTrustConfig.from_json(Path(spec.trusted_root).read_text(encoding="utf-8"))
    return ClientTrustConfig.staging() if spec.staging else ClientTrustConfig.production()


def sign_keyless(
    statement: dict[str, Any],
    *,
    staging: bool = False,
    identity_token: str | None = None,
    issuer_url: str | None = None,
    trusted_root: Path | None = None,
) -> Any:
    """Sign an in-toto statement keylessly; returns a sigstore ``Bundle`` (serialise with ``bundle.to_json()``)."""
    _require()
    from sigstore.dsse import Statement

    cfg = (
        ClientTrustConfig.from_json(trusted_root.read_text(encoding="utf-8"))
        if trusted_root
        else (ClientTrustConfig.staging() if staging else ClientTrustConfig.production())
    )
    ctx = SigningContext.from_trust_config(cfg)
    if identity_token:
        token = IdentityToken(identity_token)
    elif issuer_url:
        token = Issuer(issuer_url).identity_token()
    else:
        ambient = detect_credential()
        if ambient is None:
            raise RuntimeError("no ambient OIDC credential; pass identity_token or issuer_url")
        token = IdentityToken(ambient)
    stmt = Statement(json.dumps(statement, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    with ctx.signer(token) as signer:
        return signer.sign_dsse(stmt)


def verify_bundle(
    bundle_source: str | bytes | Path, spec: VerifyPolicySpec, *, expected_predicate_types: Iterable[str] = ()
) -> SigstoreVerification:
    """Verify a Sigstore bundle carrying a DSSE envelope and classify the outcome (Design 002 vocabulary)."""
    _require()
    raw = (
        bundle_source.read_text(encoding="utf-8")
        if isinstance(bundle_source, Path)
        else (bundle_source.decode("utf-8") if isinstance(bundle_source, bytes) else bundle_source)
    )
    try:
        bundle = Bundle.from_json(raw)
    except Exception as exc:
        return SigstoreVerification(outcome=SignatureOutcome.ERROR, reason=f"invalid bundle: {exc}")
    try:
        policy = build_policy(spec)
    except ValueError as exc:
        return SigstoreVerification(outcome=SignatureOutcome.ERROR, reason=str(exc))
    verifier = (
        Verifier(trusted_root=_trust_config(spec).trusted_root)
        if spec.trusted_root
        else (Verifier.staging() if spec.staging else Verifier.production())
    )
    try:
        payload_type, payload = verifier.verify_dsse(bundle, policy)
    except sp.VerificationError as exc:
        msg = str(exc)
        outcome = (
            SignatureOutcome.IDENTITY_MISMATCH
            if "SAN" in msg or "identity" in msg.lower() or "issuer" in msg.lower()
            else SignatureOutcome.FAILED
        )
        return SigstoreVerification(outcome=outcome, reason=msg)
    except Exception as exc:
        return SigstoreVerification(outcome=SignatureOutcome.ERROR, reason=f"{type(exc).__name__}: {exc}")
    identity, issuer = _cert_identity(bundle)
    log_index = bundle.log_entry.log_index if bundle.log_entry is not None else None
    try:
        stmt = json.loads(payload)
    except json.JSONDecodeError as exc:
        return SigstoreVerification(outcome=SignatureOutcome.ERROR, reason=f"payload is not JSON: {exc}")
    expected = set(expected_predicate_types)
    if expected and stmt.get("predicateType") not in expected:
        return SigstoreVerification(
            outcome=SignatureOutcome.FAILED,
            payload_type=payload_type,
            payload=payload,
            identity=identity,
            issuer=issuer,
            log_index=log_index,
            reason=f"unexpected predicateType {stmt.get('predicateType')!r}",
        )
    outcome = (
        SignatureOutcome.SIGNATURE_VALID_UNCONSTRAINED if not spec.identities else SignatureOutcome.VERIFIED
    )
    return SigstoreVerification(
        outcome=outcome,
        payload_type=payload_type,
        payload=payload,
        identity=identity,
        issuer=issuer,
        log_index=log_index,
    )


def _cert_identity(bundle: Any) -> tuple[str | None, str | None]:
    from cryptography import x509
    from cryptography.x509.oid import ObjectIdentifier

    cert = bundle.signing_certificate
    identity: str | None = None
    issuer: str | None = None
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        vals = sans.get_values_for_type(x509.RFC822Name) + sans.get_values_for_type(
            x509.UniformResourceIdentifier
        )
        identity = vals[0] if vals else None
    except x509.ExtensionNotFound:
        pass
    for oid in ("1.3.6.1.4.1.57264.1.8", "1.3.6.1.4.1.57264.1.1"):
        try:
            ext = cert.extensions.get_extension_for_oid(ObjectIdentifier(oid)).value
            raw = getattr(ext, "value", b"")
            issuer = (
                raw.decode("utf-8", "replace").lstrip("\x0c\x16").strip("\x00")
                if isinstance(raw, bytes)
                else str(raw)
            )
            if issuer:
                break
        except x509.ExtensionNotFound:
            continue
    return identity, issuer


__all__ = [
    "HAVE_SIGSTORE",
    "IdentityConstraint",
    "SigstoreVerification",
    "VerifyPolicySpec",
    "build_policy",
    "sign_keyless",
    "verify_bundle",
]
