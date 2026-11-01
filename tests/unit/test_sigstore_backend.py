from __future__ import annotations

import pytest

sigstore = pytest.importorskip("sigstore")

from symbiote.attest.sigstore_backend import IdentityConstraint, VerifyPolicySpec, build_policy, verify_bundle  # noqa: E402
from symbiote.model.enums import SignatureOutcome  # noqa: E402


def test_policy_refuses_unconstrained_by_default() -> None:
    with pytest.raises(ValueError):
        build_policy(VerifyPolicySpec())
    policy = build_policy(VerifyPolicySpec(insecure_unconstrained=True))
    assert type(policy).__name__ == "UnsafeNoOp"


def test_policy_builds_identity_and_regex() -> None:
    spec = VerifyPolicySpec(
        identities=[IdentityConstraint(identity="release@example.com", issuer="https://accounts.google.com")]
    )
    assert type(build_policy(spec)).__name__ == "Identity"
    spec2 = VerifyPolicySpec(
        identities=[
            IdentityConstraint(
                identity="re:https://github\\.com/aisecnomad/symbiote/\\.github/workflows/release\\.yml@refs/tags/v.*",
                issuer="https://token.actions.githubusercontent.com",
            ),
            IdentityConstraint(identity="release@example.com", issuer="https://accounts.google.com"),
        ]
    )
    assert type(build_policy(spec2)).__name__ == "AnyOf"


def test_verify_bundle_reports_error_outcome_for_garbage() -> None:
    res = verify_bundle(
        "{not a bundle",
        VerifyPolicySpec(identities=[IdentityConstraint(identity="a@b.c", issuer="https://x")]),
    )
    assert res.outcome is SignatureOutcome.ERROR
    assert "invalid bundle" in (res.reason or "")


def test_yaml_policy(tmp_path) -> None:
    p = tmp_path / "policy.yaml"
    p.write_text(
        "identities:\n  - identity: release@example.com\n    issuer: https://accounts.google.com\nstaging: true\n"
    )
    spec = VerifyPolicySpec.from_yaml(p)
    assert spec.staging and spec.identities[0].issuer == "https://accounts.google.com"
