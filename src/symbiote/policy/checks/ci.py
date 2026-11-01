"""CI/CD agent checks from the 2026 review (``spec/checks.md`` §2.1): the Clinejection pattern.

In February 2026 an issue title injected instructions into an AI triage bot running in GitHub Actions; the bot
executed attacker-chosen commands, poisoned the shared Actions cache, and the release workflow that restored
the cache leaked the publish credentials used for an unauthorized npm release. The identity collector tags
GitHub Actions job identities with the AI-agent actions they run, their triggers, token permissions, secrets
and caches; these checks recognise the dangerous combinations.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from symbiote.model.entities import Finding, Identity
from symbiote.model.enums import IdentityKind, Severity
from symbiote.policy.spec import CheckSpec, PolicyContext, asi, atlas, check

_PUBLISH_SECRET = re.compile(
    r"(npm|pypi|twine|publish|release|vsce|ovsx|marketplace|docker|registry|ghcr|crates|nuget|rubygems|deploy|signing)",
    re.I,
)


def _job_identities(ctx: PolicyContext) -> list[Identity]:
    return [
        i
        for i in ctx.bom.identities
        if i.identity_kind is IdentityKind.GITHUB_APP and i.ref.startswith("github-actions:")
    ]


def _tags(identity: Identity, prefix: str) -> list[str]:
    return sorted(t.split(":", 1)[1] for t in identity.tags if t.startswith(prefix + ":"))


def _secrets(ctx: PolicyContext, identity: Identity) -> list[str]:
    names: list[str] = []
    for binding in ctx.index.credentials_of(identity.id):
        target = ctx.index.get(binding.identity_ref)
        ref = getattr(target, "ref", "")
        if isinstance(ref, str) and ref.startswith("github-secret:"):
            names.append(ref.split(":", 1)[1])
    return sorted(set(names))


@check(
    "SYM-CI-001",
    "AI agent in CI runs on untrusted input with write access, secrets or a shared cache",
    Severity.CRITICAL,
    mappings=(asi(1), asi(4), asi(3), atlas("AML.T0051")),
    inputs=("identities[github-app].tags", "credential_bindings[]"),
    remediation=(
        "Give the agent job a read-only GITHUB_TOKEN (permissions: contents: read, issues: write only if it must label), "
        "no repository secrets, and no shared cache with release workflows; never interpolate issue or PR text into "
        "commands; run triage on untrusted events in an isolated workflow and publish only via OIDC trusted publishing."
    ),
    extension=True,
)
def untrusted_ci_agent(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """An AI-agent action on an untrusted trigger (issues, comments, pull_request_target) holding write/secrets/cache."""
    for identity in _job_identities(ctx):
        agents = _tags(identity, "ai-agent-action")
        triggers = _tags(identity, "untrusted-trigger")
        if not agents or not triggers:
            continue
        writes = [p for p in _tags(identity, "permission") if p.endswith(":write")]
        default_perms = "permissions:default" in identity.tags
        secrets = _secrets(ctx, identity)
        caches = _tags(identity, "cache")
        powers = [
            *(f"token {p}" for p in writes),
            *(["default (possibly write) token permissions"] if default_perms else []),
            *(f"secret {s}" for s in secrets),
            *(f"cache via {c}" for c in caches),
        ]
        if powers:
            yield spec.finding(
                ctx,
                subjects=[identity.id],
                message=f"{identity.ref}: {', '.join(agents)} runs on {', '.join(triggers)} with {', '.join(powers)}.",
            )


@check(
    "SYM-CI-002",
    "Publish credential reachable from an untrusted-trigger workflow",
    Severity.HIGH,
    mappings=(asi(4), asi(3), atlas("AML.T0010")),
    inputs=("identities[github-app].tags", "credential_bindings[]"),
    remediation="Remove long-lived publish tokens: publish with OIDC trusted publishing (npm, PyPI) from a protected release environment that untrusted events cannot trigger.",
    extension=True,
)
def publish_secret_on_untrusted_trigger(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A job triggered by untrusted events can read a long-lived publish/release secret."""
    for identity in _job_identities(ctx):
        if not _tags(identity, "untrusted-trigger"):
            continue
        publish = [s for s in _secrets(ctx, identity) if _PUBLISH_SECRET.search(s)]
        if publish:
            yield spec.finding(
                ctx,
                subjects=[identity.id],
                message=f"{identity.ref} can read publish secrets {', '.join(publish)} on untrusted events.",
            )
