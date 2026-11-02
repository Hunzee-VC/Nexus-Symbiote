"""identity-config collector: Kubernetes, SPIFFE/IAM references and GitHub Actions job identities."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from symbiote.collect.base import CollectContext, CollectionResult, load_collectors, run_collectors
from symbiote.collect.identity import (
    IdentityConfigCollector,
    action_name,
    agent_marker,
    effective_permissions,
    is_ai_agent_action,
    reference_hits,
    secret_names,
    workflow_events,
)
from symbiote.model.entities import CredentialBinding, Identity
from symbiote.model.enums import (
    CoverageStatus,
    CredentialKind,
    CredentialStorageKind,
    EdgeType,
    IdentityKind,
    Surface,
    UnknownReason,
    ValueState,
)

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
FAKE_PAT = "ghp_" + "Y" * 36  # obviously fake, credential-shaped: must never be echoed
FAKE_AWS_KEY = "AKIA" + "Q" * 16


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _run(root: Path, **kwargs: Any) -> CollectionResult:
    ctx = CollectContext(root=root, agent_id="agent:triage", now=NOW, **kwargs)
    return run_collectors(ctx, [IdentityConfigCollector()])[0]


def _identities(result: CollectionResult) -> dict[str, Identity]:
    return {e.id: e for e in result.entities if isinstance(e, Identity)}


def _bindings(result: CollectionResult) -> dict[str, CredentialBinding]:
    return {e.id: e for e in result.entities if isinstance(e, CredentialBinding)}


def _sources(result: CollectionResult) -> dict[str | None, Any]:
    return {s.locator: s for s in result.coverage[Surface.IDENTITY].sources}


# --------------------------------------------------------------------------------------------- kubernetes

K8S = """\
apiVersion: v1
kind: ServiceAccount
metadata:
  name: triage-agent
  namespace: agents
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/triage-agent-role
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: triage
  namespace: agents
spec:
  template:
    metadata:
      labels:
        app.kubernetes.io/component: llm-gateway
    spec:
      serviceAccountName: triage-agent
      automountServiceAccountToken: true
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: datadog-agent
spec:
  template:
    spec:
      containers: [{name: dd, image: datadog/agent:7}]
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly-report
  namespace: batch
spec:
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccount: reporter
---
- just
- a list document
---
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: ServiceAccount
    metadata:
      name: gke-agent
      namespace: ml
      annotations:
        iam.gke.io/gcp-service-account: agent@proj.iam.gserviceaccount.com
  - apiVersion: v1
    kind: ServiceAccount
    metadata:
      name: aks-agent
      namespace: ml
      annotations:
        azure.workload.identity/client-id: 00000000-1111-2222-3333-444444444444
        azure.workload.identity/tenant-id: 99999999-8888-7777-6666-555555555555
  - apiVersion: v1
    kind: Pod
    metadata:
      name: mcp-server
      namespace: ml
      annotations:
        vault.hashicorp.com/agent-inject: "true"
    spec:
      serviceAccountName: gke-agent
  - apiVersion: v1
    kind: ConfigMap
    metadata: {name: settings}
  - "not an object"
"""


def test_kubernetes_workloads_service_accounts_and_cloud_bindings(tmp_path: Path) -> None:
    _write(tmp_path / "deploy" / "k8s.yaml", K8S)
    result = _run(tmp_path)
    idents = _identities(result)

    sa = idents["ident:k8s-sa/agents/triage-agent"]
    assert sa.identity_kind is IdentityKind.K8S_SA
    assert sa.ref == "system:serviceaccount:agents:triage-agent"
    assert sa.provenance.locator == "deploy/k8s.yaml:4"  # the ServiceAccount object defines it
    assert {
        "automount-token:false",
        "workload:Deployment/triage",
        "agent-workload:Deployment/triage",
        "automount-token:true@Deployment/triage",
    } <= set(sa.tags)

    role = idents["ident:iam-role/arn-aws-iam-123456789012-role-triage-agent-role"]
    assert role.identity_kind is IdentityKind.IAM_ROLE and role.tenant == "123456789012"
    assert {"bound-k8s-sa:system:serviceaccount:agents:triage-agent", "federation:eks-irsa"} <= set(role.tags)

    default_sa = idents["ident:k8s-sa/default/default"]
    assert {"namespace:implicit", "workload:DaemonSet/datadog-agent"} <= set(default_sa.tags)
    assert idents["ident:k8s-sa/batch/reporter"].provenance.locator.startswith("deploy/k8s.yaml:")

    gcp = idents["ident:gcp-sa/agent-proj.iam.gserviceaccount.com"]
    assert gcp.identity_kind is IdentityKind.GCP_SA and gcp.ref == "agent@proj.iam.gserviceaccount.com"
    azure = idents["ident:azure-mi/00000000-1111-2222-3333-444444444444"]
    assert azure.identity_kind is IdentityKind.AZURE_MANAGED_IDENTITY
    assert azure.tenant == "99999999-8888-7777-6666-555555555555"

    acts = {(e.to_ref, e.qualifiers.get("via")) for e in result.edges if e.type is EdgeType.ACTS_AS}
    assert acts == {
        ("ident:k8s-sa/agents/triage-agent", None),
        (
            "ident:iam-role/arn-aws-iam-123456789012-role-triage-agent-role",
            "system:serviceaccount:agents:triage-agent",
        ),
        ("ident:k8s-sa/ml/gke-agent", None),
        ("ident:gcp-sa/agent-proj.iam.gserviceaccount.com", "system:serviceaccount:ml:gke-agent"),
    }
    deploy_edge = next(e for e in result.edges if e.to_ref == "ident:k8s-sa/agents/triage-agent")
    assert deploy_edge.from_ref == "agent:triage"
    assert deploy_edge.qualifiers["marker"] == "label:app.kubernetes.io/component=llm-gateway"
    assert deploy_edge.qualifiers["method"] == "heuristic"
    assert deploy_edge.declared_by == "deploy/k8s.yaml:21"  # the serviceAccountName line
    pod_edge = next(e for e in result.edges if e.to_ref == "ident:k8s-sa/ml/gke-agent")
    assert pod_edge.qualifiers["marker"] == "name:mcp-server"
    # the datadog DaemonSet runs as the default service account but is no AI agent: no edge
    assert all(e.to_ref != "ident:k8s-sa/default/default" for e in result.edges)
    assert _sources(result)["deploy/k8s.yaml"].ok


def test_agent_marker_rules() -> None:
    assert agent_marker("triage-agent", []) == "name:triage-agent"
    assert agent_marker("web", [{"labels": {"tier": "mcp"}}]) == "label:tier=mcp"
    assert agent_marker("web", [{"labels": {"llm.example.com/role": "x"}}]) == "label:llm.example.com/role=x"
    assert (
        agent_marker("web", [{"annotations": {"example.com/agent": "yes"}}]) == "annotation:example.com/agent"
    )
    assert agent_marker("web", [{"annotations": {"team": "agents"}}]) == "annotation:team"
    assert agent_marker("web", [{"annotations": {"cfg": "agent " * 20}}]) is None  # long values are blobs
    last = {"kubectl.kubernetes.io/last-applied-configuration": '{"name": "agent"}'}
    assert agent_marker("web", [{"annotations": last}]) is None
    assert agent_marker("datadog-agent", []) is None
    assert agent_marker("web", [{"annotations": {"vault.hashicorp.com/agent-inject": "true"}}]) is None
    assert agent_marker("web", [{"labels": "nope", "annotations": ["nope"]}]) is None


def test_templated_and_broken_yaml_are_coverage_facts(tmp_path: Path) -> None:
    _write(
        tmp_path / "chart" / "templates" / "deploy.yaml",
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}-agent\n  labels: {{ x\n",
    )
    _write(tmp_path / "bad.yaml", "apiVersion: v1\nkind: Pod\nmetadata: {name: x\n")
    _write(tmp_path / "plain.yaml", "key: value\n")  # no apiVersion/kind: text scan only
    (tmp_path / "binary.json").write_bytes(b"\xff\xfe\xfa")
    _write(tmp_path / "huge.toml", "a = 1\n" * 100)
    result = _run(tmp_path, max_file_bytes=400)
    sources = _sources(result)
    assert sources["chart/templates/deploy.yaml"].error_class == "unsupported-source"
    assert sources["bad.yaml"].error_class == "parse-error"
    assert sources["plain.yaml"].ok
    assert sources["binary.json"].error_class == "not-utf8"
    assert sources["huge.toml"].error_class == "too-large"
    assert result.coverage[Surface.IDENTITY].status is CoverageStatus.PARTIAL
    assert any("YAML not analysed" in w for w in result.warnings)


# --------------------------------------------------------------------------------------------- references


def test_spiffe_ids_and_iam_role_arns_in_config(tmp_path: Path) -> None:
    _write(
        tmp_path / "config" / "spire.json",
        '{\n  "ids": ["spiffe://prod.example.org/ns/agents/sa/triage", "spiffe://prod.example.org"],\n'
        '  "role": "arn:aws:iam::123456789012:role/reader"\n}\n',
    )
    _write(tmp_path / "config" / "settings.toml", "trust = 'spiffe://dev.example.org/workload/a',\n")
    _write(
        tmp_path / "infra" / "main.tf",
        'assume = "arn:aws-us-gov:iam::210987654321:role/service-role/deployer."\n',
    )
    _write(tmp_path / "values.yml", "roles: [arn:aws:iam::123456789012:role/reader, other]\n")
    _write(tmp_path / "notes.md", "spiffe://ignored.example.org/not-config\n")
    result = _run(tmp_path)
    idents = _identities(result)
    triage = idents["ident:spiffe/prod.example.org-ns-agents-sa-triage"]
    assert triage.identity_kind is IdentityKind.SPIFFE
    assert triage.issuer == "spiffe://prod.example.org"
    assert triage.provenance.locator == "config/spire.json:2"
    assert idents["ident:spiffe/prod.example.org"].ref == "spiffe://prod.example.org"
    assert idents["ident:spiffe/dev.example.org-workload-a"].ref == "spiffe://dev.example.org/workload/a"
    reader = idents["ident:iam-role/arn-aws-iam-123456789012-role-reader"]
    assert reader.ref == "arn:aws:iam::123456789012:role/reader"
    # one identity however often it is referenced; the first reference walked is its locator
    assert reader.provenance.locator in {"config/spire.json:3", "values.yml:1"}
    assert sum(i.ref == reader.ref for i in idents.values()) == 1
    gov = next(i for i in idents.values() if i.ref.startswith("arn:aws-us-gov"))
    assert gov.ref == "arn:aws-us-gov:iam::210987654321:role/service-role/deployer"
    assert gov.tenant == "210987654321"
    assert not any("ignored" in i.ref for i in idents.values())
    sources = _sources(result)
    assert sources["config/spire.json"].items == 3
    assert sources["infra/main.tf"].ok and "notes.md" not in sources
    assert not result.edges


def test_reference_hits_and_collisions() -> None:
    hits = reference_hits("a: 'spiffe://td.example/x',\nb: arn:aws:iam::123456789012:role/r.\n")
    assert [(h.kind, h.ref, h.line) for h in hits] == [
        (IdentityKind.SPIFFE, "spiffe://td.example/x", 1),
        (IdentityKind.IAM_ROLE, "arn:aws:iam::123456789012:role/r", 2),
    ]
    assert reference_hits("nothing to see") == []


def test_slug_collisions_get_a_digest_suffix(tmp_path: Path) -> None:
    _write(
        tmp_path / "roles.json",
        '["arn:aws:iam::123456789012:role/x+y", "arn:aws:iam::123456789012:role/x=y"]',
    )
    ids = sorted(_identities(_run(tmp_path)))
    assert ids[0] == "ident:iam-role/arn-aws-iam-123456789012-role-x-y"
    assert ids[1].startswith("ident:iam-role/arn-aws-iam-123456789012-role-x-y-") and len(ids) == 2


def test_credential_shaped_identity_refs_are_withheld(tmp_path: Path) -> None:
    _write(
        tmp_path / "sa.yaml",
        "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: leaky\n  annotations:\n"
        f"    eks.amazonaws.com/role-arn: {FAKE_AWS_KEY}\n",
    )
    result = _run(tmp_path)
    assert all(FAKE_AWS_KEY not in i.ref for i in _identities(result).values())
    assert "ident:k8s-sa/default/leaky" in _identities(result)
    [redaction] = result.redactions
    assert redaction.count == 1 and redaction.redaction_class == "credential-shaped-token"


# --------------------------------------------------------------------------------------------- github actions

TRIAGE_WORKFLOW = f"""\
name: Issue triage
on:
  issues:
    types: [opened]
  issue_comment:
  workflow_dispatch:
permissions:
  contents: read
env:
  RELEASE: ${{{{ secrets.NPM_RELEASE_TOKEN }}}}
  HARDCODED: {FAKE_PAT}
jobs:
  triage:
    runs-on: [self-hosted, linux]
    environment: production
    permissions:
      issues: write
      contents: WRITE
      id-token: none
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
      - uses: actions/setup-node@v4
        with:
          cache: npm
      - uses: actions/cache/restore@v4
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{{{ secrets.ANTHROPIC_API_KEY }}}}
          github_token: ${{{{ secrets.GITHUB_TOKEN }}}}
      - run: npx -y @anthropic-ai/claude-code -p "triage this issue"
      - if: secrets.SLACK_WEBHOOK != ''
        run: echo "${{{{ secrets['PAGER_KEY'] }}}}"
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/triage-deployer
      - "junk step"
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
        with:
          cache: false
      - run: python -c "import secrets; secrets.token_hex()"
  release:
    permissions: write-all
    runs-on: {{group: big, labels: [self-hosted]}}
    steps: [{{uses: ./.github/actions/llm-review}}]
  call:
    uses: acme/workflows/.github/workflows/claude-review.yml@main
    secrets: inherit
  not-a-job: just a string
"""


def test_github_workflow_job_identities_capture_clinejection_inputs(tmp_path: Path) -> None:
    _write(tmp_path / ".github" / "workflows" / "triage.yml", TRIAGE_WORKFLOW)
    result = _run(tmp_path)
    idents = _identities(result)
    bindings = _bindings(result)
    wf = ".github/workflows/triage.yml"

    triage = idents["ident:github-actions/github-workflows-triage.yml/triage"]
    assert triage.identity_kind is IdentityKind.GITHUB_APP
    assert triage.ref == f"github-actions:{wf}#triage"
    assert triage.provenance.locator == f"{wf}:13"  # the job key
    assert {
        "trigger:issues",
        "trigger:issue_comment",
        "trigger:workflow_dispatch",
        "untrusted-trigger:issues",
        "untrusted-trigger:issue_comment",
        "permission:contents:write",
        "permission:issues:write",
        "ai-agent-action:anthropics/claude-code-action",
        "ai-agent-cli:claude-code",
        "cache:actions/setup-node",
        "cache:actions/cache",
        "checkout:untrusted-ref",
        "runner:self-hosted",
        "environment:production",
        "inline-secret-literal",
    } <= set(triage.tags)
    assert "untrusted-trigger:workflow_dispatch" not in triage.tags
    assert not any(t.startswith("permission:id-token") for t in triage.tags)

    token = bindings["cred:github-actions/github-workflows-triage.yml/triage/github-token"]
    assert token.credential_kind is CredentialKind.EPHEMERAL_TASK_SCOPED
    assert token.subject_ref == token.identity_ref == triage.id
    assert token.scopes_granted is not None
    assert token.scopes_granted.value == ["contents:write", "issues:write"]
    assert token.scopes_granted.locator == f"{wf}:16"  # the job-level permissions key
    assert token.storage.kind is CredentialStorageKind.SECRET_MANAGER
    assert token.storage.locator == "github-actions:GITHUB_TOKEN"

    secrets = {b.identity_ref for b in bindings.values() if b.subject_ref == triage.id} - {triage.id}
    assert secrets == {
        "ident:github-secret/anthropic_api_key",
        "ident:github-secret/npm_release_token",
        "ident:github-secret/slack_webhook",
        "ident:github-secret/pager_key",
    }
    assert "ident:github-secret/github_token" not in idents  # the job token is not a repository secret
    npm = bindings["cred:github-actions/github-workflows-triage.yml/triage/secret/npm_release_token"]
    assert npm.credential_kind is CredentialKind.STATIC_LONG_LIVED
    assert npm.storage.locator == "github-secrets:NPM_RELEASE_TOKEN"
    assert npm.provenance.locator == f"{wf}:10"
    assert idents["ident:github-secret/npm_release_token"].ref == "github-secret:NPM_RELEASE_TOKEN"
    holds = {
        (e.from_ref, e.to_ref, e.qualifiers["kind"])
        for e in result.edges
        if e.type is EdgeType.HOLDS_CREDENTIAL
    }
    assert (triage.id, npm.id, "static-long-lived") in holds
    assert (triage.id, token.id, "ephemeral-task-scoped") in holds
    deployer = idents["ident:iam-role/arn-aws-iam-123456789012-role-triage-deployer"]
    assert f"referenced-by:github-actions:{wf}#triage" in deployer.tags

    build = idents["ident:github-actions/github-workflows-triage.yml/build"]
    assert "permission:contents:read" in build.tags  # inherited from the workflow level
    assert not any(t.startswith(("cache:", "ai-agent")) for t in build.tags)
    build_token = bindings["cred:github-actions/github-workflows-triage.yml/build/github-token"]
    assert build_token.scopes_granted is not None and build_token.scopes_granted.locator == f"{wf}:7"
    assert "ident:github-secret/token_hex" not in idents  # plain script text is not an expression

    release = idents["ident:github-actions/github-workflows-triage.yml/release"]
    assert {
        "permission:*:write",
        "runner:self-hosted",
        "ai-agent-action:./.github/actions/llm-review",
    } <= set(release.tags)
    call = idents["ident:github-actions/github-workflows-triage.yml/call"]
    assert {
        "calls-workflow:acme/workflows/.github/workflows/claude-review.yml",
        "secrets:inherit",
        "ai-agent-action:acme/workflows",
        "permission:contents:read",  # no job-level permissions: the workflow level applies
    } <= set(call.tags)

    dump = json.dumps([e.to_json_dict() for e in result.entities] + [e.to_json_dict() for e in result.edges])
    assert FAKE_PAT not in dump and FAKE_PAT not in json.dumps(result.warnings)
    [redaction] = result.redactions
    assert redaction.count == 1  # the hard-coded literal is counted once although every job reads it
    assert _sources(result)[wf].ok


def test_workflow_edge_cases(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    _write(wf_dir / "list.yml", "- not\n- a workflow\n")
    _write(wf_dir / "nojobs.yaml", "on: push\njobs: [1, 2]\n")
    _write(wf_dir / "broken.yml", "on: [push\njobs:\n")
    _write(wf_dir / "empty.yml", "")
    _write(wf_dir / "nested" / "deep.yml", "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n")
    result = _run(tmp_path)
    sources = _sources(result)
    assert sources[".github/workflows/list.yml"].ok and sources[".github/workflows/list.yml"].items == 0
    assert sources[".github/workflows/nojobs.yaml"].ok
    assert sources[".github/workflows/broken.yml"].error_class == "parse-error"
    assert sources[".github/workflows/empty.yml"].ok
    assert sources[".github/workflows/nested/deep.yml"].source == "yaml-config"  # GitHub ignores sub-dirs
    assert not _identities(result)


@pytest.mark.parametrize(
    ("workflow", "job", "expected"),
    [
        ({}, {}, (None, "default")),
        ({"permissions": "read-all"}, {}, (["*:read"], "workflow")),
        ({"permissions": "read-all"}, {"permissions": "write-all"}, (["*:write"], "job")),
        ({"permissions": {"contents": "write"}}, {"permissions": {}}, ([], "job")),
        ({}, {"permissions": {"issues": "write", "pages": "none", "x": 1}}, (["issues:write"], "job")),
        ({}, {"permissions": "admin"}, (None, "unrecognized")),
        ({}, {"permissions": None}, (None, "unrecognized")),
    ],
)
def test_effective_permissions(
    workflow: dict[str, Any], job: dict[str, Any], expected: tuple[list[str] | None, str]
) -> None:
    assert effective_permissions(workflow, job) == expected


def test_permission_tags_default_empty_and_unrecognized(tmp_path: Path) -> None:
    _write(
        tmp_path / ".github" / "workflows" / "p.yml",
        "on: push\njobs:\n  none:\n    permissions: {}\n  odd:\n    permissions: admin\n"
        "  dflt:\n    runs-on: ubuntu-latest\n",
    )
    result = _run(tmp_path)
    idents = _identities(result)
    assert "permissions:none" in idents["ident:github-actions/github-workflows-p.yml/none"].tags
    assert "permissions:unrecognized" in idents["ident:github-actions/github-workflows-p.yml/odd"].tags
    assert "permissions:default" in idents["ident:github-actions/github-workflows-p.yml/dflt"].tags
    bindings = _bindings(result)
    empty = bindings["cred:github-actions/github-workflows-p.yml/none/github-token"].scopes_granted
    assert empty is not None and empty.state is ValueState.PRESENT and empty.value == []
    default = bindings["cred:github-actions/github-workflows-p.yml/dflt/github-token"].scopes_granted
    assert (
        default is not None and default.state is ValueState.UNKNOWN
    )  # the repository default is not in files
    assert default.unknown_reason is UnknownReason.NOT_COLLECTED
    assert default.locator == ".github/workflows/p.yml:7"  # no permissions key: the job itself


@pytest.mark.parametrize(
    ("on", "events"),
    [
        ({"on": "push"}, ["push"]),
        ({"on": ["push", "issues", 3, " "]}, ["issues", "push"]),
        (
            {True: {"pull_request_target": None, "schedule": [{"cron": "0 0 * * *"}]}},
            ["pull_request_target", "schedule"],
        ),
        ({"on": 5}, []),
        ({}, []),
    ],
)
def test_workflow_events(on: dict[Any, Any], events: list[str]) -> None:
    assert workflow_events(on) == events


def test_action_names_and_ai_agent_detection() -> None:
    assert action_name("actions/cache/restore@v4") == "actions/cache"
    assert action_name("Anthropics/Claude-Code-Action@v1") == "anthropics/claude-code-action"
    assert action_name("./.github/actions/review") == "./.github/actions/review"
    assert (
        action_name("docker://ghcr.io/acme/claude-runner:1.2@sha256:abc")
        == "docker://ghcr.io/acme/claude-runner"
    )
    assert action_name("docker://alpine:3") == "docker://alpine"
    assert is_ai_agent_action("anthropics/claude-code-base-action@beta")
    assert is_ai_agent_action("google-github-actions/run-gemini-cli@v0")
    assert is_ai_agent_action("openai/codex-action@v1")
    assert is_ai_agent_action("github/copilot-swe-agent@v1")
    assert is_ai_agent_action("cline/cline-action@v1")
    assert is_ai_agent_action("acme/actions/llm-review@v2")
    assert not is_ai_agent_action("actions/checkout@v4")


def test_secret_name_extraction() -> None:
    text = (
        "${{ secrets.npm_token || secrets['Other_Key'] }} and secrets.PLAIN and ${{ secrets.GITHUB_TOKEN }}"
    )
    assert secret_names(text, expression=False) == ["NPM_TOKEN", "OTHER_KEY"]
    assert secret_names("secrets.PLAIN != ''", expression=True) == ["PLAIN"]


# --------------------------------------------------------------------------------------------- coverage


def test_empty_repository_is_queried(tmp_path: Path) -> None:
    _write(tmp_path / "README.md", "nothing")
    result = _run(tmp_path)
    cov = result.coverage[Surface.IDENTITY]
    assert cov.status is CoverageStatus.QUERIED and cov.items_seen == 0
    assert not result.entities and not result.edges and not result.redactions


def test_truncated_walk_is_reported(tmp_path: Path) -> None:
    for i in range(3):
        _write(tmp_path / f"c{i}.json", "{}")
    result = _run(tmp_path, max_files=2)
    cov = result.coverage[Surface.IDENTITY]
    assert cov.status is CoverageStatus.TRUNCATED and cov.truncated_at == 2
    assert any("walk stopped" in w for w in result.warnings)


def test_registered_as_builtin_and_always_detects(tmp_path: Path) -> None:
    [collector] = load_collectors(["identity-config"], include_plugins=False)
    assert isinstance(collector, IdentityConfigCollector)
    assert collector.detect(CollectContext(root=tmp_path))
    assert collector.record().surfaces == [Surface.IDENTITY]


def test_repeated_service_account_definitions_merge(tmp_path: Path) -> None:
    base = "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: agent\n  namespace: ai\n"
    _write(tmp_path / "base" / "sa.yaml", base)
    _write(
        tmp_path / "overlays" / "prod" / "sa-patch.yaml",
        base
        + "  annotations:\n    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/prod-agent\n"
        + "automountServiceAccountToken: false\n",
    )
    _write(
        tmp_path / "deploy.yaml",
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: worker\n  namespace: ai\n"
        "spec:\n  template:\n    spec:\n      serviceAccountName: agent\n",
    )
    result = _run(tmp_path)
    idents = _identities(result)
    sa = idents["ident:k8s-sa/ai/agent"]
    assert sa.provenance.locator == "base/sa.yaml:4"
    assert "automount-token:false" in sa.tags
    role = idents["ident:iam-role/arn-aws-iam-123456789012-role-prod-agent"]
    assert "bound-k8s-sa:system:serviceaccount:ai:agent" in role.tags
    assert not result.edges  # "worker" carries no agent marker
