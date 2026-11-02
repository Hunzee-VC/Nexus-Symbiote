"""``identity-config`` collector: workload identities and credentials declared in repository files.

Files only: nothing is executed and no CLI (``kubectl``, ``gh``, ``aws``) is consulted; YAML is parsed with
the safe loader, everything else is scanned as text. Secret *values* are never read into entities.

* **Kubernetes manifests** (``*.yaml``/``*.yml`` documents with ``apiVersion`` and ``kind``; ``kind: List`` is
  unwrapped): every workload (Deployment, StatefulSet, DaemonSet, Job, CronJob, Pod) runs as
  ``system:serviceaccount:<namespace>:<serviceAccountName>`` (``default`` when unset) -> ``Identity(k8s-sa)``.
  ServiceAccount objects add the cloud identities their workload-identity annotations bind
  (EKS IRSA ``eks.amazonaws.com/role-arn`` -> ``iam-role``, GKE ``iam.gke.io/gcp-service-account`` -> ``gcp-sa``,
  ``azure.workload.identity/client-id`` -> ``azure-managed-identity``) and ``automountServiceAccountToken``.
  The scanned agent ``actsAs`` a workload's service account, and the cloud identities bound to it, only when
  the workload carries an obvious agent marker (``agent``, ``mcp`` or ``llm`` in its name, labels or
  annotations; well-known infrastructure agents such as ``datadog-agent`` or Vault's ``agent-inject``
  annotations are excluded). Other workloads' identities are tagged ``workload:<kind>/<name>`` without edges.
* **SPIFFE IDs** and **AWS IAM role ARNs** referenced in YAML/JSON/TOML/HCL configuration -> ``Identity``.
* **GitHub Actions workflows** (``.github/workflows/*.yml``): each job is an ``Identity(github-app)`` tagged with
  its triggers (``untrusted-trigger:<event>`` for attacker-controllable events), effective ``GITHUB_TOKEN``
  permissions (job-level overrides workflow-level; absent -> ``permissions:default``), AI-agent actions or
  CLIs, cache use, untrusted checkouts and self-hosted runners. The job holds an ``ephemeral-task-scoped``
  binding for its token and a ``static-long-lived`` binding (``holdsCredential`` edge) for every repository
  secret it references by name. Together these are the inputs of the Clinejection pattern: an AI agent fed by
  an untrusted trigger while holding a write token, secrets or a shared cache.

Every examined file is a coverage source (``ok``, ``parse-error``, ``unsupported-source`` for templated YAML
such as Helm charts, or the read error class).
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Final

import yaml

from symbiote.collect._common import as_str_list
from symbiote.collect.base import BaseCollector, CollectContext, CollectionResult
from symbiote.model.common import Claim, Provenance, looks_like_secret
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    CredentialBinding,
    CredentialStorage,
    Identity,
    Redaction,
)
from symbiote.model.enums import (
    ClaimMethod,
    CollectorMode,
    CoverageStatus,
    CredentialKind,
    CredentialStorageKind,
    EdgeScope,
    EdgeType,
    IdentityKind,
    Surface,
    UnknownReason,
)
from symbiote.model.ids import make_id, slugify

try:
    from yaml import CSafeLoader as _SafeLoader
except ImportError:  # pragma: no cover - PyYAML built without libyaml
    from yaml import SafeLoader as _SafeLoader  # type: ignore[assignment]

__all__ = [
    "AI_AGENT_ACTIONS",
    "UNTRUSTED_TRIGGERS",
    "WORKLOAD_POD_SPEC",
    "IdentityConfigCollector",
    "action_name",
    "agent_marker",
    "bypass_flags",
    "effective_permissions",
    "expression_spans",
    "is_ai_agent_action",
    "reference_hits",
    "secret_names",
    "untrusted_expressions",
    "workflow_events",
]

# --------------------------------------------------------------------------------------------- tables

#: Workload kind -> path of its pod spec.
WORKLOAD_POD_SPEC: Final[dict[str, tuple[str, ...]]] = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}


@dataclass(frozen=True, slots=True)
class _CloudBinding:
    kind: IdentityKind
    prefix: str
    mechanism: str


#: ServiceAccount annotation -> the cloud identity it binds (workload identity federation).
SA_ANNOTATIONS: Final[dict[str, _CloudBinding]] = {
    "eks.amazonaws.com/role-arn": _CloudBinding(IdentityKind.IAM_ROLE, "iam-role", "eks-irsa"),
    "iam.gke.io/gcp-service-account": _CloudBinding(IdentityKind.GCP_SA, "gcp-sa", "gke-workload-identity"),
    "azure.workload.identity/client-id": _CloudBinding(
        IdentityKind.AZURE_MANAGED_IDENTITY, "azure-mi", "azure-workload-identity"
    ),
}
_AZURE_TENANT_ANNOTATION: Final = "azure.workload.identity/tenant-id"

#: Substrings that mark a workload as an AI agent (name, label keys/values, annotation keys/short values).
AGENT_MARKERS: Final = ("agent", "mcp", "llm")
#: Infrastructure agents whose names contain "agent" but are not AI agents (matched as substrings).
INFRA_AGENT_VENDORS: Final = (
    "datadog",
    "vault",
    "consul",
    "otel",
    "opentelemetry",
    "elastic",
    "newrelic",
    "jenkins",
    "buildkite",
    "gitlab",
    "teleport",
    "splunk",
    "dynatrace",
    "oneagent",
    "instana",
    "sysdig",
    "wazuh",
    "azure-pipelines",
    "ssm-agent",
    "cloudwatch",
    "spire",
    "grafana",
    "velero",
    "pilot-agent",
    "appdynamics",
    "crowdstrike",
    "zabbix",
)
#: Annotation values longer than this are configuration blobs, not markers.
_MAX_MARKER_VALUE: Final = 63
_LAST_APPLIED: Final = "kubectl.kubernetes.io/last-applied-configuration"

#: Events whose payload an outside party controls (issue titles, comments, fork PR heads, ...).
UNTRUSTED_TRIGGERS: Final = frozenset(
    {
        "issues",
        "issue_comment",
        "pull_request_target",
        "discussion",
        "discussion_comment",
        "pull_request_review",  # the review body is attacker-controlled text
        "pull_request_review_comment",
        "workflow_run",
    }
)
_PERMISSION_SHORTHANDS: Final[dict[str, str]] = {"read-all": "read", "write-all": "write"}
_GRANTED_LEVELS: Final = frozenset({"read", "write"})

#: Known AI coding-agent actions (``owner/repo``), prefixes, and name markers.
AI_AGENT_ACTIONS: Final = frozenset(
    {
        "anthropics/claude-code-action",
        "anthropics/claude-code-base-action",
        "openai/codex-action",
        "google-github-actions/run-gemini-cli",
    }
)
AI_AGENT_ACTION_PREFIXES: Final = ("github/copilot-", "cline/")
AI_AGENT_ACTION_MARKERS: Final = ("claude", "codex", "gemini-cli", "copilot", "ai-agent", "llm")
#: AI coding-agent CLIs invoked from ``run:`` steps.
_AI_AGENT_CLIS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "claude-code",
        re.compile(r"@anthropic-ai/claude-code\b|(?:^|[\s;&|(`])claude\s+(?:-p\b|--print\b|--dangerously)"),
    ),
    ("codex", re.compile(r"@openai/codex\b|(?:^|[\s;&|(`])codex\s+exec\b")),
    ("gemini-cli", re.compile(r"@google/gemini-cli\b|(?:^|[\s;&|(`])gemini\s+(?:-p\b|--prompt\b|--yolo\b)")),
    ("cline", re.compile(r"(?:^|[\s;&|(`/])cline\s+(?:-|task\b)")),
)
#: Event fields any GitHub user can set (GitHub Security Lab's untrusted-input list). Templated into an agent's
#: prompt or command they are the root cause of Clinejection; bounded alternations keep the scan linear.
_UNTRUSTED_EXPR: Final = re.compile(
    r"github\.head_ref\b|github\.event\.(?:"
    r"issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))|comment\.body"
    r"|review\.body|review_comment\.body|discussion\.(?:title|body)"
    r"|pages(?:\[[^\]]{0,24}\]|\.\*)?\.page_name"
    r"|(?:commits(?:\[[^\]]{0,24}\]|\.\*)?|head_commit)\.(?:message|author\.(?:email|name))"
    r"|workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:email|name))))\b"
)
#: Flags that start a coding-agent CLI with every approval (and often the sandbox) disabled.
_BYPASS_FLAGS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("--dangerously-skip-permissions", re.compile(r"--dangerously-skip-permissions(?![\w-])")),
    (
        "--permission-mode=bypassPermissions",
        re.compile(r"--permission-mode[=\s]+[\"']?bypassPermissions(?![\w-])"),
    ),
    (
        "--dangerously-bypass-approvals-and-sandbox",
        re.compile(r"--dangerously-bypass-approvals-and-sandbox(?![\w-])"),
    ),
    (
        "--ask-for-approval=never",
        re.compile(r"(?:--ask-for-approval|(?<![\w-])-a)[=\s]+[\"']?never(?![\w-])"),
    ),
    ("--yolo", re.compile(r"(?<![\w-])--yolo(?![\w-])")),
    ("--approval-mode=yolo", re.compile(r"--approval-mode[=\s]+[\"']?yolo(?![\w-])")),
    ("--trust-all-tools", re.compile(r"--trust-all-tools(?![\w-])")),
    ("--allow-all-tools", re.compile(r"--allow-all-tools(?![\w-])")),
    ("--yes-always", re.compile(r"--yes-always(?![\w-])")),
)
_UNRESTRICTED_BASH: Final = re.compile(r"(?<![\w-])Bash\b(?!\s*\()")
_MAX_SCANNED: Final = 64 * 1024


def untrusted_expressions(text: str) -> list[str]:
    """Attacker-controllable ``${{ ... }}`` expressions in ``text`` (normalised, de-duplicated, sorted)."""
    found = {
        m.group(0)
        for body in expression_spans(text[:_MAX_SCANNED])
        for m in _UNTRUSTED_EXPR.finditer(body[:4096])
    }
    return sorted(found)


def bypass_flags(text: str) -> list[str]:
    """Approval-bypass flags present in an agent invocation or action input."""
    head = text[:_MAX_SCANNED]
    return sorted(name for name, pattern in _BYPASS_FLAGS if pattern.search(head))


#: ``actions/checkout`` refs that check out attacker-controlled code (the "pwn request" pattern).
_UNTRUSTED_REF: Final = re.compile(
    r"github\.event\.pull_request\.head\.|github\.head_ref|github\.event\.issue"
)

_SECRET_REF: Final = re.compile(
    r"\bsecrets\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_]*)|\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*\])"
)
#: The job token is reachable as ``secrets.GITHUB_TOKEN`` but is not a repository secret.
_JOB_CREDENTIAL_NAME: Final = "GITHUB_TOKEN"

_SPIFFE_ID: Final = re.compile(r"spiffe://[a-z0-9.-]+(?:/[A-Za-z0-9._~%!$&'()*+,;=:@/-]*)?")
_IAM_ROLE_ARN: Final = re.compile(r"arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]+", re.ASCII)


@dataclass(frozen=True, slots=True)
class _ReferencePattern:
    kind: IdentityKind
    prefix: str
    needle: str
    pattern: re.Pattern[str]
    strip: str


#: Identity references found by text scan; ``strip`` removes trailing delimiters the pattern can swallow.
_REFERENCE_PATTERNS: Final = (
    _ReferencePattern(IdentityKind.SPIFFE, "spiffe", "spiffe://", _SPIFFE_ID, "'),;.:!*/"),
    _ReferencePattern(IdentityKind.IAM_ROLE, "iam-role", "arn:aws", _IAM_ROLE_ARN, ".,"),
)

#: File suffix -> coverage source label (workflows are recognised by location first).
_SOURCE_LABELS: Final[dict[str, str]] = {
    ".yaml": "yaml-config",
    ".yml": "yaml-config",
    ".json": "json-config",
    ".toml": "toml-config",
    ".tf": "hcl-config",
    ".tfvars": "hcl-config",
    ".hcl": "hcl-config",
}
_WORKFLOW_LABEL: Final = "github-actions-workflow"
_YAML_LABEL: Final = "yaml-config"


# --------------------------------------------------------------------------------------------- pure helpers


@dataclass(frozen=True, slots=True)
class ReferenceHit:
    kind: IdentityKind
    prefix: str
    ref: str
    line: int

    @property
    def key(self) -> tuple[str, ...]:
        """Id parts: the reference without its ``spiffe://`` scheme (ARNs are used whole)."""
        return (self.ref.removeprefix("spiffe://"),)


_AGENT_DECLARATIONS: Final = frozenset({"symbiote.yaml", "symbiote.yml", "agent.yaml", "agent.yml"})


def reference_hits(text: str) -> list[ReferenceHit]:
    """SPIFFE IDs and IAM role ARNs referenced anywhere in ``text``, with 1-based line numbers."""
    hits: list[ReferenceHit] = []
    for rp in _REFERENCE_PATTERNS:
        if rp.needle not in text:
            continue
        line, offset = 1, 0
        for m in rp.pattern.finditer(text):
            line += text.count(
                "\n", offset, m.start()
            )  # carried forward: linear in the text, not hits x size
            offset = m.start()
            ref = m.group(0).rstrip(rp.strip)
            if ref:
                hits.append(ReferenceHit(rp.kind, rp.prefix, ref, line))
    return hits


def _issuer_tenant(kind: IdentityKind, ref: str) -> tuple[str | None, str | None]:
    if kind is IdentityKind.SPIFFE:
        return "spiffe://" + ref.removeprefix("spiffe://").split("/", 1)[0], None
    if kind is IdentityKind.IAM_ROLE and ref.count(":") >= 5:
        return None, ref.split(":")[4] or None
    return None, None


def _marker_hit(text: str) -> bool:
    lowered = text.lower()
    return any(m in lowered for m in AGENT_MARKERS) and not any(v in lowered for v in INFRA_AGENT_VENDORS)


def agent_marker(name: str, metadata: list[Mapping[str, Any]]) -> str | None:
    """First obvious AI-agent marker on a workload (``name:...``, ``label:...``, ``annotation:...``)."""
    if _marker_hit(name):
        return f"name:{name}"
    for meta in metadata:
        labels = meta.get("labels")
        for key, value in labels.items() if isinstance(labels, Mapping) else []:
            if _marker_hit(str(key)) or _marker_hit(str(value)):
                text = str(value)
                keep = len(text) <= 63 and not looks_like_secret(text)  # Kubernetes caps label values at 63
                return f"label:{key}={text}" if keep else f"label:{key}"
        annotations = meta.get("annotations")
        for key, value in annotations.items() if isinstance(annotations, Mapping) else []:
            if str(key) == _LAST_APPLIED:
                continue
            short = isinstance(value, str) and len(value) <= _MAX_MARKER_VALUE
            if _marker_hit(str(key)) or (short and _marker_hit(str(value))):
                return f"annotation:{key}"
    return None


def workflow_events(workflow: Mapping[Any, Any]) -> list[str]:
    """Trigger event names from ``on`` (string, list or map). YAML 1.1 reads a bare ``on`` key as ``True``."""
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        events = [on]
    elif isinstance(on, list):
        events = [e for e in on if isinstance(e, str)]
    elif isinstance(on, Mapping):
        events = [str(k) for k in on]
    else:
        events = []
    return sorted({e.strip() for e in events if e.strip()})


def effective_permissions(
    workflow: Mapping[Any, Any], job: Mapping[Any, Any]
) -> tuple[list[str] | None, str]:
    """``GITHUB_TOKEN`` grants as sorted ``<scope>:<level>`` strings, and where they come from.

    Job-level ``permissions`` replace workflow-level ones; ``read-all``/``write-all`` become ``*:read`` /
    ``*:write``; ``none`` levels grant nothing. Returns ``(None, "default")`` when neither level sets
    permissions (the repository/organisation default applies, which files cannot reveal) and
    ``(None, "unrecognized")`` for values GitHub would not accept.
    """
    if "permissions" in job:
        perms, origin = job["permissions"], "job"
    elif "permissions" in workflow:
        perms, origin = workflow["permissions"], "workflow"
    else:
        return None, "default"
    if isinstance(perms, str):
        level = _PERMISSION_SHORTHANDS.get(perms.strip().lower())
        return ([f"*:{level}"], origin) if level else (None, "unrecognized")
    if not isinstance(perms, Mapping):
        return None, "unrecognized"
    granted = {
        f"{scope}:{level.strip().lower()}"
        for scope, level in perms.items()
        if isinstance(level, str) and level.strip().lower() in _GRANTED_LEVELS
    }
    return sorted(granted), origin


def action_name(uses: str) -> str:
    """``owner/repo`` of a step's ``uses`` (local ``./path`` and ``docker://image`` kept as written, sans tag)."""
    ref = uses.strip()
    if ref.startswith("docker://"):
        image = ref.split("@", 1)[0]
        head, _, tail = image.rpartition("/")
        return f"{head}/{tail.split(':', 1)[0]}" if head else image
    base = ref.split("@", 1)[0]
    if base.startswith((".", "/")):
        return base
    return "/".join(base.split("/")[:2]).lower()


_WHOLE_SECRETS: Final = re.compile(r"toJSON\(\s*secrets\s*\)|\bsecrets\s*\[\s*(?![\'\"])")


def _all_secrets_used(job: Mapping[Any, Any]) -> bool:
    """True when any expression in the job reads the whole secrets context or indexes it by expression."""
    stack: list[object] = [job]
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            if "secrets" in cur and any(
                _WHOLE_SECRETS.search(body) for body in expression_spans(cur[:_MAX_SCANNED])
            ):
                return True
        elif isinstance(cur, Mapping):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return False


def _agent_input_tags(inputs: object) -> set[str]:
    """Tags from an AI-agent action's ``with:`` inputs: untrusted text, bypass flags, open access, raw Bash."""
    tags: set[str] = set()
    if not isinstance(inputs, Mapping):
        return tags
    for key, value in inputs.items():
        if not isinstance(value, str):
            continue
        tags.update(f"prompt-interpolates:{e}" for e in untrusted_expressions(value))
        tags.update(f"agent-cli-bypass:{f}" for f in bypass_flags(value))
        if key == "allowed_non_write_users" and value.strip() == "*":
            tags.add("allows-any-user")  # anyone who can open an issue can drive the agent
        if key in ("allowed_tools", "claude_args", "args") and _UNRESTRICTED_BASH.search(
            value[:_MAX_SCANNED]
        ):
            tags.add("agent-tools:Bash")  # unrestricted shell, not Bash(cmd:*)-scoped
    return tags


def is_ai_agent_action(uses: str) -> bool:
    """True for a known AI coding-agent action or one whose path names an agent/LLM."""
    path = uses.strip().split("@", 1)[0].lower()
    return (
        action_name(uses).lower() in AI_AGENT_ACTIONS
        or path.startswith(AI_AGENT_ACTION_PREFIXES)
        or any(marker in path for marker in AI_AGENT_ACTION_MARKERS)
    )


def _uses_cache(action: str, with_: object) -> bool:
    if action == "actions/cache":
        return True
    if not action.rsplit("/", 1)[-1].startswith("setup-") or not isinstance(with_, Mapping):
        return False
    cache = with_.get("cache")
    return cache not in (None, False, "") and str(cache).strip().lower() not in ("false", "")


def expression_spans(text: str) -> list[str]:
    """Bodies of ``${{ ... }}`` expressions, found with a linear scan (a regex is quadratic on unclosed ``${{``)."""
    spans: list[str] = []
    start = text.find("${{")
    while start != -1:
        end = text.find("}}", start + 3)
        if end == -1:
            break
        spans.append(text[start + 3 : end])
        start = text.find("${{", end + 2)
    return spans


def secret_names(text: str, *, expression: bool) -> list[str]:
    """Repository secret names referenced in ``text`` (upper-cased; ``GITHUB_TOKEN`` excluded).

    Only ``${{ ... }}`` expressions are searched unless ``expression`` (``if:`` values are expressions).
    """
    spans = [text] if expression else expression_spans(text)
    names = ((m.group(1) or m.group(2)).upper() for span in spans for m in _SECRET_REF.finditer(span))
    return [n for n in names if n != _JOB_CREDENTIAL_NAME]


# --------------------------------------------------------------------------------------------- YAML with line numbers


def _yaml_documents(text: str) -> tuple[list[tuple[yaml.Node, Any]], bool]:
    """Safely parse a YAML stream into ``(node, value)`` pairs; the flag is True when parsing failed.

    Nodes keep source marks, so locators can cite exact lines. Documents parsed before an error are kept.
    """
    docs: list[tuple[yaml.Node, Any]] = []
    loader = _SafeLoader(text)
    try:
        while loader.check_node():
            node = loader.get_node()
            if node is None:
                continue
            if _expanded_weight(node) > MAX_EXPANDED_YAML_WEIGHT:
                return docs, True  # alias or merge-key amplification: refuse instead of expanding it
            docs.append((node, loader.construct_document(node)))
    except (yaml.YAMLError, ValueError, TypeError, RecursionError, KeyError, IndexError, AttributeError):
        return docs, True
    finally:
        loader.dispose()
    return docs, False


#: Ceiling on a YAML document's size with every alias expanded (one unit per node plus one per 256 characters
#: of scalar text). Real workflows and manifests stay in the low thousands; a "billion laughs" document is
#: rejected before construction instead of being expanded by the constructor or re-walked per alias.
MAX_EXPANDED_YAML_WEIGHT: Final = 300_000


def _node_children(node: yaml.Node) -> list[yaml.Node]:
    if isinstance(node, yaml.MappingNode):
        return [part for pair in node.value for part in pair]
    if isinstance(node, yaml.SequenceNode):
        return list(node.value)
    return []


def _expanded_weight(root: yaml.Node) -> int:
    """Weight of ``root`` with aliases expanded, memoised per node (linear in the node graph); capped."""
    cap = MAX_EXPANDED_YAML_WEIGHT + 1
    memo: dict[int, int] = {}
    on_path: set[int] = set()
    stack: list[tuple[yaml.Node, bool]] = [(root, False)]
    while stack:
        node, done = stack.pop()
        nid = id(node)
        if done:
            on_path.discard(nid)
            if isinstance(node, yaml.ScalarNode):
                memo[nid] = 1 + len(str(node.value)) // 256
            else:
                memo[nid] = min(cap, 1 + sum(memo[id(c)] for c in _node_children(node)))
            continue
        if nid in memo:
            continue
        if nid in on_path:
            return cap  # recursive anchor
        on_path.add(nid)
        stack.append((node, True))
        stack.extend((c, False) for c in _node_children(node) if id(c) not in memo)
    return memo[id(root)]


def _entry(node: yaml.Node | None, key: str | int) -> tuple[yaml.Node, yaml.Node] | None:
    """``(key node, value node)`` of a mapping entry, or ``(item, item)`` of a sequence index."""
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            if isinstance(k, yaml.ScalarNode) and k.value == str(key):
                return k, v
    elif isinstance(node, yaml.SequenceNode) and isinstance(key, int) and 0 <= key < len(node.value):
        return node.value[key], node.value[key]
    return None


def _child(node: yaml.Node | None, *path: str | int) -> yaml.Node | None:
    for key in path:
        found = _entry(node, key)
        if found is None:
            return None
        node = found[1]
    return node


def _line(node: yaml.Node | None, *path: str | int) -> int:
    """1-based line of the deepest node found along ``path`` (the key's own line for the last mapping key)."""
    cur = node
    line = cur.start_mark.line + 1 if cur is not None else 1
    for key in path:
        found = _entry(cur, key)
        if found is None:
            break
        line = found[0].start_mark.line + 1
        cur = found[1]
    return line


def _scalars(node: yaml.Node | None) -> Iterator[tuple[str | None, yaml.ScalarNode]]:
    """Value scalars under ``node`` in document order with their parent key; shared (aliased) nodes once."""
    if node is None:
        return
    seen: set[int] = set()
    stack: list[tuple[str | None, yaml.Node]] = [(None, node)]
    while stack:
        key, cur = stack.pop()
        if id(cur) in seen:
            continue
        seen.add(id(cur))
        if isinstance(cur, yaml.ScalarNode):
            yield key, cur
        elif isinstance(cur, yaml.MappingNode):
            stack.extend(
                (k.value if isinstance(k, yaml.ScalarNode) else None, v) for k, v in reversed(cur.value)
            )
        elif isinstance(cur, yaml.SequenceNode):
            stack.extend((key, v) for v in reversed(cur.value))


def _dig(data: object, path: tuple[str, ...]) -> object:
    for key in path:
        if not isinstance(data, Mapping):
            return None
        data = data.get(key)
    return data


# --------------------------------------------------------------------------------------------- accumulation


@dataclass(slots=True)
class _Draft:
    kind: IdentityKind
    ref: str
    name: str
    locator: str
    tags: set[str]
    issuer: str | None = None
    tenant: str | None = None


@dataclass(slots=True)
class _Ledger:
    """Identities merged by id (first locator wins, tags union), bindings and edges de-duplicated."""

    collector_ref: str
    now: datetime
    identities: dict[str, _Draft] = field(default_factory=dict)
    bindings: dict[str, CredentialBinding] = field(default_factory=dict)
    edges: dict[tuple[str, str, str], Edge] = field(default_factory=dict)
    redacted: int = 0
    #: ``path:line:column`` of credential-shaped literals seen (each counted once however often it is read)
    withheld: set[str] = field(default_factory=set)

    def identity(
        self,
        kind: IdentityKind,
        prefix: str,
        ref: str,
        *,
        locator: str,
        name: str | None = None,
        tags: set[str] | None = None,
        tenant: str | None = None,
        key: tuple[str, ...] | None = None,
    ) -> str | None:
        """Record (or merge into) an identity; a credential-shaped ``ref`` is withheld and counted.

        The id is ``ident:<prefix>/<slug(key or ref)...>``; a slug collision between distinct references gets
        a digest suffix (``spec/agentbom-profile.md`` section 1.1).
        """
        if looks_like_secret(ref):
            self.redacted += 1
            return None
        parts = key or (ref,)
        ident_id = make_id("ident", prefix, *parts)
        existing = self.identities.get(ident_id)
        if existing is not None and existing.ref != ref:
            ident_id = make_id("ident", prefix, *parts, collision_seed=ref)
            existing = self.identities.get(ident_id)
        issuer, implied_tenant = _issuer_tenant(kind, ref)
        if existing is None:
            self.identities[ident_id] = _Draft(
                kind, ref, name or ref, locator, set(tags or ()), issuer, tenant or implied_tenant
            )
        else:
            existing.tags.update(tags or ())
            existing.tenant = existing.tenant or tenant
        return ident_id

    def binding(self, binding: CredentialBinding) -> None:
        self.bindings.setdefault(binding.id, binding)

    def edge(
        self, edge_type: EdgeType, src: str, dst: str, *, qualifiers: dict[str, str], declared_by: str
    ) -> None:
        key = (edge_type.value, src, dst)
        if key not in self.edges:
            self.edges[key] = Edge.model_validate(
                {
                    "type": edge_type,
                    "from": src,
                    "to": dst,
                    "scope": EdgeScope.RUNTIME,
                    "qualifiers": qualifiers,
                    "declaredBy": declared_by,
                }
            )

    def provenance(self, locator: str) -> Provenance:
        return Provenance(
            method=ClaimMethod.CONFIG, locator=locator, collector=self.collector_ref, observed_at=self.now
        )

    def entities(self) -> list[Identity | CredentialBinding]:
        out: list[Identity | CredentialBinding] = [
            Identity(
                id=ident_id,
                name=d.name,
                provenance=self.provenance(d.locator),
                tags=sorted(d.tags),
                identity_kind=d.kind,
                ref=d.ref,
                issuer=d.issuer,
                tenant=d.tenant,
            )
            for ident_id, d in self.identities.items()
        ]
        out.extend(self.bindings.values())
        return out


@dataclass(slots=True)
class _Workload:
    kind: str
    name: str
    namespace: str
    implicit_namespace: bool
    service_account: str
    locator: str
    marker: str | None
    automount: object


@dataclass(slots=True)
class _ServiceAccount:
    name: str
    namespace: str
    implicit_namespace: bool
    locator: str
    automount: object
    clouds: list[tuple[_CloudBinding, str, str, str | None]] = field(default_factory=list)


@dataclass(slots=True)
class _K8s:
    workloads: list[_Workload] = field(default_factory=list)
    service_accounts: dict[tuple[str, str], _ServiceAccount] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _WorkflowScope:
    display: str
    data: Mapping[Any, Any]
    node: yaml.Node
    events: list[str]


def _sa_ref(namespace: str, name: str) -> str:
    return f"system:serviceaccount:{namespace}:{name}"


# --------------------------------------------------------------------------------------------- collector


class IdentityConfigCollector(BaseCollector):
    """Workload identities, CI job identities and credential bindings declared in repository files."""

    name = "identity-config"
    version = "0.1.0"
    surfaces = (Surface.IDENTITY,)
    mode = CollectorMode.DECLARED

    def detect(self, ctx: CollectContext) -> bool:
        del ctx
        return True  # a repository without identity configuration is itself a recorded fact

    def collect(self, ctx: CollectContext) -> CollectionResult:
        result = self.new_result()
        ledger = _Ledger(collector_ref=self.ref, now=ctx.now)
        k8s = _K8s()
        walked = 0
        for path in ctx.walk():
            walked += 1
            label = self._label(ctx, path)
            if label is not None:
                self._examine(ctx, result, path, label, ledger=ledger, k8s=k8s)
        self._resolve_k8s(ctx, ledger, k8s)
        result.entities.extend(ledger.entities())
        result.edges.extend(ledger.edges.values())
        result.add_source(Surface.IDENTITY, "identity-config:repo-walk", locator=".", ok=True, items=0)
        if walked >= ctx.max_files:
            result.set_status(Surface.IDENTITY, CoverageStatus.TRUNCATED, truncated_at=walked)
            result.warnings.append(f"repository walk stopped at {walked} files; later files not examined")
        withheld = ledger.redacted + len(ledger.withheld)
        if withheld:
            result.redactions.append(
                Redaction(
                    redaction_class="credential-shaped-token",
                    count=withheld,
                    applied_by=self.ref,
                    applied_at=ctx.now,
                )
            )
        return result

    @staticmethod
    def _label(ctx: CollectContext, path: Path) -> str | None:
        label = _SOURCE_LABELS.get(path.suffix.lower())
        if label == _YAML_LABEL:
            parents = path.relative_to(ctx.root).parts[:-1]
            if parents[-2:] == (".github", "workflows"):
                return _WORKFLOW_LABEL
        return label

    def _examine(
        self,
        ctx: CollectContext,
        result: CollectionResult,
        path: Path,
        label: str,
        *,
        ledger: _Ledger,
        k8s: _K8s,
    ) -> None:
        display = ctx.display(path)
        outcome = ctx.read_config(path)  # confined beneath the scan root (or home with user scope)
        if not outcome.ok or outcome.data is None:
            result.add_source(
                Surface.IDENTITY, label, locator=display, ok=False, error_class=outcome.error_class
            )
            return
        try:
            text = outcome.data.decode("utf-8-sig")
        except UnicodeDecodeError:
            result.add_source(Surface.IDENTITY, label, locator=display, ok=False, error_class="not-utf8")
            return
        touched: set[str] = set()
        # the agent's own declaration names the identities it runs as: those are actsAs, not mere mentions
        own_declaration = display in _AGENT_DECLARATIONS
        for hit in reference_hits(text):
            ident = ledger.identity(
                hit.kind, hit.prefix, hit.ref, locator=f"{display}:{hit.line}", key=hit.key
            )
            if ident:
                touched.add(ident)
                if own_declaration:
                    ledger.edge(
                        EdgeType.ACTS_AS,
                        ctx.agent_id,
                        ident,
                        qualifiers={"method": "declared"},
                        declared_by=f"{display}:{hit.line}",
                    )
        error_class: str | None = None
        found = 0
        if label == _WORKFLOW_LABEL:
            error_class = self._workflow(display, text, ledger, touched)
        elif label == _YAML_LABEL and "apiVersion" in text and "kind" in text:
            error_class, found = self._k8s_file(display, text, k8s)
        if error_class is not None:
            result.warnings.append(f"{display}: YAML not analysed ({error_class})")
        result.add_source(
            Surface.IDENTITY,
            label,
            locator=display,
            ok=error_class is None,
            error_class=error_class,
            items=len(touched) + found,
        )

    # ----------------------------------------------------------------------------------------- kubernetes

    def _k8s_file(self, display: str, text: str, k8s: _K8s) -> tuple[str | None, int]:
        docs, failed = _yaml_documents(text)
        found = 0
        for doc_node, doc in docs:
            if not isinstance(doc, Mapping):
                continue
            items = doc.get("items")
            if doc.get("kind") == "List" and isinstance(items, list):
                for i, item in enumerate(items):
                    found += self._k8s_object(display, item, _child(doc_node, "items", i), k8s)
            else:
                found += self._k8s_object(display, doc, doc_node, k8s)
        if failed:
            return ("unsupported-source" if "{{" in text else "parse-error"), found
        return None, found

    @staticmethod
    def _k8s_object(display: str, obj: object, node: yaml.Node | None, k8s: _K8s) -> int:
        if not isinstance(obj, Mapping) or not isinstance(obj.get("kind"), str):
            return 0
        kind = str(obj["kind"])
        meta = obj.get("metadata")
        meta = meta if isinstance(meta, Mapping) else {}
        name = str(meta.get("name") or "")
        namespace = meta.get("namespace")
        implicit = not isinstance(namespace, str) or not namespace
        ns = "default" if implicit else str(namespace)
        if kind == "ServiceAccount" and name:
            sa = _ServiceAccount(
                name=name,
                namespace=ns,
                implicit_namespace=implicit,
                locator=f"{display}:{_line(node, 'metadata', 'name')}",
                automount=obj.get("automountServiceAccountToken"),
            )
            annotations = meta.get("annotations")
            annotations = annotations if isinstance(annotations, Mapping) else {}
            tenant = annotations.get(_AZURE_TENANT_ANNOTATION)
            for key, cloud in SA_ANNOTATIONS.items():
                value = annotations.get(key)
                if isinstance(value, str) and value.strip():
                    line = _line(node, "metadata", "annotations", key)
                    sa.clouds.append(
                        (
                            cloud,
                            value.strip(),
                            f"{display}:{line}",
                            tenant if isinstance(tenant, str) else None,
                        )
                    )
            existing = k8s.service_accounts.setdefault((ns, name), sa)
            if existing is not sa:  # a second definition (overlay/patch) adds to the first
                existing.clouds.extend(c for c in sa.clouds if c not in existing.clouds)
                if not isinstance(existing.automount, bool):
                    existing.automount = sa.automount
            return 1 + len(sa.clouds)
        pod_path = WORKLOAD_POD_SPEC.get(kind)
        if pod_path is None or not name:
            return 0
        pod = _dig(obj, pod_path)
        pod = pod if isinstance(pod, Mapping) else {}
        sa_name = pod.get("serviceAccountName") or pod.get("serviceAccount") or "default"
        template_meta = _dig(obj, (*pod_path[:-1], "metadata")) if kind != "Pod" else None
        metadata = [meta] + ([template_meta] if isinstance(template_meta, Mapping) else [])
        sa_key = "serviceAccountName" if "serviceAccountName" in pod else "serviceAccount"
        k8s.workloads.append(
            _Workload(
                kind=kind,
                name=name,
                namespace=ns,
                implicit_namespace=implicit,
                service_account=str(sa_name),
                locator=f"{display}:{_line(node, *pod_path, sa_key)}",
                marker=agent_marker(name, metadata),
                automount=pod.get("automountServiceAccountToken"),
            )
        )
        return 1

    def _resolve_k8s(self, ctx: CollectContext, ledger: _Ledger, k8s: _K8s) -> None:
        clouds_by_sa: dict[tuple[str, str], list[tuple[str, str]]] = {}
        for (ns, name), sa in k8s.service_accounts.items():
            sa_ref = _sa_ref(ns, name)
            tags = {"namespace:implicit"} if sa.implicit_namespace else set()
            if isinstance(sa.automount, bool):
                tags.add(f"automount-token:{str(sa.automount).lower()}")
            ledger.identity(
                IdentityKind.K8S_SA,
                "k8s-sa",
                sa_ref,
                locator=sa.locator,
                name=f"{ns}/{name}",
                tags=tags,
                key=(ns, name),
            )
            for cloud, ref, loc, tenant in sa.clouds:
                cloud_id = ledger.identity(
                    cloud.kind,
                    cloud.prefix,
                    ref,
                    locator=loc,
                    tags={f"bound-k8s-sa:{sa_ref}", f"federation:{cloud.mechanism}"},
                    tenant=tenant,
                )
                if cloud_id:
                    clouds_by_sa.setdefault((ns, name), []).append((cloud_id, cloud.mechanism))
        for wl in k8s.workloads:
            sa_ref = _sa_ref(wl.namespace, wl.service_account)
            tags = {f"workload:{wl.kind}/{wl.name}"}
            if wl.implicit_namespace:
                tags.add("namespace:implicit")
            if isinstance(wl.automount, bool):
                tags.add(f"automount-token:{str(wl.automount).lower()}@{wl.kind}/{wl.name}")
            if wl.marker:
                tags.add(f"agent-workload:{wl.kind}/{wl.name}")
            sa_id = ledger.identity(
                IdentityKind.K8S_SA,
                "k8s-sa",
                sa_ref,
                locator=wl.locator,
                name=f"{wl.namespace}/{wl.service_account}",
                tags=tags,
                key=(wl.namespace, wl.service_account),
            )
            if not wl.marker or sa_id is None:
                continue
            qualifiers = {
                "workload": f"{wl.kind}/{wl.namespace}/{wl.name}",
                "marker": wl.marker,
                "method": "heuristic",
            }
            ledger.edge(EdgeType.ACTS_AS, ctx.agent_id, sa_id, qualifiers=qualifiers, declared_by=wl.locator)
            for cloud_id, mechanism in clouds_by_sa.get((wl.namespace, wl.service_account), []):
                ledger.edge(
                    EdgeType.ACTS_AS,
                    ctx.agent_id,
                    cloud_id,
                    qualifiers={**qualifiers, "via": sa_ref, "mechanism": mechanism},
                    declared_by=wl.locator,
                )

    # ----------------------------------------------------------------------------------------- github actions

    def _workflow(self, display: str, text: str, ledger: _Ledger, touched: set[str]) -> str | None:
        docs, failed = _yaml_documents(text)
        if failed:
            return "parse-error"
        if not docs or not isinstance(docs[0][1], Mapping):
            return None
        node, data = docs[0]
        scope = _WorkflowScope(display=display, data=data, node=node, events=workflow_events(data))
        jobs = data.get("jobs")
        for job_id, job in jobs.items() if isinstance(jobs, Mapping) else []:
            if isinstance(job, Mapping):
                touched.update(self._job(scope, str(job_id), job, ledger))
        return None

    def _job(self, wf: _WorkflowScope, job_id: str, job: Mapping[Any, Any], ledger: _Ledger) -> set[str]:
        job_node = _child(wf.node, "jobs", job_id)
        job_line = _line(wf.node, "jobs", job_id)
        job_loc = f"{wf.display}:{job_line}"
        job_ref = f"github-actions:{wf.display}#{job_id}"
        tags = {f"trigger:{e}" for e in wf.events}
        tags.update(f"untrusted-trigger:{e}" for e in wf.events if e in UNTRUSTED_TRIGGERS)
        granted, origin = effective_permissions(wf.data, job)
        if origin in ("default", "unrecognized"):
            tags.add(f"permissions:{origin}")
        elif not granted:
            tags.add("permissions:none")
        tags.update(f"permission:{g}" for g in granted or [])
        tags.update(self._step_tags(job))
        refs: dict[str, int] = {}
        inline = 0
        env_node = _child(wf.node, "env")
        for key, scalar in [*_scalars(env_node), *_scalars(job_node)]:
            for secret in secret_names(scalar.value, expression=key == "if"):
                refs.setdefault(secret, scalar.start_mark.line + 1)
            if looks_like_secret(scalar.value):
                inline += 1
                mark = scalar.start_mark
                ledger.withheld.add(f"{wf.display}:{mark.line + 1}:{mark.column + 1}")
            for hit in reference_hits(scalar.value):
                ledger.identity(
                    hit.kind,
                    hit.prefix,
                    hit.ref,
                    locator=f"{wf.display}:{scalar.start_mark.line + 1}",
                    tags={f"referenced-by:{job_ref}"},
                    key=hit.key,
                )
        if inline:
            tags.add("inline-secret-literal")
        job_id_ref = ledger.identity(
            IdentityKind.GITHUB_APP,
            "github-actions",
            job_ref,
            locator=job_loc,
            name=f"{wf.display}#{job_id}",
            tags=tags,
            key=(wf.display, job_id),
        )
        if job_id_ref is None:  # pragma: no cover - a job reference is never credential-shaped
            return set()
        perm_path: tuple[str, ...] = ("jobs", job_id, "permissions") if origin == "job" else ("permissions",)
        perm_loc = f"{wf.display}:{_line(wf.node, *perm_path)}" if origin in ("job", "workflow") else job_loc
        scopes: Claim[list[str]] = (
            Claim.declared(granted, locator=perm_loc, collector=ledger.collector_ref, observed_at=ledger.now)
            if granted is not None
            else Claim.unknown(UnknownReason.NOT_COLLECTED, locator=perm_loc, collector=ledger.collector_ref)
        )
        # bindings inherit the job identity's (collision-resolved) id: Triage and triage never share them
        token_id = f"cred:{job_id_ref.split(':', 1)[1]}/github-token"
        ledger.binding(
            CredentialBinding(
                id=token_id,
                name=f"{job_id} GITHUB_TOKEN",
                provenance=ledger.provenance(perm_loc),
                subject_ref=job_id_ref,
                identity_ref=job_id_ref,
                credential_kind=CredentialKind.EPHEMERAL_TASK_SCOPED,
                scopes_granted=scopes,
                storage=CredentialStorage(
                    kind=CredentialStorageKind.SECRET_MANAGER, locator="github-actions:GITHUB_TOKEN"
                ),
            )
        )
        ledger.edge(
            EdgeType.HOLDS_CREDENTIAL,
            job_id_ref,
            token_id,
            qualifiers={"kind": CredentialKind.EPHEMERAL_TASK_SCOPED.value},
            declared_by=perm_loc,
        )
        touched = {job_id_ref}
        for secret, line in sorted(refs.items()):
            secret_loc = f"{wf.display}:{line}"
            secret_id = ledger.identity(
                IdentityKind.API_KEY_REF,
                "github-secret",
                f"github-secret:{secret}",
                locator=secret_loc,
                name=secret,
                key=(secret,),
            )
            # names matching [A-Za-z_][A-Za-z0-9_]* are never credential-shaped, so this is defensive only
            if secret_id is None:  # pragma: no cover
                continue
            touched.add(secret_id)
            cred_id = f"cred:{job_id_ref.split(':', 1)[1]}/secret/{slugify(secret)}"
            ledger.binding(
                CredentialBinding(
                    id=cred_id,
                    name=f"{job_id} secret {secret}",
                    provenance=ledger.provenance(secret_loc),
                    subject_ref=job_id_ref,
                    identity_ref=secret_id,
                    credential_kind=CredentialKind.STATIC_LONG_LIVED,
                    storage=CredentialStorage(
                        kind=CredentialStorageKind.SECRET_MANAGER, locator=f"github-secrets:{secret}"
                    ),
                )
            )
            ledger.edge(
                EdgeType.HOLDS_CREDENTIAL,
                job_id_ref,
                cred_id,
                qualifiers={"kind": CredentialKind.STATIC_LONG_LIVED.value},
                declared_by=secret_loc,
            )
        return touched

    @staticmethod
    def _step_tags(job: Mapping[Any, Any]) -> set[str]:
        """Tags from the job's steps and job-level keys: AI agents, caches, checkouts, runners, reuse."""
        tags: set[str] = set()
        steps = job.get("steps")
        for step in steps if isinstance(steps, list) else []:
            if not isinstance(step, Mapping):
                continue
            uses = step.get("uses")
            if isinstance(uses, str) and uses.strip():
                action = action_name(uses)
                if is_ai_agent_action(uses):
                    tags.add(f"ai-agent-action:{action}")
                    tags.update(_agent_input_tags(step.get("with")))
                if _uses_cache(action, step.get("with")):
                    tags.add(f"cache:{action}")
                ref = _dig(step, ("with", "ref"))
                if action == "actions/checkout" and isinstance(ref, str) and _UNTRUSTED_REF.search(ref):
                    tags.add("checkout:untrusted-ref")
            run = step.get("run")
            if isinstance(run, str):
                clis = [tool for tool, pattern in _AI_AGENT_CLIS if pattern.search(run[:_MAX_SCANNED])]
                tags.update(f"ai-agent-cli:{tool}" for tool in clis)
                if clis:  # an agent is invoked here: what reaches it, and with which approvals
                    tags.update(f"prompt-interpolates:{e}" for e in untrusted_expressions(run))
                    tags.update(f"agent-cli-bypass:{f}" for f in bypass_flags(run))
        called = job.get("uses")
        if isinstance(called, str) and called.strip():
            tags.add(f"calls-workflow:{called.strip().split('@', 1)[0]}")
            if is_ai_agent_action(called):
                tags.add(f"ai-agent-action:{action_name(called)}")
        if job.get("secrets") == "inherit":
            tags.add("secrets:inherit")
        if _all_secrets_used(job):
            tags.add(
                "secrets:all"
            )  # toJSON(secrets) or secrets[<expr>]: every repository secret is reachable
        runs_on = job.get("runs-on")
        labels = as_str_list(runs_on.get("labels")) if isinstance(runs_on, Mapping) else as_str_list(runs_on)
        if any(label.strip().lower() == "self-hosted" for label in labels):
            tags.add("runner:self-hosted")
        environment = job.get("environment")
        env_name = environment.get("name") if isinstance(environment, Mapping) else environment
        if isinstance(env_name, str) and env_name.strip():
            tags.add(f"environment:{env_name.strip()}")
        return tags
