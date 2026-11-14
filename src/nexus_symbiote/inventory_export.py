"""Export a reviewed repository agent as an approved inventory Nexus-ShadowScan accepts.

ShadowScan calls a finding shadow when no entry of its approved inventory binds the finding's
resource, and it refuses the native inventory as an approved inventory. This module writes
ShadowScan's documented simple list, ``{"agents": [...]}``, following ShadowScan commit
``SHADOWSCAN_COMMIT``. The list holds one entry, the inventory's repository agent: its ``id`` is
the agent's reference, which ``agent.yaml``'s declared ``id`` determines, and an agent whose
identity was inferred is exported only on request, under an id derived from the inventory's
content digest. The entry binds one resource, the operator-supplied label under which
ShadowScan's code connectors report the repository, escaped to match only that exact string and
limited to the ``project`` observation on the ``code`` surface: the finding those connectors
report for the repository's project, not the coding-agent configurations they report under the
same resource.

The export establishes that the file names the agent the inventory records. It does not
authenticate the inventory or its producer, check that the label names the reviewed repository,
carry an autonomy level (the two tools' scales differ), or bind the agent's components. ShadowScan
approves a location, not its content: a later change under the bound resource is still approved,
so content changes are caught by ``diff`` against the reviewed baseline, not by this file.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from nexus_symbiote.core.aibom import (
    AIBOM,
    NativeFormatError,
    parse_native_bytes,
    read_native_bytes,
)
from nexus_symbiote.core.content_digest import NESTED_TOO_DEEPLY, inventory_content_digest
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import AgentComponent
from nexus_symbiote.generators._common import imported_discovery_component
from nexus_symbiote.graph import INFERRED_AGENT_REF, MANIFEST
from nexus_symbiote.utils.terminal import UNSAFE_TEXT

SHADOWSCAN_COMMIT = "999bef1a277cfbcdc44fdbca925e54c07efa278d"
"""The ShadowScan commit (release 0.1.4) whose inventory reader and code connectors this follows."""
AGENT_OBSERVATION = "project"
"""The ``identity_discriminator`` of the finding ShadowScan's code connectors report for a project."""
CODE_SURFACE = "code"
MAX_TEXT_CHARS = 4096
UNNAMED_AGENT_PREFIX = "agent:unnamed:"
_UNNAMED_HINT = (
    "pass --include-unnamed to export the agent under an id derived from the inventory content "
    "digest."
)
UNDECLARED_IDENTITY = (
    "The repository agent's identity is not declared. Declare `id` (and `name`) in agent.yaml "
    "and scan again, or " + _UNNAMED_HINT
)
LEGACY_IDENTITY = (
    "The inventory is native format 1.0, whose agent reference does not show whether agent.yaml "
    "declared an id. Scan the repository again with this release, or " + _UNNAMED_HINT
)

_REPOSITORY_AGENT_REF = re.compile(r"agent:repository:[0-9a-f]{24}")
_GLOB_LITERALS = str.maketrans({"*": "[*]", "?": "[?]", "[": "[[]"})
_UNENCODABLE = re.compile(r"[\ud800-\udfff]")
_REDACTED = "[REDACTED]"
_NOT_STRICT_JSON = "It is not strict UTF-8 JSON; duplicate keys and nonfinite numbers are refused."
# Before native format 1.1, an agent without a declared id had a reference derived from the
# checkout path, so only from 1.1 on does a reference other than the inferred one show an id.
_DECLARED_REFERENCES_SINCE = (1, 1)


class InventoryExportError(ValueError):
    """The inventory or an option cannot be exported; the message never quotes inventory text."""


@dataclass(frozen=True)
class NativeInventory:
    """A native inventory read once: the model, the file's SHA-256 and the content digest."""

    bom: AIBOM
    file_sha256: str
    content_digest: str


@dataclass(frozen=True)
class SimpleEntry:
    """One simple-list entry. Its field names are the only keys the export can write."""

    id: str
    resources: tuple[str, ...]
    surfaces: tuple[str, ...]
    discriminators: tuple[str, ...]
    name: str | None = None
    owner: str | None = None
    names: tuple[str, ...] = ()

    def as_json(self) -> dict[str, Any]:
        """The entry as JSON values, without the optional fields it leaves unset."""
        values = {item.name: getattr(self, item.name) for item in fields(self)}
        return {
            key: list(value) if isinstance(value, tuple) else value
            for key, value in values.items()
            if value is not None and value != ()
        }


@dataclass(frozen=True)
class InventoryExport:
    """The exported entry, its rendered file text and what the export left out."""

    entry: SimpleEntry
    declared: bool
    other_agents: int
    text: str


def literal_resource_pattern(resource: str) -> str:
    """A ShadowScan resource pattern that matches exactly ``resource``.

    ShadowScan matches patterns with case-sensitive ``fnmatch``. Like its own
    ``literal_resource_pattern``, this puts ``*``, ``?`` and ``[`` in one-character classes;
    ``]`` outside a class is already literal.
    """
    return resource.translate(_GLOB_LITERALS)


def checked_text(label: str, value: str) -> str:
    """``value`` unchanged when ShadowScan reads it back exactly, else a refusal naming ``label``."""
    if not value:
        raise InventoryExportError(f"The {label} is empty; ShadowScan requires a nonempty value.")
    if len(value) > MAX_TEXT_CHARS:
        raise InventoryExportError(f"The {label} is longer than {MAX_TEXT_CHARS:,} characters.")
    if UNSAFE_TEXT.search(value) or "\t" in value or _UNENCODABLE.search(value):
        raise InventoryExportError(
            f"The {label} contains a control, format, line-separator or unencodable character, "
            "which ShadowScan would reject or misread."
        )
    if value != value.strip():
        raise InventoryExportError(
            f"The {label} starts or ends with white space, which ShadowScan removes when it loads "
            "the file."
        )
    return value


def checked_resource_prefix(value: str) -> str:
    """The operator's label for the repository, refused when no ShadowScan finding can carry it."""
    checked_text("resource prefix", value)
    if _REDACTED in value:
        raise InventoryExportError(
            f"The resource prefix contains {_REDACTED}; ShadowScan approves no resource that does."
        )
    return value


def read_native_inventory(path: Path) -> NativeInventory:
    """Read, digest and validate a native inventory from a single bounded read of the file.

    The read, parse and schema checks are ``AIBOM.load``'s own, and every failure is a
    ``NativeFormatError``. One read keeps the printed digests bound to the bytes the export
    comes from. A document without a ``components`` list has no content digest and is
    refused.
    """
    raw = read_native_bytes(path)
    document = parse_native_bytes(raw)
    bom = AIBOM.from_native(document)
    try:
        digest = inventory_content_digest(document)
    except ValueError as exc:
        if exc.args == (NESTED_TOO_DEEPLY,):
            # The parse refuses nesting beyond MAX_NATIVE_NESTING, well within what the
            # digest canonicalizes; should that change, nesting is still refused here.
            raise NativeFormatError(_NOT_STRICT_JSON) from exc
        # The schema check accepts a missing components list, and nothing else that is
        # valid lacks a content digest.
        raise NativeFormatError("It has no components list, so it has no content digest.") from exc
    return NativeInventory(bom=bom, file_sha256=hash_bytes(raw), content_digest=digest)


def shadowscan_simple_inventory(
    inventory: NativeInventory, *, resource_prefix: str, include_unnamed: bool = False
) -> InventoryExport:
    """The repository agent as a ShadowScan simple list, or a refusal that names the reason."""
    agents = [c for c in inventory.bom.components if isinstance(c, AgentComponent)]
    repository = [
        agent
        for agent in agents
        if _REPOSITORY_AGENT_REF.fullmatch(agent.bom_ref)
        and not imported_discovery_component(agent)
    ]
    if not repository:
        raise InventoryExportError(
            "The inventory records no repository agent; export an inventory that "
            "`nexus-symbiote scan` wrote."
        )
    if len(repository) > 1:
        raise InventoryExportError(
            "The inventory records more than one repository agent; their bindings would be "
            "identical, and ShadowScan approves nothing that two entries bind."
        )
    [agent] = repository
    major, minor = (int(part) for part in inventory.bom.metadata.spec_version.split(".")[:2])
    current = (major, minor) >= _DECLARED_REFERENCES_SINCE
    manifest = agent.properties.get("identity_source") == MANIFEST
    declared = current and manifest and agent.bom_ref != INFERRED_AGENT_REF
    if not declared and not include_unnamed:
        raise InventoryExportError(UNDECLARED_IDENTITY if current else LEGACY_IDENTITY)
    names: tuple[str, ...] = ()
    if declared:
        identity = agent.bom_ref
    else:
        digest = inventory.content_digest
        identity = UNNAMED_AGENT_PREFIX + digest.removeprefix("sha256:")[:24]
        names = (f"unnamed repository agent; id from inventory content digest {digest}",)
    entry = SimpleEntry(
        id=identity,
        name=checked_text("agent name", agent.name) if manifest else None,
        owner=checked_text("agent owner", agent.supplier)
        if manifest and agent.supplier is not None
        else None,
        names=names,
        resources=(literal_resource_pattern(checked_resource_prefix(resource_prefix)),),
        surfaces=(CODE_SURFACE,),
        discriminators=(AGENT_OBSERVATION,),
    )
    text = json.dumps({"agents": [entry.as_json()]}, indent=2, sort_keys=True, ensure_ascii=False)
    return InventoryExport(
        entry=entry, declared=declared, other_agents=len(agents) - 1, text=text + "\n"
    )
