"""Read CycloneDX documents the same way for every tool.

Nothing here knows which tool wrote a document. An *element* is any component,
service, workflow or task, wherever it sits; its text is every string and number it
holds, without the elements nested inside it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote

ELEMENT_LISTS = {
    "components": "component",
    "services": "service",
    "workflows": "workflow",
    "tasks": "task",
}
VOLATILE_TOP = ("serialNumber",)
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
PURL = re.compile(r"^pkg:[A-Za-z][A-Za-z0-9.+\-]*/[^\s@?#]+(@[^\s?#]+)?(\?[^\s#]+)?(#\S+)?$")
LABEL = re.compile(r"[A-Za-z0-9 _:\-]{1,40}")
HEXISH = re.compile(r"[0-9a-fA-F]{16,}")
Signature = tuple[str, str, frozenset[str], frozenset[tuple[str, str]]]


@dataclass
class Element:
    index: int
    kind: str
    type: str
    ref: str
    text: str
    obj: dict[str, Any]
    parent: int | None

    @property
    def signature(self) -> Signature:
        """How the tool rendered this element, without its identity.

        Property names, plus the values that read as labels. Paths, digests and
        numbers are left out, so two files listed the same way share a signature.
        """
        names: set[str] = set()
        labels: set[tuple[str, str]] = set()
        for prop in self.obj.get("properties") or []:
            if not isinstance(prop, dict):
                continue
            name = str(prop.get("name", ""))
            value = prop.get("value")
            names.add(name)
            if (
                isinstance(value, str)
                and LABEL.fullmatch(value)
                and not HEXISH.fullmatch(value)
                and not value.replace(".", "").isdigit()
            ):
                labels.add((name, value))
        return (self.kind, self.type, frozenset(names), frozenset(labels))


def load(path: Path) -> dict[str, Any] | None:
    """Parse a JSON document; ``None`` when it is missing, invalid or not an object."""
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _own_text(node: Any, out: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ELEMENT_LISTS and isinstance(value, list):
                continue
            if key == "component" and isinstance(value, dict):
                continue
            _own_text(value, out)
    elif isinstance(node, list):
        for item in node:
            _own_text(item, out)
    elif isinstance(node, str):
        out.append(node)
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        out.append(str(node))


def elements(bom: dict[str, Any]) -> list[Element]:
    """Every component, service, workflow and task in a document."""
    found: list[Element] = []

    def add(obj: dict[str, Any], kind: str, parent: int | None) -> None:
        parts: list[str] = []
        _own_text(obj, parts)
        index = len(found)
        found.append(
            Element(
                index=index,
                kind=kind,
                type=str(obj.get("type", "")),
                ref=str(obj.get("bom-ref", "")),
                text="\n".join(parts).lower(),
                obj=obj,
                parent=parent,
            )
        )
        walk(obj, index)

    def walk(node: Any, parent: int | None) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ELEMENT_LISTS and isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            add(item, ELEMENT_LISTS[key], parent)
                elif key == "component" and isinstance(value, dict):
                    add(value, "component", parent)
                else:
                    walk(value, parent)
        elif isinstance(node, list):
            for item in node:
                walk(item, parent)

    walk(bom, None)
    return found


def links(bom: dict[str, Any]) -> dict[str, set[str]]:
    """Undirected adjacency between bom-refs from the ``dependencies`` section."""
    graph: dict[str, set[str]] = {}
    for entry in bom.get("dependencies") or []:
        if not isinstance(entry, dict):
            continue
        source = str(entry.get("ref", ""))
        for key in ("dependsOn", "provides"):
            for target in entry.get(key) or []:
                graph.setdefault(source, set()).add(str(target))
                graph.setdefault(str(target), set()).add(source)
    return graph


def normalize_purl(value: str) -> tuple[str, str, str] | None:
    """Type, name with namespace, and version, compared without case or encoding."""
    if not value.lower().startswith("pkg:"):
        return None
    rest = value[4:].split("#", 1)[0].split("?", 1)[0]
    kind, _, remainder = rest.partition("/")
    if not remainder:
        return None
    name, version = remainder, ""
    if "@" in remainder.lstrip("@"):
        name, _, version = remainder.rpartition("@")
    name = unquote(name).strip("/").lower()
    kind = kind.lower()
    if kind == "pypi":
        name = re.sub(r"[-_.]+", "-", name)
    return (kind, name, unquote(version).lower())


def purl_values(obj: Any) -> list[str]:
    """Every string in an element that is, or claims to be, a package URL."""
    values: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in ELEMENT_LISTS:
                continue
            if isinstance(value, str) and (key == "purl" or value.startswith("pkg:")):
                values.append(value)
            else:
                values += purl_values(value)
    elif isinstance(obj, list):
        for item in obj:
            values += purl_values(item)
    return values


def strict_form(bom: dict[str, Any]) -> str:
    """The document without its serial number and timestamp."""
    copy = {key: value for key, value in bom.items() if key not in VOLATILE_TOP}
    metadata = copy.get("metadata")
    if isinstance(metadata, dict):
        copy["metadata"] = {key: value for key, value in metadata.items() if key != "timestamp"}
    return json.dumps(copy, sort_keys=True)


def _semantic(node: Any) -> Any:
    if isinstance(node, dict):
        return {key: _semantic(value) for key, value in sorted(node.items())}
    if isinstance(node, list):
        items = [_semantic(item) for item in node]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(node, str):
        return TIMESTAMP.sub("<time>", UUID.sub("<uuid>", node))
    return node


def semantic_form(bom: dict[str, Any]) -> str:
    """The strict form with identifiers, times and list order removed."""
    return json.dumps(_semantic(json.loads(strict_form(bom))), sort_keys=True)


def bounded_nodes(node: Any, limit: int = 4000) -> list[str]:
    """Lower-cased text of every JSON object that serializes within ``limit`` characters."""
    texts: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            encoded = json.dumps(value, ensure_ascii=False)
            if len(encoded) <= limit:
                texts.append(encoded.lower())
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(node)
    return texts
