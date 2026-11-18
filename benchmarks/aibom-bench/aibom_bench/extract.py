"""Turn each tool's output files into inventory records and findings.

The same extraction runs for every tool. CycloneDX, SPDX and SARIF are read by their
structure; any other JSON is read generically, one record per object, so no tool gets a
hand-written parser.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MACHINE_FORMATS = {"cyclonedx-json", "spdx-json", "sarif", "native-json"}
TEXT_FORMATS = {"text", "markdown", "html", "csv"}
TYPE_KEY = re.compile(
    r"type|kind|category|class|purpose|ecosystem|role|scanner|collector|detector", re.I
)
NAME_KEYS = {"name", "id", "package", "package_name", "component", "title", "library", "module"}
FILE_CONTAINERS = {"files", "locations", "occurrences", "paths", "evidence", "sources", "layers"}
FILE_TYPES = re.compile(
    r"^(software_)?(file|files|blob|directory|regularfile|text|document)$", re.I
)
SEVERITY_KEY = re.compile(r"severity|risk_?level|^level$|priority|criticality", re.I)
MESSAGE_KEY = re.compile(
    r"message|description|title|detail|reason|summary|rule|category|check|finding|issue|^name$",
    re.I,
)
FINDING_MAX_CHARS = 6000
BAG_MAX_CHARS = 20000
MAX_VALUE_CHARS = 400
MAX_LIST_ITEMS = 40
MAX_NESTED_ITEMS = 200
BOM_REF_PREFIX = re.compile(r"^([A-Za-z][A-Za-z0-9_-]{1,30}):")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
VOLATILE_KEY = re.compile(
    r"time|date|created|duration|elapsed|serial|uuid|scan_?id|run_?id|generated|namespace|invocation"
    r"|_at$|_seen$",
    re.I,
)


@dataclass(frozen=True)
class Record:
    own: str
    names: frozenset[str]
    full: str
    type_evidence: str
    is_file: bool
    source: str
    ref: str = ""
    cdx_type: str = ""
    identity: str = ""
    described: str = ""


@dataclass(frozen=True)
class Finding:
    text: str
    source: str


@dataclass
class Output:
    label: str
    format: str
    path: Path
    raw: bytes
    doc: Any = None

    @property
    def text(self) -> str:
        return self.raw.decode("utf-8", errors="replace")


def load_outputs(run: dict[str, Any], out_dir: Path) -> list[Output]:
    """Every declared output of a run, plus each scan's stdout and stderr as text."""
    outputs = []
    for scan in run.get("scans", []):
        for entry in scan["outputs"]:
            # Recorded paths are absolute; a moved or published work directory still scores.
            path = out_dir / Path(entry["path"]).name
            if not path.is_file():
                continue
            output = Output(scan["label"], entry["format"], path, path.read_bytes())
            if output.format in MACHINE_FORMATS:
                try:
                    output.doc = json.loads(output.raw)
                except ValueError:
                    output.doc = _json_lines(output.text)
            outputs.append(output)
        for stream in ("stdout", "stderr"):
            path = out_dir / f"{scan['label']}.{stream}"
            declared = any(Path(entry["path"]).name == path.name for entry in scan["outputs"])
            if path.is_file() and not declared:
                outputs.append(Output(scan["label"], f"console-{stream}", path, path.read_bytes()))
    return outputs


def _json_lines(text: str) -> Any:
    """Recover JSON a tool printed after log lines, or as one object per line."""
    start = min((i for i in (text.find("{"), text.find("[")) if i >= 0), default=-1)
    if start >= 0:
        try:
            return json.loads(text[start:])
        except ValueError:
            pass
    rows = []
    for line in text.splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows or None


def _scalars(node: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """A record's short scalar fields.

    A long string or a long list is bulk content, such as a file's text or every token in
    it. Content a tool copied is not something the tool said about the component, so it is
    left out of what a record is matched on. It stays in the record's full text.
    """
    for key, value in node.items():
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            if len(str(value)) <= MAX_VALUE_CHARS:
                yield key, str(value)
        elif isinstance(value, list) and len(value) <= MAX_LIST_ITEMS:
            for element in value:
                if isinstance(element, (str, int, float)) and not isinstance(element, bool):
                    if len(str(element)) <= MAX_VALUE_CHARS:
                        yield key, str(element)


def _described(node: Any) -> str:
    """The short fields of an object and of everything nested in it, as one text."""
    parts: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            parts.extend(f"{key}: {text}" for key, text in _scalars(value))
            for child in value.values():
                if isinstance(child, (dict, list)):
                    walk(child)
        elif isinstance(value, list) and len(value) <= MAX_NESTED_ITEMS:
            for child in value:
                if isinstance(child, (dict, list)):
                    walk(child)

    walk(node)
    return " ".join(parts).lower()


def _dump(node: Any) -> str:
    return json.dumps(node, ensure_ascii=False, sort_keys=True).lower()


def _cyclonedx(doc: dict[str, Any], source: str) -> Iterator[Record]:
    stack = [*doc.get("components", []), *doc.get("services", [])]
    for formulation in doc.get("formulation", []) or []:
        stack += [*formulation.get("components", []), *formulation.get("services", [])]
    while stack:
        component = stack.pop()
        if not isinstance(component, dict):
            continue
        stack += [*component.get("components", []), *component.get("services", [])]
        own = {k: v for k, v in component.items() if k not in {"components", "services"}}
        properties = [p for p in own.get("properties", []) or [] if isinstance(p, dict)]
        # Type evidence is what the record says it is: its type, a kind prefix on its
        # reference, and properties named as a type. Names, paths and property names in
        # general are not evidence; a path that contains "mcp" does not make a file a server.
        prefix = BOM_REF_PREFIX.match(str(own.get("bom-ref", "")))
        evidence = [str(own.get("type", "")), prefix[1] if prefix else ""]
        evidence += [
            str(p.get("value", "")) for p in properties if TYPE_KEY.search(str(p.get("name", "")))
        ]
        evidence += [
            str(d.get("type", "")) for d in own.get("data", []) or [] if isinstance(d, dict)
        ]
        if own.get("modelCard"):
            evidence.append("machine-learning-model")
        purl = str(own.get("purl", ""))
        if purl:
            evidence.append(purl.split("/", 1)[0])
        if "endpoints" in own or "authenticated" in own:
            evidence.append("service")
        yield Record(
            own=_described(own),
            names=frozenset({str(own.get("name", "")).lower(), purl.lower()} - {""}),
            full=_dump(component),
            type_evidence=" ".join(evidence).lower(),
            is_file=own.get("type") == "file",
            source=source,
            ref=str(own.get("bom-ref", "")),
            cdx_type=str(own.get("type", "")),
            identity=" ".join(
                [str(own.get("name", "")), str(own.get("bom-ref", "")), purl]
            ).lower(),
            described=_described(component),
        )


def _spdx(doc: dict[str, Any], source: str) -> Iterator[Record]:
    elements = doc.get("@graph")
    if isinstance(elements, list):
        for element in elements:
            if not isinstance(element, dict):
                continue
            kind = str(element.get("type", element.get("@type", "")))
            evidence = [kind, str(element.get("software_primaryPurpose", ""))]
            evidence += [
                key.split("_", 1)[0] for key in element if key.startswith(("ai_", "dataset_"))
            ]
            evidence += [
                str(identifier.get("identifier", "")).split("/", 1)[0]
                for identifier in element.get("externalIdentifier", []) or []
                if isinstance(identifier, dict)
            ]
            yield Record(
                own=_described(element),
                names=frozenset({str(element.get("name", "")).lower()} - {""}),
                full=_dump(element),
                type_evidence=" ".join(evidence).lower(),
                is_file=kind == "software_File" and not element.get("software_primaryPurpose"),
                source=source,
                ref=str(element.get("spdxId", "")),
                identity=f"{element.get('name', '')} {element.get('spdxId', '')}".lower(),
                described=_described(element),
            )
        return
    for package in doc.get("packages", []) or []:
        evidence = ["package", str(package.get("primaryPackagePurpose", ""))]
        evidence += [
            str(ref.get("referenceLocator", "")).split("/", 1)[0]
            for ref in package.get("externalRefs", []) or []
        ]
        yield Record(
            own=_described(package),
            names=frozenset({str(package.get("name", "")).lower()} - {""}),
            full=_dump(package),
            type_evidence=" ".join(evidence).lower(),
            is_file=False,
            source=source,
            ref=str(package.get("SPDXID", "")),
        )
    for entry in doc.get("files", []) or []:
        yield Record(_dump(entry), frozenset(), _dump(entry), "file", True, source)


def _is_record(node: Any) -> bool:
    return isinstance(node, dict) and any(key.lower() in NAME_KEYS for key in node)


def _bag(node: dict[str, Any]) -> Iterator[str]:
    """Scalars of a record's property bags: nested objects that name no component.

    Tools differ in how deep they put a component's details. One writes ``args`` beside
    ``name``; another writes ``metadata.args`` or ``evidence.occurrences[].snippet``.
    Folding unnamed sub-objects into the record that owns them credits both alike.
    """
    for value in node.values():
        children = value if isinstance(value, list) else [value]
        for child in children:
            if isinstance(child, dict) and not _is_record(child):
                yield from (text for _, text in _scalars(child))
                yield from _bag(child)


def _native(
    node: Any,
    source: str,
    container: str = "",
    key: str = "",
    listed: bool = False,
    owned: bool = False,
) -> Iterator[Record]:
    """One record per object that names something.

    An object is a record when it has a name-like field, is a value in a map of records,
    or is an unnamed element of a list that no record owns. An unnamed object inside a
    record is that record's property bag. An unnamed object that is a plain field of the
    document, such as a metadata or coverage block, is neither: a list of every path a
    tool read is not a claim about what those paths contain.
    """
    if isinstance(node, list):
        for element in node:
            yield from _native(element, source, container, "", True, owned)
        return
    if not isinstance(node, dict):
        return
    scalars = list(_scalars(node))
    record = (
        bool(scalars)
        and bool(container)
        and (_is_record(node) or bool(key) or (listed and not owned))
    )
    if record:
        types = [value for name, value in scalars if TYPE_KEY.search(name)]
        names = {value.lower() for name, value in scalars if name.lower() in NAME_KEYS}
        if key:
            names.add(key.lower())
        own = " ".join([key, *(f"{name}: {value}" for name, value in scalars)])
        bag = " ".join(_bag(node))[:BAG_MAX_CHARS]
        yield Record(
            own=f"{own} {bag}".lower(),
            names=frozenset(names),
            full=_dump(node) + " " + key.lower(),
            type_evidence=" ".join([container, *types]).lower(),
            is_file=container.lower() in FILE_CONTAINERS
            or any(FILE_TYPES.match(value) for value in types),
            source=source,
            identity=" ".join(sorted(names)),
            described=_described(node) + " " + key.lower(),
        )
    all_dicts = bool(node) and all(isinstance(value, dict) for value in node.values())
    for name, value in node.items():
        if isinstance(value, dict):
            yield from _native(
                value,
                source,
                container if all_dicts else name,
                name if all_dicts else "",
                False,
                owned or record,
            )
        elif isinstance(value, list):
            yield from _native(value, source, name, "", True, owned or record)


def records(outputs: list[Output]) -> list[Record]:
    found: list[Record] = []
    for output in outputs:
        if output.doc is None:
            continue
        source = f"{output.label}:{output.format}"
        if output.format == "cyclonedx-json" and isinstance(output.doc, dict):
            found += _cyclonedx(output.doc, source)
        elif output.format == "spdx-json" and isinstance(output.doc, dict):
            found += _spdx(output.doc, source)
        elif output.format == "native-json":
            if isinstance(output.doc, dict) and output.doc.get("bomFormat") == "CycloneDX":
                found += _cyclonedx(output.doc, source)
            else:
                found += _native(
                    output.doc, source, "items" if isinstance(output.doc, list) else ""
                )
    return found


def links(outputs: list[Output]) -> set[frozenset[str]]:
    """Reference pairs a document links explicitly: CycloneDX dependencies, SPDX relationships."""
    pairs: set[frozenset[str]] = set()
    for output in outputs:
        doc = output.doc
        if not isinstance(doc, dict):
            continue
        for dependency in doc.get("dependencies", []) or []:
            if not isinstance(dependency, dict):
                continue
            for other in [
                *(dependency.get("dependsOn") or []),
                *(dependency.get("provides") or []),
            ]:
                pairs.add(frozenset({str(dependency.get("ref", "")), str(other)}))
        for element in doc.get("@graph", []) or []:
            if isinstance(element, dict) and element.get("type") == "Relationship":
                targets = element.get("to", [])
                for target in targets if isinstance(targets, list) else [targets]:
                    pairs.add(frozenset({str(element.get("from", "")), str(target)}))
    return pairs


def _native_findings(node: Any, source: str, context: str = "") -> Iterator[Finding]:
    """Objects that state a severity and say what it is about, with their parent's name."""
    if isinstance(node, list):
        for element in node:
            yield from _native_findings(element, source, context)
        return
    if not isinstance(node, dict):
        return
    keys = list(node)
    text = _dump(node)
    if (
        any(SEVERITY_KEY.search(key) for key in keys)
        and any(MESSAGE_KEY.search(key) for key in keys)
        and len(text) <= FINDING_MAX_CHARS
    ):
        yield Finding(f"{context} {text}", source)
    names = " ".join(value for name, value in _scalars(node) if name.lower() in NAME_KEYS).lower()
    for value in node.values():
        yield from _native_findings(value, source, names[:300])


def findings(outputs: list[Output]) -> list[Finding]:
    found: list[Finding] = []
    for output in outputs:
        source = f"{output.label}:{output.format}"
        doc = output.doc
        if output.format == "sarif" and isinstance(doc, dict):
            for run in doc.get("runs", []) or []:
                rules = {
                    rule.get("id"): _dump(rule)
                    for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []
                }
                for result in run.get("results", []) or []:
                    found.append(
                        Finding(_dump(result) + " " + rules.get(result.get("ruleId"), ""), source)
                    )
        elif output.format == "cyclonedx-json" and isinstance(doc, dict):
            by_ref = {record.ref: record.own for record in _cyclonedx(doc, source) if record.ref}
            for vulnerability in doc.get("vulnerabilities", []) or []:
                affected = " ".join(
                    by_ref.get(str(affect.get("ref", "")), "")[:4000]
                    for affect in vulnerability.get("affects", []) or []
                )
                found.append(Finding(_dump(vulnerability) + " " + affected, source))
        elif output.format in {"native-json", "spdx-json"} and doc is not None:
            found += _native_findings(doc, source)
        elif output.format in TEXT_FORMATS or output.format.startswith("console-"):
            lines = output.text.lower().splitlines()
            for index, line in enumerate(lines):
                if line.strip():
                    window = " ".join(lines[max(0, index - 2) : index + 3])
                    found.append(Finding(f"{line} \x00 {window}", source))
    return found


def normalized(doc: Any) -> Any:
    """A document with fields that legitimately vary between runs removed."""
    if isinstance(doc, dict):
        return {
            key: normalized(value)
            for key, value in sorted(doc.items())
            if not VOLATILE_KEY.search(key)
        }
    if isinstance(doc, list):
        return [normalized(value) for value in doc]
    if isinstance(doc, str):
        return UUID.sub("<uuid>", doc)
    return doc
