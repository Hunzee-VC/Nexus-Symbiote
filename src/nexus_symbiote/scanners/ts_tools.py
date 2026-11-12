"""Bounded static MCP names from lexically bound TypeScript SDK registrations.

This records source declarations, never evaluated tool descriptors or runtime
registration. Dynamic names and unsupported bindings remain
explicit collection gaps. No source module or package code is executed.

The tree-sitter runtime and grammar are native code and parse the file in this
process, bounded by the source size, a native parse timeout, a node limit and an
analysis deadline. They are not isolated in a separate process.
"""

from __future__ import annotations

import codecs
import re
import time
import warnings
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote

if TYPE_CHECKING:
    from tree_sitter import Node, Parser

from nexus_symbiote import limits
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import ClaimEvidence, MCPServerComponent, ToolComponent
from nexus_symbiote.limits import Bound
from nexus_symbiote.scanners.base import ScanResult

_MODULES = {"@modelcontextprotocol/server", "@modelcontextprotocol/sdk/server/mcp.js"}
_IGNORED = {"dist", "build", "__tests__", "tests", "test", "docs", "benchmarks", "examples"}
SERVER_MARKERS = (b"@modelcontextprotocol/", b"McpServer")
# tsc and web browsers decode a source file that starts with a UTF-16 byte order
# mark as UTF-16 (bun only the little-endian form), and any other file as UTF-8.
UTF16_BYTE_ORDER_MARKS = {codecs.BOM_UTF16_LE: "utf-16-le", codecs.BOM_UTF16_BE: "utf-16-be"}
MAX_REGISTRATIONS = 1_000
# Time bounds for the default size limits; they grow in proportion when an
# operator raises syntax-bytes or ts-nodes, so a larger file is not refused for time.
MAX_PARSE_SECONDS = 0.25
MAX_ANALYSIS_SECONDS = 2.0


class _RefusedError(ValueError):
    """The file was not collected; the message names why and quotes no source."""


def is_server_source(path: Path) -> bool:
    """A TypeScript file this collector supports, before its content is known."""
    return (
        path.suffix == ".ts"
        and not _IGNORED.intersection(path.parts)
        and not path.name.endswith((".d.ts", ".spec.ts", ".test.ts"))
    )


def source_text(content: bytes) -> str:
    """The text tsc reads from one complete source file; a ValueError says why there is none."""
    encoding = UTF16_BYTE_ORDER_MARKS.get(content[:2])
    try:
        return content.decode("utf-8") if encoding is None else content[2:].decode(encoding)
    except UnicodeDecodeError:
        raise _RefusedError("invalid UTF-8" if encoding is None else "invalid UTF-16") from None


def _value(node: Node | None) -> str:
    return ((node.text or b"") if node is not None else b"").decode("utf-8")


def _nodes(root: Node, limit: Bound) -> Iterator[Node]:
    pending = [root]
    count = 0
    while pending:
        node = pending.pop()
        count += 1
        if count > limit.value:
            raise _RefusedError(limit.exceeded())
        yield node
        pending.extend(reversed(node.named_children))


_FUNCTIONS = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
}
_SCOPES = {"program", "statement_block", "catch_clause", *_FUNCTIONS}


@dataclass
class _Index:
    """Every named node once, with its parent and enclosing scope.

    tree-sitter finds a node's parent by descending from the root, so climbing
    ``Node.parent`` costs the depth at every step. Recording both relations in one
    traversal keeps the analysis linear in the number of nodes.
    """

    nodes: list[Node]
    parents: dict[int, Node]
    scopes: dict[int, Node]
    deadline: float

    def parent(self, node: Node | None) -> Node | None:
        return None if node is None else self.parents.get(node.id)

    def scope(self, node: Node | None) -> Node | None:
        """The nearest scope that is ``node`` itself or encloses it."""
        return None if node is None else self.scopes.get(node.id)

    def check_deadline(self) -> None:
        if time.monotonic() >= self.deadline:
            raise _RefusedError("TypeScript analysis exceeded its time limit")


def _index(root: Node, limit: Bound, deadline: float) -> _Index:
    index = _Index([], {}, {}, deadline)
    pending: list[tuple[Node, Node | None]] = [(root, None)]
    while pending:
        node, parent = pending.pop()
        if len(index.nodes) >= limit.value:
            raise _RefusedError(limit.exceeded())
        if not len(index.nodes) % 1024:
            index.check_deadline()
        index.nodes.append(node)
        if parent is not None:
            index.parents[node.id] = parent
        if parent is None or node.type in _SCOPES:
            index.scopes[node.id] = node
        else:
            index.scopes[node.id] = index.scopes[parent.id]
        pending.extend((child, node) for child in reversed(node.named_children))
    return index


def _pattern_names(node: Node | None) -> list[str]:
    """Names a declaration pattern binds; default values and types declare nothing."""
    names: list[str] = []
    pending = [] if node is None else [node]
    while pending:
        current = pending.pop()
        kind = current.type
        if kind in {"identifier", "shorthand_property_identifier_pattern"}:
            names.append(_value(current))
            continue
        children: list[Node | None]
        if kind in {"object_pattern", "array_pattern", "rest_pattern", "formal_parameters"}:
            children = list(reversed(current.named_children))
        elif kind == "pair_pattern":
            children = [current.child_by_field_name("value")]
        elif kind in {"assignment_pattern", "object_assignment_pattern"}:
            children = [current.child_by_field_name("left")]
        elif kind in {"required_parameter", "optional_parameter"}:
            children = [current.child_by_field_name("pattern")]
        else:
            continue
        pending.extend(child for child in children if child is not None)
    return names


def _bindings(index: _Index, root: Node) -> dict[tuple[int, str], object]:
    bindings: dict[tuple[int, str], object] = {}

    def bind(scope: Node | None, name: str, value: object) -> None:
        if scope is not None and name:
            key = (scope.id, name)
            bindings[key] = "ambiguous" if key in bindings else value

    for position, node in enumerate(index.nodes):
        if not position % 1024:
            index.check_deadline()
        parent = index.parent(node)
        if node.type == "import_statement" and parent is not None and parent.id == root.id:
            sdk = _value(node.child_by_field_name("source"))[1:-1] in _MODULES and not any(
                child.type == "type" for child in node.children
            )
            for spec in _nodes(node, limits.bound("ts-nodes")):
                if spec.type == "import_specifier":
                    name = spec.child_by_field_name("name")
                    bind(
                        root,
                        _value(spec.child_by_field_name("alias") or name),
                        "sdk"
                        if sdk
                        and _value(name) == "McpServer"
                        and not any(child.type == "type" for child in spec.children)
                        else "other",
                    )
                elif spec.type in {"namespace_import", "import_clause"}:
                    for child in spec.named_children:
                        if child.type == "identifier":
                            bind(root, _value(child), "other")
        elif node.type == "variable_declarator":
            for declared_name in _pattern_names(node.child_by_field_name("name")):
                bind(index.scope(parent), declared_name, node.id)
        elif node.type in _FUNCTIONS:
            name = node.child_by_field_name("name")
            if name is not None:
                bind(
                    index.scope(parent) if "declaration" in node.type else node,
                    _value(name),
                    "other",
                )
            parameters = node.child_by_field_name("parameters") or node.child_by_field_name(
                "parameter"
            )
            for parameter in _pattern_names(parameters):
                bind(node, parameter, "other")
        elif node.type in {"class_declaration", "enum_declaration"}:
            bind(index.scope(parent), _value(node.child_by_field_name("name")), "other")
        elif node.type == "catch_clause":
            for caught_name in _pattern_names(node.child_by_field_name("parameter")):
                bind(node, caught_name, "other")
    return bindings


class _Resolver:
    """Resolve a name from a scope outward, remembering each scope's answer per name.

    Without the memory, deeply nested scopes that each look a name up would
    climb the same chain again every time.
    """

    def __init__(self, index: _Index, bindings: dict[tuple[int, str], object]) -> None:
        self.index = index
        self.bindings = bindings
        self._known: dict[str, dict[int, object]] = {}

    def bind(self, scope: Node, name: str, value: object) -> None:
        self.bindings[(scope.id, name)] = value
        self._known.pop(name, None)

    def lookup(self, name: str | None, node: Node) -> object:
        if name is None:
            return None
        known = self._known.setdefault(name, {})
        visited: list[int] = []
        found: object = None
        scope = self.index.scope(self.index.parent(node))
        while scope is not None:
            self.index.check_deadline()
            if scope.id in known:
                found = known[scope.id]
                break
            visited.append(scope.id)
            if (scope.id, name) in self.bindings:
                found = self.bindings[(scope.id, name)]
                break
            scope = self.index.scope(self.index.parent(scope))
        for scope_id in visited:
            known[scope_id] = found
        return found


def _identifier(node: Node | None) -> str | None:
    """A plain name, without copying the text of a larger expression."""
    return _value(node) if node is not None and node.type == "identifier" else None


def _called_method(member: Node) -> str | None:
    """Return the static method name, or None when its spelling needs evaluation."""
    if member.type == "member_expression":
        name = _value(member.child_by_field_name("property"))
        return None if "\\" in name else name
    index = member.child_by_field_name("index")
    if index is None or index.type not in {"string", "template_string"}:
        return None
    if any(child.type != "string_fragment" for child in index.named_children):
        return None
    return _value(index)[1:-1]


def collect_typescript_source(path: Path, content: bytes, result: ScanResult) -> None:
    """Collect one candidate server file; every refusal is a scan failure naming why."""
    location = path.as_posix()
    try:
        _collect_source(content, path, result)
    except ImportError:
        result.scan_failures.append(
            f"{location}: TypeScript MCP parser dependency unavailable or incompatible"
        )
    except _RefusedError as exc:
        result.scan_failures.append(f"{location}: {exc}")
    except UnicodeError:
        result.scan_failures.append(f"{location}: invalid UTF-8")
    except ValueError:
        result.scan_failures.append(f"{location}: TypeScript source analysis refused")


def _parser(seconds: float) -> Parser:
    from tree_sitter import Language, Parser
    from tree_sitter_typescript import language_typescript

    # The pinned 0.25 binding's callback parse path crashes for this grammar.
    # Its supported native timeout bounds parsing without invoking callbacks.
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            return Parser(
                Language(language_typescript()),
                timeout_micros=max(1, int(seconds * 1_000_000)),
            )
    except (TypeError, ValueError, AttributeError) as exc:
        # A binding without timeout_micros, or a grammar ABI it rejects.
        raise ImportError("incompatible TypeScript parser binding") from exc


def _collect_source(content: bytes, path: Path, result: ScanResult) -> None:
    text = source_text(content)
    # The parser reads UTF-8; the file digest stays that of the bytes as stored.
    source = content if content[:2] not in UTF16_BYTE_ORDER_MARKS else text.encode("utf-8")
    settings = limits.current()
    nodes = limits.bound("ts-nodes")
    parse_seconds = MAX_PARSE_SECONDS * max(
        1.0, settings.syntax_bytes / limits.DEFAULTS.syntax_bytes
    )
    analysis_seconds = MAX_ANALYSIS_SECONDS * max(1.0, nodes.value / limits.DEFAULTS.ts_nodes)
    deadline = time.monotonic() + parse_seconds
    parser = _parser(parse_seconds)
    tree = parser.parse(source)
    if tree is None or time.monotonic() >= deadline:
        raise _RefusedError("TypeScript parsing exceeded its time limit")
    root = tree.root_node
    if root.has_error:
        raise _RefusedError("invalid TypeScript syntax")
    index = _index(root, nodes, time.monotonic() + analysis_seconds)
    bindings = _bindings(index, root)
    if "sdk" not in bindings.values():
        return
    resolver = _Resolver(index, bindings)
    location = path.as_posix()
    file_digest = hash_bytes(content)
    servers: dict[int, tuple[MCPServerComponent, int]] = {}
    for node in index.nodes:
        if node.type != "new_expression":
            continue
        constructor = _identifier(node.child_by_field_name("constructor"))
        if resolver.lookup(constructor, node) != "sdk":
            continue
        variable = index.parent(node)
        declaration = index.parent(variable)
        identifier = variable.child_by_field_name("name") if variable is not None else None
        receiver = _value(identifier) if identifier is not None else ""
        direct_scope = index.parent(declaration)
        scope = index.scope(direct_scope)
        if direct_scope is not None and direct_scope.type == "export_statement":
            direct_scope = index.parent(direct_scope)
        if (
            variable is None
            or variable.type != "variable_declarator"
            or declaration is None
            or declaration.type != "lexical_declaration"
            or not declaration.children
            or declaration.children[0].type != "const"
            or direct_scope is None
            or direct_scope.type not in {"program", "statement_block"}
            or scope is None
            or identifier is None
            or identifier.type != "identifier"
            or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,127}", receiver)
            or bindings.get((scope.id, receiver)) != variable.id
        ):
            result.surfaces_excluded.append(
                f"{location}:{node.start_point.row + 1} (unsupported MCP constructor binding or scope)"
            )
            continue
        line = declaration.start_point.row + 1
        ref = f"mcp-source:{quote(location, safe='')}:{receiver}:{line}:{node.start_byte}"
        server = MCPServerComponent(
            bom_ref=ref,
            name=receiver,
            source_path=location,
            properties={
                "declaration_line": line,
                "method": "typescript-ast",
                "collection_mode": "static-source-declaration",
                "runtime_registration": "unknown",
            },
        )
        resolver.bind(scope, receiver, (server, node.end_byte))
        servers[node.id] = (server, node.end_byte)
    components: list[MCPServerComponent | ToolComponent] = [s for s, _ in servers.values()]
    registrations = 0
    for node in index.nodes:
        if node.type != "call_expression":
            continue
        member = node.child_by_field_name("function")
        if member is None or member.type not in {"member_expression", "subscript_expression"}:
            continue
        method = _called_method(member)
        if method is not None and method not in {"registerTool", "tool"}:
            continue
        receiver_name = _identifier(member.child_by_field_name("object"))
        binding = resolver.lookup(receiver_name, node)
        if method is None:
            if isinstance(binding, tuple):
                result.surfaces_excluded.append(
                    f"{location}:{node.start_point.row + 1} (unresolved MCP method name)"
                )
            continue
        if not isinstance(binding, tuple):
            result.surfaces_excluded.append(
                f"{location}:{node.start_point.row + 1} (unresolved MCP registration receiver)"
            )
            continue
        registrations += 1
        if registrations > MAX_REGISTRATIONS:
            raise _RefusedError(f"more than {MAX_REGISTRATIONS} MCP tool registrations")
        server, declared_at = binding
        statement = index.parent(node)
        statement_scope = index.parent(statement)
        if (
            statement is None
            or statement.type != "expression_statement"
            or statement_scope is None
            or statement_scope.type not in {"program", "statement_block"}
            or node.start_byte < declared_at
        ):
            result.surfaces_excluded.append(
                f"{location}:{node.start_point.row + 1} (unsupported MCP registration scope or ordering)"
            )
            continue
        arguments = node.child_by_field_name("arguments")
        arg = arguments.named_children[0] if arguments and arguments.named_children else None
        name = _value(arg)[1:-1] if arg is not None and arg.type == "string" else ""
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", name):
            result.surfaces_excluded.append(
                f"{location}:{node.start_point.row + 1} (unresolved MCP tool name)"
            )
            continue
        ref = f"tool:{server.bom_ref}/{name}"
        if ref in server.tool_refs:
            result.scan_failures.append(
                f"{location}:{node.start_point.row + 1} (duplicate MCP tool registration)"
            )
            continue
        tool = ToolComponent(
            bom_ref=ref,
            name=name,
            mcp_server_ref=server.bom_ref,
            source_path=location,
            properties={
                "declaration_line": node.start_point.row + 1,
                "method": "typescript-ast",
                "collection_mode": "static-source-declaration",
                "registration_source_sha256": hash_bytes(node.text or b""),
                "source_sha256": file_digest,
            },
            claims={
                "tool_definition": ClaimEvidence(
                    method="not-collected",
                    scope="source-declaration",
                    unknown_reason="Only the literal registration name was collected; the effective descriptor is unobserved",
                )
            },
        )
        server.tool_refs.append(ref)
        server.tool_count += 1
        components.append(tool)
    result.components.extend(components)
