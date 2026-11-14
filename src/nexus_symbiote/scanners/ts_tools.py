"""Bounded static MCP names from lexically bound TypeScript and JavaScript SDK registrations.

This records source declarations, never evaluated tool descriptors or runtime
registration. Servers are collected only when ``McpServer`` is imported from a
known module of the official SDK, by name or through a namespace import, and
constructed in a supported form. A module specifier names the SDK wherever its
scope appears in it: after ``npm:``, in a URL or in a path into ``node_modules``.
The uses of the SDK this analysis meets and does not follow are explicit collection
gaps: another import form or module path, a module load by ``require`` or dynamic
import, also of a module name it cannot read, a re-export, the low-level ``Server``
class, a client transport that starts or reaches a server, a direct ``eval``,
dynamic names, unsupported bindings and registration ordering. It does not see the
SDK behind an alias resolved outside the file, such as a ``#`` subpath import, or
what code does with a collected server other than registering tools on it. No
source module or package code is executed.

TypeScript is parsed with the TypeScript grammar, and ``.tsx`` and JavaScript with
its TSX variant, as tsc reads them. The grammar is TypeScript's, so a JavaScript file
it cannot parse, or that it reads as type syntax where JavaScript reads a comparison,
is a gap rather than a failure.

The tree-sitter runtime and grammar are native code and parse the file in this
process, bounded by the source size, a native parse timeout, a node limit and an
analysis deadline. They are not isolated in a separate process.
"""

from __future__ import annotations

import codecs
import re
import time
import warnings
from collections.abc import Callable, Collection, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote, unquote

if TYPE_CHECKING:
    from tree_sitter import Node, Parser

from nexus_symbiote import limits
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import ClaimEvidence, MCPServerComponent, ToolComponent
from nexus_symbiote.limits import Bound
from nexus_symbiote.scanners.base import ScanResult

_SDK = "@modelcontextprotocol/"
_MODULES = {"@modelcontextprotocol/server", "@modelcontextprotocol/sdk/server/mcp.js"}
_IGNORED = {"dist", "build", "__tests__", "tests", "test", "docs", "benchmarks", "examples"}
# Whether tsc reads a suffix with JSX: TypeScript without, .tsx and JavaScript with.
_JSX = {
    ".ts": False,
    ".mts": False,
    ".cts": False,
    ".tsx": True,
    ".js": True,
    ".jsx": True,
    ".mjs": True,
    ".cjs": True,
}
SCRIPT_SUFFIXES = frozenset(_JSX)
_JAVASCRIPT = frozenset({".js", ".jsx", ".mjs", ".cjs"})
NOT_SOURCE_NAMES = (
    ".d.ts",
    ".d.mts",
    ".d.cts",
    *(f".{kind}{suffix}" for kind in ("spec", "test") for suffix in _JSX),
)
SDK_MARKER = b"@modelcontextprotocol/"
# A file is parsed when it names the SDK and a server or client transport class, or
# names a server or client module, also by a build path or with a version, so a
# server or launch built by any import form is seen.
_CLASS_MARKERS = (b"McpServer", b"ClientTransport")
_MODULE_MARKERS = (
    *(b"@modelcontextprotocol/sdk" + end for end in (b"/server", b"/client", b"/dist", b"@")),
    *(
        b"@modelcontextprotocol/" + package + end
        for package in (b"server", b"client")
        for end in (b'"', b"'", b"`", b"/", b"@", b"?", b"#")
    ),
)
SOURCE_MARKERS = (SDK_MARKER, *_CLASS_MARKERS, *_MODULE_MARKERS)
# tsc and web browsers decode a source file that starts with a UTF-16 byte order
# mark as UTF-16 (bun only the little-endian form), and any other file as UTF-8.
UTF16_BYTE_ORDER_MARKS = {codecs.BOM_UTF16_LE: "utf-16-le", codecs.BOM_UTF16_BE: "utf-16-be"}
MAX_REGISTRATIONS = 1_000
# Time bounds for the default size limits; they grow in proportion when an
# operator raises syntax-bytes or ts-nodes, so a larger file is not refused for time.
MAX_PARSE_SECONDS = 0.25
MAX_ANALYSIS_SECONDS = 2.0

LAUNCHED = "MCP server launched from application code; launcher not inventoried"
REACHED = "MCP server reached from application code; endpoint not inventoried"
_TRANSPORTS = {
    "StdioClientTransport": LAUNCHED,
    "SSEClientTransport": REACHED,
    "StreamableHTTPClientTransport": REACHED,
    "WebSocketClientTransport": REACHED,
}
_LOW_LEVEL = "low-level MCP server tool list uncollected"
_UNSUPPORTED_IMPORT = "unsupported MCP SDK import"
_UNSUPPORTED_BINDING = "unsupported MCP server SDK binding"
_NAMESPACE_USE = "unsupported use of an MCP SDK namespace"
_UNREAD_MODULE = "module specifier the analysis cannot read"
_EVALUATED = "direct eval can use the MCP SDK imports of the file; what it builds not inventoried"
_REEXPORTED = (
    "MCP SDK class re-exported; servers it builds, starts or reaches elsewhere not inventoried"
)
_LOADED = {
    "server": "MCP server SDK loaded by require or dynamic import; servers and tools not "
    "inventoried",
    "client": "MCP client SDK loaded by require or dynamic import; servers it starts or "
    "reaches not inventoried",
}
_COMPUTED_LOAD = (
    "require or dynamic import of a module name the analysis cannot read; what it loads not "
    "inventoried"
)
_NAMED = "MCP SDK module named as a call argument; what the call loads not inventoried"
# Expressions that evaluate to one operand: `(0, require)`, `require as Loader`, `require!`.
_WRAPPERS = frozenset(
    {
        "parenthesized_expression",
        "sequence_expression",
        "type_assertion",
        "as_expression",
        "satisfies_expression",
        "non_null_expression",
    }
)
_OPERAND_FIRST = frozenset({"as_expression", "satisfies_expression", "non_null_expression"})
# `(eval)(code)` and `eval!(code)` still call eval directly; `(0, eval)(code)` does not.
_REFERENCE_WRAPPERS = _WRAPPERS - {"sequence_expression"}
_UNPARSED_JAVASCRIPT = (
    "JavaScript the TypeScript grammar cannot parse; servers and tools in the file not inventoried"
)
_TYPE_READING = (
    "JavaScript comparison the TypeScript grammar reads as type arguments; servers and "
    "tools in the file not inventoried"
)
# Type syntax, which TypeScript erases: a name inside it is no runtime reference.
_TYPE_SYNTAX = frozenset(
    {
        "type_annotation",
        "type_arguments",
        "type_parameters",
        "type_query",
        "type_alias_declaration",
        "interface_declaration",
        "implements_clause",
        "extends_type_clause",
        "ambient_declaration",
        "function_signature",
        "method_signature",
        "abstract_method_signature",
        "index_signature",
        "property_signature",
        "call_signature",
        "construct_signature",
        "nested_type_identifier",
        "generic_type",
        "object_type",
        "function_type",
        "constructor_type",
        "union_type",
        "intersection_type",
        "array_type",
        "tuple_type",
        "parenthesized_type",
        "lookup_type",
        "index_type_query",
        "conditional_type",
        "infer_type",
        "literal_type",
        "readonly_type",
        "template_literal_type",
        "predefined_type",
        "type_predicate",
        "type_predicate_annotation",
        "asserts",
        "asserts_annotation",
        "opting_type_annotation",
        "omitting_type_annotation",
        "adding_type_annotation",
    }
)
# Statements and specifiers that ``type`` makes type-only: `export type { X }`.
_TYPE_ONLY_CAPABLE = frozenset(
    {"import_statement", "import_specifier", "export_statement", "export_specifier"}
)
_IDENTIFIER_ESCAPE = re.compile(r"\\u(?:\{([0-9A-Fa-f]{1,6})\}|([0-9A-Fa-f]{4}))")
_HEX_ESCAPE = re.compile(r"x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|u\{([0-9A-Fa-f]{1,6})\}")
_SINGLE_ESCAPES = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "0": "\0"}
_LINE_CONTINUATIONS = frozenset({"\n", "\r", "\r\n", "\u2028", "\u2029"})


class _RefusedError(ValueError):
    """The file was not collected; the message names why and quotes no source."""


@dataclass(frozen=True)
class _Namespace:
    """A namespace import of an SDK module: server, client or other, and the collected one."""

    kind: str
    exact: bool


@dataclass(frozen=True)
class _Launcher:
    """A client transport class of the SDK, which starts or reaches a server."""

    reason: str


def is_server_source(path: Path) -> bool:
    """A TypeScript or JavaScript file this collector supports, before its content is known."""
    return (
        path.suffix in SCRIPT_SUFFIXES
        and not _IGNORED.intersection(path.parts)
        and not path.name.endswith(NOT_SOURCE_NAMES)
    )


def is_analysis_candidate(found: Collection[bytes]) -> bool:
    """Whether the markers a search found make a script one the analysis parses."""
    return (SDK_MARKER in found and any(marker in found for marker in _CLASS_MARKERS)) or any(
        marker in found for marker in _MODULE_MARKERS
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


def _code_point(match: re.Match[str]) -> str:
    value = int(match.group(1) or match.group(2), 16)
    return chr(value) if value <= 0x10FFFF else match.group(0)


def _name(node: Node | None) -> str:
    """An identifier as JavaScript reads it: ``\\u0073erver`` is ``server``."""
    text = _value(node)
    return text if "\\" not in text else _IDENTIFIER_ESCAPE.sub(_code_point, text)


def _escape(sequence: str) -> str | None:
    """The text one string escape sequence stands for; None for legacy octal forms."""
    body = sequence[1:]
    hexadecimal = _HEX_ESCAPE.fullmatch(body)
    if hexadecimal is not None:
        value = int(next(group for group in hexadecimal.groups() if group), 16)
        return chr(value) if value <= 0x10FFFF else None
    if body in _SINGLE_ESCAPES:
        return _SINGLE_ESCAPES[body]
    if body in _LINE_CONTINUATIONS:
        return ""
    return body if len(body) == 1 and not body.isdigit() and body not in {"x", "u"} else None


def _string_value(node: Node | None) -> str | None:
    """A string or substitution-free template literal as JavaScript reads it, else None."""
    if node is None or node.type not in {"string", "template_string"}:
        return None
    parts: list[str] = []
    for child in node.named_children:
        if child.type == "string_fragment":
            parts.append(_value(child))
            continue
        decoded = _escape(_value(child)) if child.type == "escape_sequence" else None
        if decoded is None:
            return None
        parts.append(decoded)
    return "".join(parts)


def _module_kind(module: str) -> str | None:
    """Whether a module specifier names a server, client or other module of the SDK.

    The scope counts wherever it appears, since a runtime or bundler can resolve it
    there: after ``npm:`` or ``jsr:``, in a URL, in a path into ``node_modules``, with a
    version after the package name, with a query or fragment, percent-encoded, with
    backslashes or in another letter case. Only the exact names in ``_MODULES`` are
    followed.
    """
    text = unquote(module).replace("\\", "/").lower()
    start = text.find(_SDK)
    if start < 0:
        return None
    path = re.split(r"[?#]", text[start + len(_SDK) :], maxsplit=1)[0]
    package, *rest = path.split("/")
    segments = [package.split("@", 1)[0], *rest]
    for kind in ("server", "client"):
        if kind in segments:
            return kind
    return "other"


def _type_only(node: Node) -> bool:
    return any(child.type == "type" for child in node.children)


def _same(node: Node | None, other: Node) -> bool:
    return node is not None and node.id == other.id


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
    """Every named node once, with its parent, its enclosing scope and whether it is erased.

    tree-sitter finds a node's parent by descending from the root, so climbing
    ``Node.parent`` costs the depth at every step. Recording these relations in one
    traversal keeps the analysis linear in the number of nodes. ``erased`` holds the
    nodes inside type syntax, which has no runtime effect.
    """

    nodes: list[Node]
    parents: dict[int, Node]
    scopes: dict[int, Node]
    erased: set[int]
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
    index = _Index([], {}, {}, set(), deadline)
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
        if (
            (parent is not None and parent.id in index.erased)
            or node.type in _TYPE_SYNTAX
            or (node.type in _TYPE_ONLY_CAPABLE and _type_only(node))
        ):
            index.erased.add(node.id)
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
            names.append(_name(current))
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


@dataclass
class _Declarations:
    """The names a file binds, the SDK import forms that are gaps, and the import identifiers.

    ``declared`` holds the identifiers inside import and re-export statements, which
    bind a name or name another module's export and never use a binding of this file.
    ``loaders`` holds ``require`` and every name the file binds to what
    ``createRequire`` returns.
    """

    bindings: dict[tuple[int, str], object]
    gaps: list[tuple[Node, str]]
    declared: set[int]
    loaders: set[str]


def _imported_name(node: Node | None) -> str | None:
    """An imported or exported name, which may be a string: ``import { "a b" as c }``."""
    if node is not None and node.type == "string":
        return _string_value(node)
    return _name(node)


def _bind_import(
    statement: Node,
    root: Node,
    bind: Callable[[Node | None, str, object], None],
    found: _Declarations,
) -> None:
    """Bind the names one import declares, sorting the SDK forms the analysis follows."""
    clause = next((c for c in statement.named_children if c.type == "import_require_clause"), None)
    module = _string_value((clause or statement).child_by_field_name("source"))
    if module is None:
        found.gaps.append((statement, _UNREAD_MODULE))
    kind = None if module is None or _type_only(statement) else _module_kind(module)
    for spec in _nodes(statement, limits.bound("ts-nodes")):
        if spec.type == "identifier":
            found.declared.add(spec.id)
        elif spec.type == "import_specifier":
            imported = _imported_name(spec.child_by_field_name("name"))
            alias = spec.child_by_field_name("alias")
            value: object = "other"
            if kind is not None and not _type_only(spec):
                if (
                    imported is None
                    or (imported == "McpServer" and module not in _MODULES)
                    or (imported == "default" and kind in {"server", "client"})
                ):
                    found.gaps.append((spec, _UNSUPPORTED_IMPORT))
                elif imported == "McpServer":
                    value = "sdk"
                elif imported == "Server" and kind == "server":
                    found.gaps.append((spec, _LOW_LEVEL))
                elif imported in _TRANSPORTS:
                    value = _Launcher(_TRANSPORTS[imported])
            bind(root, _name(alias) if alias is not None else imported or "", value)
        elif spec.type == "namespace_import":
            for child in spec.named_children:
                if child.type == "identifier":
                    namespace = None if kind is None else _Namespace(kind, module in _MODULES)
                    bind(root, _name(child), namespace or "other")
        elif spec.type in {"import_clause", "import_require_clause"}:
            for child in spec.named_children:
                if child.type != "identifier":
                    continue
                # A default import of a server or client module may be the whole module.
                if kind in {"server", "client"}:
                    reason = _LOADED[kind] if spec.type == "import_require_clause" else None
                    found.gaps.append((child, reason or _UNSUPPORTED_IMPORT))
                bind(root, _name(child), "other")


def _reexport(statement: Node, found: _Declarations) -> None:
    """Record a re-export of an SDK class or module: what is built from it is elsewhere."""
    specifiers: list[Node] = []
    for node in _nodes(statement, limits.bound("ts-nodes")):
        if node.type == "identifier":
            found.declared.add(node.id)
        elif node.type == "export_specifier" and not _type_only(node):
            specifiers.append(node)
    module = _string_value(statement.child_by_field_name("source"))
    if module is None:
        found.gaps.append((statement, _UNREAD_MODULE))
        return
    kind = _module_kind(module)
    if kind is None or _type_only(statement):
        return
    module_wide = kind in {"server", "client"}
    whole = any(child.type in {"*", "namespace_export"} for child in statement.children)
    if whole and module_wide:
        found.gaps.append((statement, _REEXPORTED))
    for spec in specifiers:
        name = _imported_name(spec.child_by_field_name("name"))
        if (
            name in {None, "McpServer", *_TRANSPORTS}
            or (name == "Server" and kind == "server")
            or (name == "default" and module_wide)
        ):
            found.gaps.append((spec, _REEXPORTED))


def _bindings(index: _Index, root: Node) -> _Declarations:
    found = _Declarations({}, [], set(), {"require"})
    bindings = found.bindings

    def bind(scope: Node | None, name: str, value: object) -> None:
        if scope is not None and name:
            key = (scope.id, name)
            bindings[key] = "ambiguous" if key in bindings else value

    for position, node in enumerate(index.nodes):
        if not position % 1024:
            index.check_deadline()
        parent = index.parent(node)
        at_root = parent is not None and parent.id == root.id
        if node.type == "import_statement" and at_root:
            _bind_import(node, root, bind, found)
        elif node.type == "export_statement" and at_root and node.child_by_field_name("source"):
            _reexport(node, found)
        elif node.type == "variable_declarator":
            target = node.child_by_field_name("name")
            for declared_name in _pattern_names(target):
                bind(index.scope(parent), declared_name, node.id)
            if _creates_require(node.child_by_field_name("value")):
                found.loaders.update(_pattern_names(target))
        elif node.type == "assignment_expression":
            if _creates_require(node.child_by_field_name("right")):
                found.loaders.update(_pattern_names(node.child_by_field_name("left")))
        elif node.type in _FUNCTIONS:
            name = node.child_by_field_name("name")
            # A method's name is a property key: `McpServer() {}` binds no McpServer.
            if name is not None and node.type != "method_definition":
                bind(
                    index.scope(parent) if "declaration" in node.type else node,
                    _name(name),
                    "other",
                )
            parameters = node.child_by_field_name("parameters") or node.child_by_field_name(
                "parameter"
            )
            for parameter in _pattern_names(parameters):
                bind(node, parameter, "other")
        elif node.type in {"class_declaration", "enum_declaration"}:
            bind(index.scope(parent), _name(node.child_by_field_name("name")), "other")
        elif node.type == "catch_clause":
            for caught_name in _pattern_names(node.child_by_field_name("parameter")):
                bind(node, caught_name, "other")
    return found


class _Resolver:
    """The binding each name in the file refers to, found in one walk of the tree.

    The walk keeps, for every name, the stack of bindings in effect, so resolving all
    references costs one step each however deep the scopes or many the names. A
    binding's value can change later, when a server is bound to its receiver; which
    binding a reference names cannot.
    """

    def __init__(self, index: _Index, root: Node, bindings: dict[tuple[int, str], object]) -> None:
        self.bindings = bindings
        self._targets: dict[int, tuple[int, str]] = {}
        declared: dict[int, list[str]] = {}
        for scope_id, name in bindings:
            declared.setdefault(scope_id, []).append(name)
        active: dict[str, list[tuple[int, str]]] = {}
        pending: list[tuple[Node, bool]] = [(root, False)]
        visited = 0
        while pending:
            node, leaving = pending.pop()
            names = declared.get(node.id, ())
            if leaving:
                for name in names:
                    active[name].pop()
                continue
            visited += 1
            if not visited % 1024:
                index.check_deadline()
            if node.type in {"identifier", "shorthand_property_identifier"}:
                stack = active.get(_name(node))
                if stack:
                    self._targets[node.id] = stack[-1]
            if names:
                for name in names:
                    active.setdefault(name, []).append((node.id, name))
                pending.append((node, True))
            pending.extend((child, False) for child in reversed(node.named_children))

    def bind(self, scope: Node, name: str, value: object) -> None:
        self.bindings[(scope.id, name)] = value

    def lookup(self, node: Node | None) -> object:
        """The value of the binding an identifier refers to, or None when it is unbound."""
        target = None if node is None else self._targets.get(node.id)
        return None if target is None else self.bindings.get(target)


def _identifier(node: Node | None) -> str | None:
    """A plain name, without copying the text of a larger expression."""
    return _name(node) if node is not None and node.type == "identifier" else None


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


def _operand(node: Node | None, wrappers: Collection[str] = _WRAPPERS) -> Node | None:
    """The expression a wrapper such as ``(0, require)`` or ``require as Loader`` evaluates to."""
    while node is not None and node.type in wrappers and node.named_children:
        children = node.named_children
        node = children[0] if node.type in _OPERAND_FIRST else children[-1]
    return node


def _property(member: Node) -> str | None:
    """A member's name as JavaScript reads it, or None when it is computed."""
    if member.type == "member_expression":
        return _name(member.child_by_field_name("property"))
    if member.type == "subscript_expression":
        return _string_value(member.child_by_field_name("index"))
    return None


def _creates_require(node: Node | None) -> bool:
    """Whether an expression calls ``createRequire``, which returns a module loader."""
    call = _operand(node)
    if call is None or call.type != "call_expression":
        return False
    function = _operand(call.child_by_field_name("function"))
    if function is not None and function.type == "identifier":
        return _name(function) == "createRequire"
    return function is not None and _property(function) == "createRequire"


def _loader(function: Node | None, loaders: Collection[str]) -> bool:
    """Whether a callee loads a module: ``import``, ``require``, ``module.require`` or a loader
    ``createRequire`` made."""
    callee = _operand(function)
    if callee is not None and callee.type in {"import", "identifier"}:
        return callee.type == "import" or _name(callee) in loaders
    return callee is not None and (_property(callee) == "require" or _creates_require(callee))


def _load(call: Node, loaders: Collection[str]) -> tuple[bool, Node | None]:
    """Whether a call loads a module, and the argument that names it, if any.

    The name is the first argument of a direct call, the second of ``call``, and the
    first element of the array literal ``apply`` passes; for any other call, the
    first argument is returned for the caller to check.
    """
    function = _operand(call.child_by_field_name("function"))
    arguments = call.child_by_field_name("arguments")
    # A tagged template passes no specifier a loader accepts.
    listed = arguments is not None and arguments.type == "arguments"
    values = arguments.named_children if arguments is not None and listed else []
    if _loader(function, loaders):
        return True, values[0] if values else None
    method = None if function is None else _property(function)
    if function is not None and method in {"call", "apply"}:
        if _loader(function.child_by_field_name("object"), loaders):
            passed = values[1] if len(values) > 1 else None
            if method == "apply":
                array = passed is not None and passed.type == "array"
                elements = passed.named_children if passed is not None and array else []
                passed = elements[0] if elements else None
            return True, passed
    return False, values[0] if values else None


def _is_constructor(node: Node, index: _Index) -> bool:
    """Whether ``node`` is what a ``new`` expression constructs."""
    outer = index.parent(node)
    return (
        outer is not None
        and outer.type == "new_expression"
        and _same(outer.child_by_field_name("constructor"), node)
    )


def _use(node: Node, binding: object, index: _Index) -> str | None:
    """The gap one use of an SDK import leaves, or None when the analysis follows it."""
    parent = index.parent(node)
    if parent is not None and parent.type == "export_specifier":
        if _same(parent.child_by_field_name("alias"), node):
            return None
    if binding == "sdk":
        return None if _is_constructor(node, index) else _UNSUPPORTED_BINDING
    if isinstance(binding, _Launcher):
        return binding.reason
    if not isinstance(binding, _Namespace):
        return None
    member = (
        parent
        if parent is not None
        and parent.type in {"member_expression", "subscript_expression"}
        and _same(parent.child_by_field_name("object"), node)
        else None
    )
    name = None if member is None else _called_method(member)
    # With CommonJS interop, ``default`` can be the whole module again.
    if name is None or name == "default":
        return _NAMESPACE_USE if binding.kind in {"server", "client"} else None
    if name == "McpServer" and member is not None:
        if not binding.exact:
            return _UNSUPPORTED_IMPORT
        return None if _is_constructor(member, index) else _UNSUPPORTED_BINDING
    if name == "Server" and binding.kind == "server":
        return _LOW_LEVEL
    return _TRANSPORTS.get(name)


def _sdk_uses(index: _Index, root: Node, found: _Declarations, resolver: _Resolver) -> None:
    """Record each use of the SDK the analysis does not follow as a gap.

    A use is an identifier outside type syntax that resolves to an SDK import; a
    module load, such as ``require`` or ``import()``, of a server or client module or
    of a name the analysis cannot read; any other call whose first argument names a
    server or client module; and a direct ``eval``, which can reach the imports of
    the module it runs in.
    """
    tracked = {
        name
        for (scope, name), value in found.bindings.items()
        if scope == root.id and (value == "sdk" or isinstance(value, (_Namespace, _Launcher)))
    }
    for position, node in enumerate(index.nodes):
        if not position % 1024:
            index.check_deadline()
        if node.id in index.erased:
            continue
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if tracked and _identifier(_operand(function, _REFERENCE_WRAPPERS)) == "eval":
                found.gaps.append((node, _EVALUATED))
            loads, specifier = _load(node, found.loaders)
            module = _string_value(specifier)
            kind = None if module is None else _module_kind(module)
            if loads and module is None:
                found.gaps.append((node, _COMPUTED_LOAD))
            elif kind in _LOADED:
                found.gaps.append((node, _LOADED[kind] if loads else _NAMED))
            continue
        if (
            node.type not in {"identifier", "shorthand_property_identifier"}
            or node.id in found.declared
        ):
            continue
        if _name(node) in tracked:
            reason = _use(node, resolver.lookup(node), index)
            if reason is not None:
                found.gaps.append((node, reason))


def _sdk_constructor(callee: Node | None, resolver: _Resolver) -> bool:
    """Whether a ``new`` expression's callee is the collected ``McpServer`` class."""
    if callee is not None and callee.type in {"member_expression", "subscript_expression"}:
        binding = resolver.lookup(callee.child_by_field_name("object"))
        return (
            isinstance(binding, _Namespace)
            and binding.exact
            and _called_method(callee) == "McpServer"
        )
    return resolver.lookup(callee) == "sdk"


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


def _parser(seconds: float, jsx: bool) -> Parser:
    from tree_sitter import Language, Parser
    from tree_sitter_typescript import language_tsx, language_typescript

    # The pinned 0.25 binding's callback parse path crashes for this grammar.
    # Its supported native timeout bounds parsing without invoking callbacks.
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            return Parser(
                Language(language_tsx() if jsx else language_typescript()),
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
    parser = _parser(parse_seconds, _JSX.get(path.suffix, False))
    tree = parser.parse(source)
    if tree is None or time.monotonic() >= deadline:
        raise _RefusedError("TypeScript parsing exceeded its time limit")
    root = tree.root_node
    location = path.as_posix()
    javascript = path.suffix in _JAVASCRIPT
    if root.has_error:
        if javascript:
            result.surfaces_excluded.append(f"{location}: {_UNPARSED_JAVASCRIPT}")
            return
        raise _RefusedError("invalid TypeScript syntax")
    index = _index(root, nodes, time.monotonic() + analysis_seconds)
    if javascript:
        # JavaScript reads `a < b > (c)` as two comparisons, TypeScript as a call.
        reading = next((node for node in index.nodes if node.type == "type_arguments"), None)
        if reading is not None:
            result.surfaces_excluded.append(
                f"{location}:{reading.start_point.row + 1} ({_TYPE_READING})"
            )
            return
    found = _bindings(index, root)
    bindings = found.bindings
    resolver = _Resolver(index, root, bindings)
    _sdk_uses(index, root, found, resolver)
    found.gaps.sort(key=lambda gap: (gap[0].start_byte, gap[1]))
    result.surfaces_excluded.extend(
        dict.fromkeys(f"{location}:{node.start_point.row + 1} ({why})" for node, why in found.gaps)
    )
    if not any(
        value == "sdk" or (isinstance(value, _Namespace) and value.exact)
        for value in bindings.values()
    ):
        return
    file_digest = hash_bytes(content)
    servers: dict[int, tuple[MCPServerComponent, int]] = {}
    # An ambient declaration, such as `declare namespace`, is erased and never runs.
    for node in index.nodes:
        if node.type != "new_expression" or node.id in index.erased:
            continue
        if not _sdk_constructor(node.child_by_field_name("constructor"), resolver):
            continue
        variable = index.parent(node)
        declaration = index.parent(variable)
        identifier = variable.child_by_field_name("name") if variable is not None else None
        receiver = _name(identifier) if identifier is not None else ""
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
        if node.type != "call_expression" or node.id in index.erased:
            continue
        member = node.child_by_field_name("function")
        if member is None or member.type not in {"member_expression", "subscript_expression"}:
            continue
        method = _called_method(member)
        if method is not None and method not in {"registerTool", "tool"}:
            continue
        binding = resolver.lookup(member.child_by_field_name("object"))
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
