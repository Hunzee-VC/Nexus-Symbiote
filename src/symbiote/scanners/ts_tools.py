"""Static, literal MCP tool registrations in TypeScript; never execute package code."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import quote

from tree_sitter import Language, Node, Parser, Query, QueryCursor
from tree_sitter_typescript import language_typescript

from symbiote.core.hashing import hash_bytes
from symbiote.core.models import MCPServerComponent, ToolComponent
from symbiote.scanners.base import ScanResult, read_regular_text

_LANGUAGE = Language(language_typescript())
_IMPORT = Query(
    _LANGUAGE,
    """
(import_statement (import_clause (named_imports (import_specifier) @binding)) source: (string) @module)
""",
)
_CTOR = Query(
    _LANGUAGE,
    """
(lexical_declaration "const" (variable_declarator name: (identifier) @receiver value:
    (new_expression constructor: (identifier) @ctor))) @decl
""",
)
_CALL = Query(
    _LANGUAGE,
    """
(call_expression function: (member_expression object: (identifier) @receiver property:
    (property_identifier) @method) arguments: (arguments . (string) @name)) @call
""",
)
_MODULES = {"@modelcontextprotocol/server", "@modelcontextprotocol/sdk/server/mcp.js"}
_IGNORED = {".git", "node_modules", ".venv", "dist", "build", "__tests__", "tests", "test"}


def _value(node: Node) -> str:
    return (node.text or b"").decode("utf-8")


def _block(node: Node) -> int | None:
    while node.parent:
        node = node.parent
        if node.type in {"program", "statement_block"}:
            return node.id
    return None


def collect_typescript(root: Path, result: ScanResult) -> None:
    parser = Parser(_LANGUAGE)
    for path in sorted(root.rglob("*.ts")):
        rel = path.relative_to(root)
        if _IGNORED.intersection(rel.parts) or path.name.endswith(
            (".d.ts", ".spec.ts", ".test.ts")
        ):
            continue
        try:
            source = read_regular_text(path)
        except (OSError, ValueError):
            result.scan_failures.append(f"Cannot inspect TypeScript source {rel}")
            continue
        if "@modelcontextprotocol/" not in source or "McpServer" not in source:
            continue
        tree = parser.parse(source.encode())
        result.surfaces_scanned.append(str(rel))
        if tree.root_node.has_error:
            result.scan_failures.append(f"Invalid TypeScript syntax in {rel}")
            continue
        aliases = set()
        for _, match in QueryCursor(_IMPORT).matches(tree.root_node):
            binding = match["binding"][0]
            import_name = binding.child_by_field_name("name")
            if (
                import_name
                and _value(import_name) == "McpServer"
                and _value(match["module"][0])[1:-1] in _MODULES
            ):
                aliases.add(_value(binding.child_by_field_name("alias") or import_name))
        servers: dict[tuple[int | None, str], MCPServerComponent] = {}
        for _, match in QueryCursor(_CTOR).matches(tree.root_node):
            if _value(match["ctor"][0]) not in aliases:
                continue
            receiver = _value(match["receiver"][0])
            line = match["decl"][0].start_point.row + 1
            key = f"mcp-source:{quote(rel.as_posix(), safe='')}:{receiver}:{line}"
            server = MCPServerComponent(
                bom_ref=key,
                name=receiver,
                source_path=rel.as_posix(),
                properties={"declaration_line": line, "method": "typescript-ast"},
            )
            servers[(_block(match["decl"][0]), receiver)] = server
            result.components.append(server)
        for _, match in QueryCursor(_CALL).matches(tree.root_node):
            call = match["call"][0]
            bound_server = servers.get((_block(call), _value(match["receiver"][0])))
            if not bound_server or _value(match["method"][0]) not in {"registerTool", "tool"}:
                continue
            name = _value(match["name"][0])[1:-1]
            if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", name):
                continue
            tool = ToolComponent(
                bom_ref=f"tool:{bound_server.bom_ref}/{name}",
                name=name,
                mcp_server_ref=bound_server.bom_ref,
                source_path=rel.as_posix(),
                properties={
                    "declaration_line": call.start_point.row + 1,
                    "method": "typescript-ast",
                    "registration_source_sha256": hash_bytes(call.text or b""),
                },
            )
            if tool.bom_ref in bound_server.tool_refs:
                result.scan_failures.append(
                    f"Duplicate tool registration {name!r} at {rel}:{call.start_point.row + 1}"
                )
                continue
            bound_server.tool_refs.append(tool.bom_ref)
            bound_server.tool_count += 1
            result.components.append(tool)
