"""Collect literal Python SDK tool declarations without importing scanned code."""

from __future__ import annotations

import ast
import re
from collections import Counter
from itertools import islice
from pathlib import Path
from urllib.parse import quote

from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import ClaimEvidence, MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.base import ScanResult

PYTHON_TOOL_HINTS = ("mcp", "langchain", "crewai", "function_tool", "smolagents", "pydantic_ai")

_FACTORIES = {
    ("mcp.server.fastmcp", "FastMCP"),
    ("mcp.server.mcpserver", "MCPServer"),
    ("fastmcp", "FastMCP"),
}

_DECORATOR_IMPORTS = {
    ("langchain_core.tools", "tool"): "langchain",
    ("langchain.tools", "tool"): "langchain",
    ("crewai.tools", "tool"): "crewai",
    ("agents", "function_tool"): "openai-agents",
    ("agents.tool", "function_tool"): "openai-agents",
    ("smolagents", "tool"): "smolagents",
    ("smolagents.tools", "tool"): "smolagents",
}

_AGENT_FACTORIES = {
    ("pydantic_ai", "Agent"): "pydantic-ai",
    ("pydantic_ai.agent", "Agent"): "pydantic-ai",
}


def _bindings(nodes: list[ast.AST]) -> Counter[str]:
    # Count even nested writes conservatively. A shadowed name needs scope
    # analysis before it can be attributed to the SDK or a particular server.
    names: Counter[str] = Counter()
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names[node.id] += 1
        elif isinstance(node, ast.alias):
            names[node.asname or node.name.split(".")[0]] += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names[node.name] += 1
        elif isinstance(node, ast.arg):
            names[node.arg] += 1
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            names[node.name] += 1
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names[node.rest] += 1
    return names


def _record_decorator(
    deco: ast.Call,
    default_name: str,
    server: MCPServerComponent,
    path: Path,
    source_digest: str,
    result: ScanResult,
) -> None:
    options = {kw.arg: kw.value for kw in deco.keywords}
    name: object = default_name
    if "name" in options:
        value = options["name"]
        name = value.value if isinstance(value, ast.Constant) else None
    if (
        deco.args
        or len(options) != len(deco.keywords)
        or None in options
        or not isinstance(name, str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
    ):
        result.surfaces_excluded.append(f"{path}:{deco.lineno}: unresolved Python MCP tool name")
        return
    ref = f"tool:{server.bom_ref}/{name}"
    if ref in server.tool_refs:
        result.scan_failures.append(f"{path}:{deco.lineno}: duplicate Python MCP tool declaration")
        return
    result.components.append(
        ToolComponent(
            bom_ref=ref,
            name=name,
            mcp_server_ref=server.bom_ref,
            source_path=path.as_posix(),
            claims={
                "tool_definition": ClaimEvidence(
                    method="not-collected",
                    scope="source-declaration",
                    unknown_reason="Effective descriptor requires runtime evidence",
                )
            },
            properties={
                "method": "python-ast",
                "collection_mode": "static-source-declaration",
                "declaration_line": deco.lineno,
                "source_sha256": source_digest,
            },
        )
    )
    server.tool_refs.append(ref)
    server.tool_count += 1


def _record_sdk_decorator(
    deco: ast.AST,
    default_name: str,
    framework: str,
    path: Path,
    source_digest: str,
    seen_refs: set[str],
    result: ScanResult,
) -> None:
    lineno = getattr(deco, "lineno", 1)
    name: object = default_name
    if isinstance(deco, ast.Call):
        options = {kw.arg: kw.value for kw in deco.keywords}
        name_keys = [k for k in ("name", "name_or_callable", "name_override") if k in options]
        if (
            len(deco.args) > 1
            or any(isinstance(arg, ast.Starred) for arg in deco.args)
            or len(options) != len(deco.keywords)
            or None in options
            or len(name_keys) > 1
            or (deco.args and name_keys)
        ):
            result.surfaces_excluded.append(f"{path}:{lineno}: unresolved Python SDK tool name")
            return
        if len(deco.args) == 1:
            arg = deco.args[0]
            name = arg.value if isinstance(arg, ast.Constant) else None
        elif name_keys:
            val = options[name_keys[0]]
            name = val.value if isinstance(val, ast.Constant) else None
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
        result.surfaces_excluded.append(f"{path}:{lineno}: unresolved Python SDK tool name")
        return
    ref = f"tool:python:{quote(path.as_posix(), safe='')}/{name}"
    if ref in seen_refs:
        result.scan_failures.append(f"{path}:{lineno}: duplicate Python SDK tool declaration")
        return
    seen_refs.add(ref)
    result.components.append(
        ToolComponent(
            bom_ref=ref,
            name=name,
            source_path=path.as_posix(),
            claims={
                "tool_definition": ClaimEvidence(
                    method="not-collected",
                    scope="source-declaration",
                    unknown_reason="Effective descriptor requires runtime evidence",
                )
            },
            properties={
                "method": "python-ast",
                "framework": framework,
                "collection_mode": "static-source-declaration",
                "declaration_line": lineno,
                "source_sha256": source_digest,
            },
        )
    )


def _collect_sdk_decorators(
    tree: ast.Module,
    nodes: list[ast.AST],
    decorators: dict[str, tuple[ast.ImportFrom, str]],
    bindings: Counter[str],
    path: Path,
    source_digest: str,
    seen_refs: set[str],
    result: ScanResult,
) -> None:
    top_level = set(tree.body)
    valid: dict[str, tuple[int, str]] = {}
    unsupported = False
    for alias, (imported, framework) in decorators.items():
        if imported not in top_level or bindings[alias] != 1:
            unsupported = True
            continue
        valid[alias] = (imported.lineno, framework)
    if sum(isinstance(n, ast.Name) and n.id in decorators for n in nodes) > 1000:
        result.scan_failures.append(f"{path}: Python SDK tool registration limit exceeded")
        return
    handled: set[ast.AST] = set()
    for stmt in tree.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in stmt.decorator_list:
            if isinstance(deco, ast.Name) and deco.id in valid:
                import_line, framework = valid[deco.id]
                if import_line >= stmt.lineno:
                    unsupported = True
                    continue
                handled.add(deco)
                _record_sdk_decorator(
                    deco, stmt.name, framework, path, source_digest, seen_refs, result
                )
            elif (
                isinstance(deco, ast.Call)
                and isinstance(deco.func, ast.Name)
                and deco.func.id in valid
            ):
                import_line, framework = valid[deco.func.id]
                if import_line >= stmt.lineno:
                    unsupported = True
                    continue
                handled.add(deco.func)
                _record_sdk_decorator(
                    deco, stmt.name, framework, path, source_digest, seen_refs, result
                )
    load_uses = {
        node
        for node in nodes
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in decorators
    }
    if unsupported or (load_uses - handled):
        result.surfaces_excluded.append(
            f"{path}: unsupported Python SDK tool binding or dynamic registration"
        )


def _collect_agent_decorators(
    tree: ast.Module,
    nodes: list[ast.AST],
    agent_factories: dict[str, tuple[ast.ImportFrom, str]],
    bindings: Counter[str],
    path: Path,
    source_digest: str,
    seen_refs: set[str],
    result: ScanResult,
) -> None:
    top_level = set(tree.body)
    calls = {
        node
        for node in nodes
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in agent_factories
    }
    changed_receivers = {
        node.value.id
        for node in nodes
        if isinstance(node, ast.Attribute)
        and node.attr in {"tool", "tool_plain"}
        and isinstance(node.value, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
    }
    if (
        sum(
            isinstance(node, ast.Attribute) and node.attr in {"tool", "tool_plain"}
            for node in nodes
        )
        > 1000
    ):
        result.scan_failures.append(f"{path}: Python SDK tool registration limit exceeded")
        return
    unsupported_factory = any(
        imported not in top_level or bindings[factory] != 1
        for factory, (imported, _) in agent_factories.items()
    )
    agents: dict[str, tuple[int, str]] = {}
    handled: set[ast.AST] = set()
    for stmt in tree.body:
        target: ast.AST | None = None
        call: ast.AST | None = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            call = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            target = stmt.target
            call = stmt.value
        if target is not None and call is not None:
            if not (
                isinstance(target, ast.Name)
                and isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call in calls
            ):
                continue
            factory = call.func.id
            imported, framework = agent_factories[factory]
            if (
                imported not in top_level
                or imported.lineno >= stmt.lineno
                or bindings[factory] != 1
                or target.id in changed_receivers
                or bindings[target.id] != 1
            ):
                continue
            handled.add(call)
            agents[target.id] = (stmt.lineno, framework)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for deco in stmt.decorator_list:
                if (
                    isinstance(deco, ast.Attribute)
                    and deco.attr in {"tool", "tool_plain"}
                    and isinstance(deco.value, ast.Name)
                    and deco.value.id in agents
                ):
                    decl_line, framework = agents[deco.value.id]
                    if decl_line >= stmt.lineno:
                        continue
                    handled.add(deco)
                    _record_sdk_decorator(
                        deco, stmt.name, framework, path, source_digest, seen_refs, result
                    )
                elif (
                    isinstance(deco, ast.Call)
                    and isinstance(deco.func, ast.Attribute)
                    and deco.func.attr in {"tool", "tool_plain"}
                    and isinstance(deco.func.value, ast.Name)
                    and deco.func.value.id in agents
                ):
                    decl_line, framework = agents[deco.func.value.id]
                    if decl_line >= stmt.lineno:
                        continue
                    handled.add(deco.func)
                    _record_sdk_decorator(
                        deco, stmt.name, framework, path, source_digest, seen_refs, result
                    )
    candidates: set[ast.AST] = set(calls)
    candidates.update(
        node
        for node in nodes
        if isinstance(node, ast.Attribute)
        and node.attr in {"tool", "tool_plain"}
        and isinstance(node.value, ast.Name)
        and node.value.id in agents
    )
    aliases = any(
        isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
        and isinstance(node.value, ast.Name)
        and node.value.id in agents
        for node in nodes
    )
    if unsupported_factory or aliases or (candidates - handled):
        result.surfaces_excluded.append(
            f"{path}: unsupported Python SDK tool binding or dynamic registration"
        )


def _report_import_scope(
    imports: list[ast.ImportFrom], nodes: list[ast.AST], path: Path, result: ScanResult
) -> None:
    if any(
        stmt.module == "mcp.server" and any(a.name == "Server" for a in stmt.names)
        for stmt in imports
    ):
        result.surfaces_excluded.append(f"{path}: low-level MCP server tool list uncollected")
    modules = {module for module, _ in _FACTORIES}
    qualified_import = any(
        isinstance(node, ast.Import) and any(a.name in modules for a in node.names)
        for node in nodes
    )
    if qualified_import or any(
        stmt.module in modules and any(a.name == "*" for a in stmt.names) for stmt in imports
    ):
        result.surfaces_excluded.append(f"{path}: unresolved Python MCP factory import")
    sdk_modules = {module for module, _ in _DECORATOR_IMPORTS} | {
        module for module, _ in _AGENT_FACTORIES
    }
    qualified_sdk_import = any(
        isinstance(node, ast.Import) and any(a.name in sdk_modules for a in node.names)
        for node in nodes
    )
    if qualified_sdk_import or any(
        stmt.module in sdk_modules and any(a.name == "*" for a in stmt.names) for stmt in imports
    ):
        result.surfaces_excluded.append(f"{path}: unresolved Python SDK tool import")


def _factory_calls_and_rebinds(
    nodes: list[ast.AST], factories: dict[str, ast.ImportFrom]
) -> tuple[set[ast.Call], set[str]]:
    calls = {
        node
        for node in nodes
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in factories
    }
    changed_receivers = {
        node.value.id
        for node in nodes
        if isinstance(node, ast.Attribute)
        and node.attr == "tool"
        and isinstance(node.value, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
    }
    return calls, changed_receivers


def _server_from_assignment(
    stmt: ast.Assign,
    calls: set[ast.Call],
    factories: dict[str, ast.ImportFrom],
    top_level: set[ast.stmt],
    bindings: Counter[str],
    changed_receivers: set[str],
    path: Path,
) -> tuple[ast.Call, MCPServerComponent] | None:
    target = stmt.targets[0]
    call = stmt.value
    if not (
        isinstance(target, ast.Name)
        and isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call in calls
    ):
        return None
    factory = call.func.id
    imported = factories[factory]
    if (
        imported not in top_level
        or imported.lineno >= stmt.lineno
        or bindings[factory] != 1
        or target.id in changed_receivers
        or bindings[target.id] != 1
    ):
        return None
    server = MCPServerComponent(
        bom_ref=f"mcp-python:{quote(path.as_posix(), safe='')}:{target.id}:{stmt.lineno}",
        name=target.id,
        source_path=path.as_posix(),
        properties={
            "method": "python-ast",
            "collection_mode": "static-source-declaration",
            "runtime_registration": "unknown",
            "declaration_line": stmt.lineno,
        },
    )
    return call, server


def _record_decorated_tools(
    stmt: ast.FunctionDef | ast.AsyncFunctionDef,
    servers: dict[str, MCPServerComponent],
    handled: set[ast.AST],
    path: Path,
    source_digest: str,
    result: ScanResult,
) -> None:
    for deco in stmt.decorator_list:
        if not (
            isinstance(deco, ast.Call)
            and isinstance(deco.func, ast.Attribute)
            and deco.func.attr == "tool"
            and isinstance(deco.func.value, ast.Name)
        ):
            continue
        receiver = deco.func.value.id
        if receiver not in servers:
            continue
        handled.add(deco.func)
        _record_decorator(deco, stmt.name, servers[receiver], path, source_digest, result)


def _has_unsupported_registration(
    nodes: list[ast.AST],
    calls: set[ast.Call],
    handled: set[ast.AST],
    servers: dict[str, MCPServerComponent],
) -> bool:
    candidates: set[ast.AST] = set(calls)
    candidates.update(
        node
        for node in nodes
        if isinstance(node, ast.Attribute)
        and node.attr in {"tool", "add_tool", "add_tools", "add_provider", "mount", "import_server"}
        and isinstance(node.value, ast.Name)
        and node.value.id in servers
    )
    aliases = any(
        isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
        and isinstance(node.value, ast.Name)
        and node.value.id in servers
        for node in nodes
    )
    return aliases or bool(candidates - handled)


def collect_python_tools(tree: ast.Module, source: str, path: Path, result: ScanResult) -> None:
    """Support direct SDK imports, module constructors and top-level decorators."""
    if not any(hint in source for hint in PYTHON_TOOL_HINTS):
        return
    nodes = list(islice(ast.walk(tree), 20_001))
    if len(nodes) > 20_000:
        result.surfaces_excluded.append(f"{path}: Python MCP AST limit exceeded")
        return
    imports = [node for node in nodes if isinstance(node, ast.ImportFrom) and not node.level]
    factories = {
        a.asname or a.name: stmt
        for stmt in imports
        for a in stmt.names
        if (stmt.module, a.name) in _FACTORIES
    }
    decorators = {
        a.asname or a.name: (stmt, _DECORATOR_IMPORTS[(stmt.module, a.name)])
        for stmt in imports
        for a in stmt.names
        if stmt.module is not None and (stmt.module, a.name) in _DECORATOR_IMPORTS
    }
    agent_factories = {
        a.asname or a.name: (stmt, _AGENT_FACTORIES[(stmt.module, a.name)])
        for stmt in imports
        for a in stmt.names
        if stmt.module is not None and (stmt.module, a.name) in _AGENT_FACTORIES
    }
    _report_import_scope(imports, nodes, path, result)
    if not factories and not decorators and not agent_factories:
        return
    if any(a.name == "*" for stmt in imports for a in stmt.names):
        result.surfaces_excluded.append(f"{path}: Python MCP bindings exceed supported scope")
        return

    bindings = _bindings(nodes)
    source_digest = hash_bytes(source.encode("utf-8"))
    seen_refs: set[str] = set()
    if decorators:
        _collect_sdk_decorators(
            tree, nodes, decorators, bindings, path, source_digest, seen_refs, result
        )
    if agent_factories:
        _collect_agent_decorators(
            tree, nodes, agent_factories, bindings, path, source_digest, seen_refs, result
        )
    if not factories:
        return
    top_level = set(tree.body)
    servers: dict[str, MCPServerComponent] = {}
    calls, changed_receivers = _factory_calls_and_rebinds(nodes, factories)
    if sum(isinstance(node, ast.Attribute) and node.attr == "tool" for node in nodes) > 1000:
        result.scan_failures.append(f"{path}: Python MCP tool registration limit exceeded")
        return
    handled: set[ast.AST] = set()
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            found = _server_from_assignment(
                stmt, calls, factories, top_level, bindings, changed_receivers, path
            )
            if found is None:
                continue
            call, server = found
            handled.add(call)
            servers[server.name] = server
            result.components.append(server)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _record_decorated_tools(stmt, servers, handled, path, source_digest, result)
    if _has_unsupported_registration(nodes, calls, handled, servers):
        result.surfaces_excluded.append(
            f"{path}: unsupported Python MCP binding or dynamic registration"
        )
