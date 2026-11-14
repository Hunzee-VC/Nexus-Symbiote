"""Collect literal Python SDK tool declarations without importing scanned code."""

from __future__ import annotations

import ast
import re
from collections import Counter
from collections.abc import Container
from pathlib import Path
from typing import NamedTuple
from urllib.parse import quote

from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import ClaimEvidence, MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.base import ScanResult

PYTHON_TOOL_HINTS = ("mcp", "langchain", "crewai", "function_tool", "smolagents", "pydantic_ai")


def _names(words: str) -> frozenset[str]:
    return frozenset(words.split())


_FACTORIES = {
    ("mcp.server", "FastMCP"),
    ("mcp.server.fastmcp", "FastMCP"),
    ("mcp.server.fastmcp.server", "FastMCP"),
    ("mcp.server.mcpserver", "MCPServer"),
    ("fastmcp", "FastMCP"),
    ("fastmcp.server", "FastMCP"),
    ("fastmcp.server.server", "FastMCP"),
}
_LOW_LEVEL = {
    ("mcp.server", "Server"),
    ("mcp.server.lowlevel", "Server"),
    ("mcp.server.lowlevel.server", "Server"),
}
# How a recognised server's name may be used without the server escaping the
# collector. A data attribute's value does not hold the server.
_SERVER_DATA = _names("name instructions settings")
# A run method or app factory may be called and its result used anywhere: the
# coroutine or app holds the server only where reflection reaches it. A method read
# without a call is a bound method that holds the server in __self__.
_SERVER_CALLS = _names(
    "run run_async run_stdio_async run_sse_async run_streamable_http_async run_http_async "
    "sse_app streamable_http_app http_app"
)
# Each returns a decorator that closes over the server, so only one applied directly
# to a function is followed.
_SERVER_DECORATORS = _names("resource prompt custom_route")
# Reflection that can reach a server or agent without naming it: these builtins
# called by name, getattr and its kin on an object that could be one, and these
# attributes, also imported by name, which expose frames, closures, namespaces and
# bound instances.
_REFLECTIVE_BUILTINS = _names("locals globals vars eval exec")
_ATTRIBUTE_BUILTINS = _names("getattr setattr delattr")
_REFLECTIVE_ATTRIBUTES = _names(
    "__self__ __closure__ __globals__ __builtins__ __dict__ __annotations__ __traceback__ "
    "__getattribute__ tb_frame tb_next f_back f_locals f_globals f_builtins gi_frame "
    "cr_frame ag_frame _getframe currentframe getouterframes getinnerframes getargvalues "
    "getclosurevars"
)
# Generics whose subscript only records its arguments as types.
_TYPING_MODULES = frozenset({"typing", "typing_extensions", "collections.abc"})
_GENERIC_BUILTINS = _names("dict frozenset list set tuple type")


def _decorates(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    owner = parents.get(node)
    return isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
        node in owner.decorator_list
    )


def _safe_use(
    name: ast.Name,
    parents: dict[ast.AST, ast.AST],
    data: frozenset[str],
    calls: frozenset[str],
    decorators: frozenset[str],
) -> bool:
    """Whether ``name`` is only read for an attribute in ``data``, called for a method
    in ``calls`` or applied directly as a decorator in ``decorators``.

    A method read and discarded is safe too. Stored, passed or dereferenced, it hands
    out the receiver through ``__self__`` or a closure.
    """
    attribute = parents.get(name)
    if not isinstance(attribute, ast.Attribute) or not isinstance(attribute.ctx, ast.Load):
        return False
    use = parents.get(attribute)
    call = use if isinstance(use, ast.Call) and use.func is attribute else None
    if attribute.attr in data or (attribute.attr in calls and call is not None):
        return True
    if attribute.attr not in calls and attribute.attr not in decorators:
        return False
    return isinstance(use, ast.Expr) or (
        attribute.attr in decorators and _decorates(call or attribute, parents)
    )


def _safe_receivers(
    nodes: list[ast.AST],
    parents: dict[ast.AST, ast.AST],
    receivers: Container[str],
    data: frozenset[str],
    calls: frozenset[str],
    decorators: frozenset[str],
) -> set[ast.AST]:
    return {
        node
        for node in nodes
        if isinstance(node, ast.Name)
        and node.id in receivers
        and _safe_use(node, parents, data, calls, decorators)
    }


def _plain_attribute(call: ast.Call, imported: set[str]) -> bool:
    """Whether getattr, setattr or delattr names a literal attribute, not a reflective
    one, of an object that cannot be a server or agent of this file.

    Such an object is a literal, or a name, or attribute of a name, that the file binds
    only by import. Anything else, such as a parameter, ``self`` or a call's result,
    could be one.
    """
    if call.keywords or len(call.args) < 2 or any(isinstance(a, ast.Starred) for a in call.args):
        return False
    target, attribute = call.args[0], call.args[1]
    if not (
        isinstance(attribute, ast.Constant)
        and isinstance(attribute.value, str)
        and attribute.value not in _REFLECTIVE_ATTRIBUTES
        and attribute.value != "modules"
    ):
        return False
    while isinstance(target, ast.Attribute):
        target = target.value
    return isinstance(target, ast.Constant) or (
        isinstance(target, ast.Name) and target.id in imported
    )


def _reflective_access(
    nodes: list[ast.AST], parents: dict[ast.AST, ast.AST], bindings: Counter[str]
) -> bool:
    """Whether reflection can reach a server or agent of the file without naming it.

    The builtins count when called by their own names and through the builtins
    module; a method that only shares a name, such as ``model.eval()``, does not.
    ``modules`` counts unless it is called, so ``sys.modules[__name__]`` does and
    ``model.modules()`` does not.
    """
    imports = Counter(
        node.asname or node.name.split(".")[0] for node in nodes if isinstance(node, ast.alias)
    )
    imported = {name for name, count in imports.items() if bindings[name] == count}
    for node in nodes:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _REFLECTIVE_BUILTINS or (
                node.func.id in _ATTRIBUTE_BUILTINS and not _plain_attribute(node, imported)
            ):
                return True
        elif isinstance(node, ast.Attribute):
            use = parents.get(node)
            if node.attr in _REFLECTIVE_ATTRIBUTES or (
                node.attr == "modules" and not (isinstance(use, ast.Call) and use.func is node)
            ):
                return True
        elif isinstance(node, ast.Name) and node.id == "__builtins__":
            return True
        elif isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] == "builtins" for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom) and not node.level:
            if node.module == "builtins" or any(
                alias.name in _REFLECTIVE_ATTRIBUTES
                or (node.module == "sys" and alias.name == "modules")
                for alias in node.names
            ):
                return True
    return False


# Constructor keywords that carry tools, or could, are registrations the
# collector does not resolve.
_REGISTERING_KEYWORDS = frozenset({"tools", "tool_serializer", "providers", "mount"})

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
# Agent constructor keywords that carry tools, or could.
_AGENT_REGISTERING_KEYWORDS = frozenset({"tools", "toolsets", "builtin_tools", "mcp_servers"})
# How a recognised agent's name may be used without the agent escaping, as for a
# server: a run's result holds the agent only where reflection reaches it.
_AGENT_DATA = _names("name")
_AGENT_CALLS = _names("run run_sync run_stream iter")
_AGENT_DECORATORS = _names("system_prompt instructions output_validator")


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
    deco: ast.Call | ast.Attribute,
    default_name: str,
    server: MCPServerComponent,
    path: Path,
    source_digest: str,
    result: ScanResult,
) -> None:
    keywords = deco.keywords if isinstance(deco, ast.Call) else []
    options = {kw.arg: kw.value for kw in keywords}
    name: object = default_name
    if "name" in options:
        value = options["name"]
        name = value.value if isinstance(value, ast.Constant) else None
    if (
        (isinstance(deco, ast.Call) and deco.args)
        or len(options) != len(keywords)
        or None in options
        or not isinstance(name, str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
    ):
        result.surfaces_excluded.append(
            f"{path.as_posix()}:{deco.lineno}: unresolved Python MCP tool name"
        )
        return
    ref = f"tool:{server.bom_ref}/{name}"
    if ref in server.tool_refs:
        result.scan_failures.append(
            f"{path.as_posix()}:{deco.lineno}: duplicate Python MCP tool declaration"
        )
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
    owner: str | None = None,
) -> None:
    """Record one decorated tool; ``owner`` names the agent it is registered on."""
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
            result.surfaces_excluded.append(
                f"{path.as_posix()}:{lineno}: unresolved Python SDK tool name"
            )
            return
        if len(deco.args) == 1:
            arg = deco.args[0]
            name = arg.value if isinstance(arg, ast.Constant) else None
        elif name_keys:
            val = options[name_keys[0]]
            name = val.value if isinstance(val, ast.Constant) else None
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
        result.surfaces_excluded.append(
            f"{path.as_posix()}:{lineno}: unresolved Python SDK tool name"
        )
        return
    scope = quote(path.as_posix(), safe="") + (f"/{owner}" if owner else "")
    ref = f"tool:python:{scope}/{name}"
    if ref in seen_refs:
        result.scan_failures.append(
            f"{path.as_posix()}:{lineno}: duplicate Python SDK tool declaration"
        )
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
        result.scan_failures.append(
            f"{path.as_posix()}: Python SDK tool registration limit exceeded"
        )
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
            f"{path.as_posix()}: unsupported Python SDK tool binding or dynamic registration"
        )


def _collect_agent_decorators(
    tree: ast.Module,
    nodes: list[ast.AST],
    parents: dict[ast.AST, ast.AST],
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
        result.scan_failures.append(
            f"{path.as_posix()}: Python SDK tool registration limit exceeded"
        )
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
                or any(isinstance(arg, ast.Starred) for arg in call.args)
                or any(
                    kw.arg is None or kw.arg in _AGENT_REGISTERING_KEYWORDS for kw in call.keywords
                )
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
                        deco,
                        stmt.name,
                        framework,
                        path,
                        source_digest,
                        seen_refs,
                        result,
                        deco.value.id,
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
                        deco,
                        stmt.name,
                        framework,
                        path,
                        source_digest,
                        seen_refs,
                        result,
                        deco.func.value.id,
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
    # An agent used other than through a handled decorator, a read, run or decorator
    # that _safe_use accepts, or a `with` statement without `as`, such as aliased,
    # passed to a function or held in a list, can be given tools elsewhere.
    reached: set[ast.AST] = {node.value for node in handled if isinstance(node, ast.Attribute)}
    reached |= _safe_receivers(nodes, parents, agents, _AGENT_DATA, _AGENT_CALLS, _AGENT_DECORATORS)
    reached.update(
        node.context_expr
        for node in nodes
        if isinstance(node, ast.withitem) and node.optional_vars is None
    )
    escaped = any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id in agents
        and node not in reached
        for node in nodes
    )
    if (
        unsupported_factory
        or escaped
        or (candidates - handled)
        or (agents and _reflective_access(nodes, parents, bindings))
    ):
        result.surfaces_excluded.append(
            f"{path.as_posix()}: unsupported Python SDK tool binding or dynamic registration"
        )


def _report_import_scope(
    imports: list[ast.ImportFrom], nodes: list[ast.AST], path: Path, result: ScanResult
) -> None:
    if any((stmt.module, a.name) in _LOW_LEVEL for stmt in imports for a in stmt.names):
        result.surfaces_excluded.append(
            f"{path.as_posix()}: low-level MCP server tool list uncollected"
        )
    modules = {module for module, _ in _FACTORIES}
    qualified_import = any(
        isinstance(node, ast.Import) and any(a.name in modules for a in node.names)
        for node in nodes
    )
    if qualified_import or any(
        stmt.module in modules and any(a.name == "*" for a in stmt.names) for stmt in imports
    ):
        result.surfaces_excluded.append(f"{path.as_posix()}: unresolved Python MCP factory import")
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
        result.surfaces_excluded.append(f"{path.as_posix()}: unresolved Python SDK tool import")


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
    source_digest: str,
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
        or any(isinstance(arg, ast.Starred) for arg in call.args)
        or any(kw.arg is None or kw.arg in _REGISTERING_KEYWORDS for kw in call.keywords)
    ):
        return None
    # The variable is bound once in this file, so path and name identify the
    # server; the line is informational and moving it is not a new server.
    server = MCPServerComponent(
        bom_ref=f"mcp-python:{quote(path.as_posix(), safe='')}:{target.id}",
        name=target.id,
        source_path=path.as_posix(),
        properties={
            "method": "python-ast",
            "collection_mode": "static-source-declaration",
            "runtime_registration": "unknown",
            "declaration_line": stmt.lineno,
            "source_sha256": source_digest,
        },
    )
    return call, server


def _tool_decorator(deco: ast.expr) -> tuple[str, ast.Call | ast.Attribute] | None:
    """The receiver name of ``@name.tool(...)`` or ``@name.tool``."""
    target = deco.func if isinstance(deco, ast.Call) else deco
    if (
        isinstance(target, ast.Attribute)
        and target.attr == "tool"
        and isinstance(target.value, ast.Name)
    ):
        return target.value.id, deco if isinstance(deco, ast.Call) else target
    return None


def _record_decorated_tools(
    stmt: ast.FunctionDef | ast.AsyncFunctionDef,
    servers: dict[str, MCPServerComponent],
    handled: set[ast.AST],
    path: Path,
    source_digest: str,
    result: ScanResult,
) -> None:
    for deco in stmt.decorator_list:
        found = _tool_decorator(deco)
        if found is None or found[0] not in servers:
            continue
        receiver, node = found
        attribute = node.func if isinstance(node, ast.Call) else node
        if isinstance(attribute, ast.Attribute):
            handled.update((attribute, attribute.value))
        _record_decorator(node, stmt.name, servers[receiver], path, source_digest, result)


class _Helper(NamedTuple):
    """How a call binds a top-level function's parameters, and the parameters it uses
    unsafely: any use a server's name could not have at the top level, and any use in a
    nested scope, which closes over the parameter."""

    positional: tuple[str, ...]
    named: frozenset[str]
    unsafe: frozenset[str]


_SCOPES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.ClassDef,
    ast.GeneratorExp,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
)


def _helper(
    function: ast.FunctionDef | ast.AsyncFunctionDef, parents: dict[ast.AST, ast.AST]
) -> _Helper:
    positional = tuple(arg.arg for arg in (*function.args.posonlyargs, *function.args.args))
    named = frozenset({*positional, *(arg.arg for arg in function.args.kwonlyargs)})
    unsafe: set[str] = set()
    pending: list[tuple[ast.AST, bool]] = [(n, False) for n in ast.iter_child_nodes(function)]
    while pending:
        node, nested = pending.pop()
        if (
            isinstance(node, ast.Name)
            and node.id in named
            and (
                nested
                or not isinstance(node.ctx, ast.Load)
                or not _safe_use(node, parents, _SERVER_DATA, _SERVER_CALLS, _SERVER_DECORATORS)
            )
        ):
            unsafe.add(node.id)
        nested = nested or isinstance(node, _SCOPES)
        pending.extend((child, nested) for child in ast.iter_child_nodes(node))
    return _Helper(positional, named, frozenset(unsafe))


def _benign_helper_arguments(
    tree: ast.Module,
    nodes: list[ast.AST],
    parents: dict[ast.AST, ast.AST],
    servers: dict[str, MCPServerComponent],
    bindings: Counter[str],
) -> set[ast.AST]:
    """Servers passed to a helper of this file that registers nothing on them and keeps
    no reference to them.

    Only an undecorated function whose name the file binds once is read, since a
    call can otherwise reach another definition or what a decorator returned. Each
    helper is read once, however many calls pass it a server, so the work stays
    linear in the size of the file.
    """
    functions = {
        stmt.name: stmt
        for stmt in tree.body
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not stmt.decorator_list
        and bindings[stmt.name] == 1
    }
    helpers: dict[str, _Helper] = {}
    benign: set[ast.AST] = set()
    for node in nodes:
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        function = functions.get(node.func.id)
        if function is None or not any(
            isinstance(value, ast.Name) and value.id in servers
            for value in (*node.args, *(keyword.value for keyword in node.keywords))
        ):
            continue
        helper = helpers.get(function.name)
        if helper is None:
            helper = helpers[function.name] = _helper(function, parents)
        passed = [
            (helper.positional[index] if index < len(helper.positional) else None, value)
            for index, value in enumerate(node.args)
        ] + [
            (keyword.arg if keyword.arg in helper.named else None, keyword.value)
            for keyword in node.keywords
        ]
        for parameter, value in passed:
            if (
                isinstance(value, ast.Name)
                and value.id in servers
                and parameter is not None
                and parameter not in helper.unsafe
            ):
                benign.add(value)
    return benign


def _chain(node: ast.expr) -> list[ast.AST] | None:
    """The nodes of a name, or of attributes of a name, the name last."""
    chain: list[ast.AST] = []
    while isinstance(node, ast.Attribute):
        chain.append(node)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    chain.append(node)
    return chain


def _typing_generics(nodes: list[ast.AST]) -> tuple[set[str], dict[str, str]]:
    """Names the file binds only to a typing generic or leaves to a built-in generic,
    and names it binds only to one module, with that module."""
    bindings = _bindings(nodes)
    generics: Counter[str] = Counter()
    modules: dict[str, list[str]] = {}
    for node in nodes:
        if isinstance(node, ast.ImportFrom) and not node.level and node.module in _TYPING_MODULES:
            generics.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                modules.setdefault(name, []).append(alias.name if alias.asname else name)
    names = {name for name, count in generics.items() if bindings[name] == count}
    names.update(name for name in _GENERIC_BUILTINS if not bindings[name])
    roots = {
        name: paths[0]
        for name, paths in modules.items()
        if bindings[name] == len(paths) and len(set(paths)) == 1
    }
    return names, roots


def _generic(node: ast.expr, names: set[str], roots: dict[str, str]) -> bool:
    """Whether ``node`` is a generic whose subscript only records types."""
    attributes: list[str] = []
    while isinstance(node, ast.Attribute):
        attributes.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return False
    if not attributes:
        return node.id in names
    if node.id not in roots:
        return False
    module = ".".join((roots[node.id], *reversed(attributes))).rpartition(".")[0]
    return module in _TYPING_MODULES


def _annotation_names(nodes: list[ast.AST]) -> set[ast.AST]:
    """Names, and attributes of names, that annotations use only as types.

    Annotations are evaluated, at definition time or later, so only these parts are
    set aside: the whole annotation, a member of a ``|`` union, and an argument of a
    generic of ``typing``, ``typing_extensions`` or ``collections.abc``, such as
    ``Optional[...]``, or of a built-in generic such as ``list[...]``. A call, any
    other subscript and every other expression in an annotation is analyzed as code.
    """
    names, roots = _typing_generics(nodes)
    pending: list[ast.expr] = []
    for node in nodes:
        if isinstance(node, ast.arg) and node.annotation is not None:
            pending.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns:
            pending.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            pending.append(node.annotation)
    found: set[ast.AST] = set()
    while pending:
        annotation = pending.pop()
        chain = _chain(annotation)
        if chain is not None:
            found.update(chain)
        elif isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
            pending += (annotation.left, annotation.right)
        elif isinstance(annotation, (ast.Tuple, ast.List)):
            pending += annotation.elts
        elif isinstance(annotation, ast.Subscript) and _generic(annotation.value, names, roots):
            found.update(_chain(annotation.value) or ())
            pending.append(annotation.slice)
    return found


def _has_unsupported_registration(
    tree: ast.Module,
    nodes: list[ast.AST],
    parents: dict[ast.AST, ast.AST],
    calls: set[ast.Call],
    handled: set[ast.AST],
    servers: dict[str, MCPServerComponent],
    factories: dict[str, ast.ImportFrom],
    bindings: Counter[str],
) -> bool:
    """Whether a recognised server or factory escapes the supported forms."""
    if calls - handled or (servers and _reflective_access(nodes, parents, bindings)):
        return True
    factory_calls = {call.func for call in calls}
    # A server named in an annotation is exposed through __annotations__.
    safe = {
        node
        for node in _annotation_names(nodes)
        if not (isinstance(node, ast.Name) and node.id in servers)
    }
    safe |= _safe_receivers(
        nodes, parents, servers, _SERVER_DATA, _SERVER_CALLS, _SERVER_DECORATORS
    )
    safe |= _benign_helper_arguments(tree, nodes, parents, servers, bindings)
    for node in nodes:
        if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load) or node in safe:
            continue
        if node.id in servers and node not in handled:
            return True
        if node.id in factories and node not in factory_calls:
            return True
    return False


def _imported_receivers(tree: ast.Module) -> bool:
    """A ``.tool`` decorator whose receiver, or its root module, is bound by an import."""
    imported = {
        (alias.asname or alias.name).split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            target = deco.func if isinstance(deco, ast.Call) else deco
            if not isinstance(target, ast.Attribute) or target.attr != "tool":
                continue
            root = target.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in imported:
                return True
    return False


def _report_imported_receivers(tree: ast.Module, path: Path, result: ScanResult) -> None:
    """A file without a recognised server factory may still register tools on an imported one."""
    if _imported_receivers(tree):
        result.surfaces_excluded.append(
            f"{path.as_posix()}: Python MCP tools registered on an imported server"
        )


def _report_unused_factories(
    nodes: list[ast.AST], factories: dict[str, ast.ImportFrom], path: Path, result: ScanResult
) -> None:
    """A server class imported and not used other than as a type in an annotation is
    passed on.

    Another module can import it from this one and build servers the collector does
    not see there, because that import does not name the SDK.
    """
    if not factories:
        return
    annotations = _annotation_names(nodes)
    used = {
        node.id
        for node in nodes
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node not in annotations
    }
    if set(factories) - used:
        result.surfaces_excluded.append(
            f"{path.as_posix()}: MCP server class imported without a use here; servers built "
            "from it elsewhere not inventoried"
        )


def collect_python_tools(
    tree: ast.Module, nodes: list[ast.AST], source: str, path: Path, result: ScanResult
) -> None:
    """Support direct SDK imports, module constructors and top-level decorators.

    ``nodes`` holds every node of ``tree``; the caller holds their number to the
    ``python-nodes`` limit, and the work here is linear in it.
    """
    if not any(hint in source for hint in PYTHON_TOOL_HINTS):
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
    _report_unused_factories(nodes, factories, path, result)
    if not factories and not decorators and not agent_factories:
        _report_imported_receivers(tree, path, result)
        return
    if any(a.name == "*" for stmt in imports for a in stmt.names):
        result.surfaces_excluded.append(
            f"{path.as_posix()}: Python MCP bindings exceed supported scope"
        )
        return

    bindings = _bindings(nodes)
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    source_digest = hash_bytes(source.encode("utf-8"))
    seen_refs: set[str] = set()
    if decorators:
        _collect_sdk_decorators(
            tree, nodes, decorators, bindings, path, source_digest, seen_refs, result
        )
    if agent_factories:
        _collect_agent_decorators(
            tree,
            nodes,
            parents,
            agent_factories,
            bindings,
            path,
            source_digest,
            seen_refs,
            result,
        )
    if not factories:
        _report_imported_receivers(tree, path, result)
        return
    top_level = set(tree.body)
    servers: dict[str, MCPServerComponent] = {}
    calls, changed_receivers = _factory_calls_and_rebinds(nodes, factories)
    if sum(isinstance(node, ast.Attribute) and node.attr == "tool" for node in nodes) > 1000:
        result.scan_failures.append(
            f"{path.as_posix()}: Python MCP tool registration limit exceeded"
        )
        return
    handled: set[ast.AST] = set()
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            found = _server_from_assignment(
                stmt,
                calls,
                factories,
                top_level,
                bindings,
                changed_receivers,
                path,
                source_digest,
            )
            if found is None:
                continue
            call, server = found
            handled.add(call)
            handled.add(stmt.targets[0])
            servers[server.name] = server
            result.components.append(server)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _record_decorated_tools(stmt, servers, handled, path, source_digest, result)
    if _has_unsupported_registration(
        tree, nodes, parents, calls, handled, servers, factories, bindings
    ) or _imported_receivers(tree):
        result.surfaces_excluded.append(
            f"{path.as_posix()}: unsupported Python MCP binding or dynamic registration"
        )
