"""Compile a disjoint SPDX class union without changing its accepted instances.

The original schema remains the fallback. A fast path is permitted only when
all alternatives necessarily require an object with a unique literal ``type``.
Leaf validators are the exact official alternatives, including their references.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any
from urllib.parse import unquote

# Structural JSON digest of the pinned, unmodified SPDX 3.0.1 schema. A vendor
# update requires explicit review; unsupported content keeps official validation.
_PINNED_SCHEMA_DIGEST = "862ea1a210fd3df4072bea752cfd6fb95f13418da7a2a5638eade5c5d4c9b51d"

_SCOPE_KEYS = frozenset(
    {"$id", "$anchor", "$dynamicAnchor", "$dynamicRef", "$recursiveRef", "$recursiveAnchor"}
)


def _unscoped(value: Any) -> bool:
    if isinstance(value, dict):
        ref = value.get("$ref")
        if ref is not None and (
            not isinstance(ref, str) or unquote(ref).startswith("#/$defs/AnyClass/")
        ):
            # The original union's interior paths must not disappear underneath
            # another constraint. Whole-union references retain their meaning.
            return False
        return not _SCOPE_KEYS.intersection(value) and all(_unscoped(v) for v in value.values())
    if isinstance(value, list):
        return all(_unscoped(v) for v in value)
    return True


def _local_ref(root: dict[str, Any], ref: Any) -> Any:
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise ValueError("nonlocal schema reference")
    value: Any = root
    for token in ref[2:].split("/"):
        value = value[token.replace("~1", "/").replace("~0", "~")]
    return value


def _conjuncts(
    root: dict[str, Any], schema: Any, active: frozenset[str] = frozenset(), depth: int = 0
) -> list[dict[str, Any]]:
    if depth > 64 or not isinstance(schema, dict):
        raise ValueError("unsupported schema proof")
    nodes = [schema]
    if "$ref" in schema:
        ref = schema["$ref"]
        if not isinstance(ref, str) or ref in active:
            raise ValueError("cyclic schema reference")
        nodes.extend(_conjuncts(root, _local_ref(root, ref), active | {ref}, depth + 1))
    if "allOf" in schema:
        children = schema["allOf"]
        if not isinstance(children, list):
            raise ValueError("invalid conjunction")
        for child in children:
            nodes.extend(_conjuncts(root, child, active, depth + 1))
    # A union with exactly one alternative is a conjunction. Multiple
    # alternatives never establish a mandatory discriminator constraint.
    for key in ("oneOf", "anyOf"):
        children = schema.get(key)
        if isinstance(children, list) and len(children) == 1:
            nodes.extend(_conjuncts(root, children[0], active, depth + 1))
    return nodes


def _tag(root: dict[str, Any], branch: dict[str, Any]) -> str | None:
    nodes = _conjuncts(root, branch)
    if not any(node.get("type") == "object" for node in nodes):
        return None
    if not any(
        isinstance(node.get("required"), list) and "type" in node["required"] for node in nodes
    ):
        return None
    tags: set[str] = set()
    for node in nodes:
        properties = node.get("properties")
        if not isinstance(properties, dict) or "type" not in properties:
            continue
        for constraint in _conjuncts(root, properties["type"]):
            literal = constraint.get("const")
            if isinstance(literal, str):
                tags.add(literal)
            values = constraint.get("enum")
            if isinstance(values, list) and len(values) == 1 and isinstance(values[0], str):
                tags.add(values[0])
    return next(iter(tags)) if len(tags) == 1 else None


def _guard(tags: list[str]) -> dict[str, Any]:
    return {"type": "object", "required": ["type"], "properties": {"type": {"enum": tags}}}


def _tree(branches: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    if len(branches) == 1:
        return branches[0][1]
    middle = len(branches) // 2
    left, right = branches[:middle], branches[middle:]
    return {"if": _guard([tag for tag, _ in left]), "then": _tree(left), "else": _tree(right)}


def dispatched_spdx_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Return an equivalent class dispatch, or the unmodified official schema.

    For an accepted known tag, every other branch is impossible and its
    annotations are absent. The selected branch already evaluates ``type``;
    guard annotations therefore add no evaluated property. Invalid selected
    branches still fail. Unknown tags and all unsupported schema shapes use the
    original union, preserving its behavior rather than assuming a new format.
    """
    try:
        digest = hashlib.sha256(
            json.dumps(schema, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        if digest != _PINNED_SCHEMA_DIGEST or not _unscoped(schema):
            return schema
        union = schema["$defs"]["AnyClass"]
        if not isinstance(union, dict) or set(union) != {"anyOf"}:
            return schema
        alternatives = union["anyOf"]
        if not isinstance(alternatives, list) or not 2 <= len(alternatives) <= 512:
            return schema
        branches: list[tuple[str, dict[str, Any]]] = []
        for branch in alternatives:
            tag = _tag(schema, branch)
            if tag is None:
                return schema
            branches.append((tag, branch))
        tags = [tag for tag, _ in branches]
        if len(set(tags)) != len(tags):
            return schema
    except (KeyError, TypeError, ValueError, RecursionError):
        return schema
    result = deepcopy(schema)
    copied_union = result["$defs"]["AnyClass"]
    # Retain the exact original branches and all root/reference constraints.
    # The copied reference targets remain identical JSON structures.
    original = {"anyOf": copied_union.pop("anyOf")}
    copied_union.update({"if": _guard(tags), "then": _tree(deepcopy(branches)), "else": original})
    return result
