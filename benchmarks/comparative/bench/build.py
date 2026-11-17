"""Helpers the case catalogs share: expectation constructors, text encoders and controls."""

from __future__ import annotations

import base64
import json
import textwrap
from collections.abc import Sequence

from .model import Attr, Case, Decoy, Domain, Edge, Expect, Files

ML_MODEL = "machine-learning-model"
DATA = "data"
# A valid 1x1 PNG. An image is the binary control because no model, dataset or
# configuration format shares its extension or its signature.
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg=="
)


def text(value: str) -> bytes:
    """Dedent a literal and end it with exactly one newline."""
    return (textwrap.dedent(value).strip("\n") + "\n").encode()


def as_json(value: object) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode()


def ver(value: str) -> Attr:
    return Attr("version", "version", (value,))


def purl(value: str) -> Attr:
    return Attr("package URL", "purl", (value,))


def sha(path: str) -> Attr:
    return Attr("SHA-256 of the file", "sha256", (path,))


def loc(path: str) -> Attr:
    return Attr("source location", "location", (path,))


def lic(value: str) -> Attr:
    return Attr("license", "license", (value,))


def typ(*values: str) -> Attr:
    return Attr("CycloneDX type", "type", values)


def has(label: str, *tokens: str) -> Attr:
    return Attr(label, "text", tokens)


def ex(
    expect_id: str,
    domain: Domain,
    kind: str,
    *groups: str | Sequence[str],
    attrs: Sequence[Attr] = (),
) -> Expect:
    token_groups = tuple((group,) if isinstance(group, str) else tuple(group) for group in groups)
    return Expect(expect_id, domain, kind, token_groups, tuple(attrs))


def edge(source: str, target: str, relation: str) -> Edge:
    return Edge(source, target, relation)


def decoy(decoy_id: str, token: str, paired: str, why: str) -> Decoy:
    return Decoy(decoy_id, (token,), paired, why)


def control_tokens(key: str) -> tuple[str, ...]:
    slug = key.lower()
    return (
        f"ctrl-notes-{slug}",
        f"ctrl-settings-{slug}",
        f"ctrl-logo-{slug}",
        f"ctrl_util_{slug.replace('-', '_')}",
    )


def control_files(key: str) -> Files:
    """Files with no AI content, added to every case.

    A tool that lists them shows how it renders an arbitrary file. A component it
    renders the same way has been listed, not recognized.
    """
    notes, settings, logo, module = control_tokens(key)
    return {
        f"docs/{notes}.md": text(
            """
            # Release checklist

            1. Update the changelog.
            2. Tag the release.
            """
        ),
        f"config/{settings}.json": as_json({"theme": "dark", "retries": 3, "page_size": 50}),
        f"assets/{logo}.png": PNG,
        f"src/{module}.py": text(
            """
            def clamp(value: int, low: int, high: int) -> int:
                return max(low, min(value, high))
            """
        ),
    }


def case(
    case_id: str,
    title: str,
    files: Files,
    expects: Sequence[Expect] = (),
    *,
    edges: Sequence[Edge] = (),
    decoys: Sequence[Decoy] = (),
    surface: str = "",
    sources: Sequence[str] = (),
    symlinks: dict[str, str] | None = None,
    fifos: Sequence[str] = (),
    executable: Sequence[str] = (),
    home_scope: bool = False,
    control_key: str | None = None,
) -> Case:
    merged = dict(files)
    merged.update(control_files(control_key or case_id))
    return Case(
        id=case_id,
        title=title,
        files=merged,
        expects=tuple(expects),
        edges=tuple(edges),
        decoys=tuple(decoys),
        symlinks=dict(symlinks or {}),
        fifos=tuple(fifos),
        executable=tuple(executable),
        home_scope=home_scope,
        surface=surface,
        sources=tuple(sources),
    )
