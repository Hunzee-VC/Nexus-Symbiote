"""Data model of the corpus: cases, expected components, decoys, risk pairs and mutations."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

Domain = Literal["model", "data", "tool", "agent", "platform"]
DOMAINS: tuple[Domain, ...] = ("model", "data", "tool", "agent", "platform")
AttrKind = Literal["version", "purl", "sha256", "text", "type", "license", "location"]

# Every scan runs with these paths, whatever the host directory, so that no output
# depends on where the corpus was materialized.
SANDBOX = "/mnt/bench"
CASE_DIR = f"{SANDBOX}/case"
RELOCATED_CASE_DIR = f"{SANDBOX}/elsewhere/checkout/case"
HOME_DIR = f"{SANDBOX}/home"
OUT_DIR = f"{SANDBOX}/out"
CANARY_DIR = f"{SANDBOX}/canary"
OUTSIDE_DIR = f"{SANDBOX}/outside"

Files = dict[str, bytes]
Apply = Callable[[Files], Files]


@dataclass(frozen=True)
class Attr:
    """One attribute the BOM element of an expected component should carry."""

    label: str
    kind: AttrKind
    values: tuple[str, ...]


@dataclass(frozen=True)
class Expect:
    """A component that is present in a case.

    ``any_of`` holds token groups. A BOM element matches when every token of at
    least one group occurs in it, ignoring case.
    """

    id: str
    domain: Domain
    kind: str
    any_of: tuple[tuple[str, ...], ...]
    attrs: tuple[Attr, ...] = ()


@dataclass(frozen=True)
class Edge:
    """A relationship between two expected components of one case."""

    source: str
    target: str
    relation: str


@dataclass(frozen=True)
class Decoy:
    """Text that looks like a component and is not one.

    ``paired`` names an expected component of the same surface in the same case. A
    decoy counts as rejected only when that component was found, so a tool that does
    not read the surface earns nothing.
    """

    id: str
    tokens: tuple[str, ...]
    paired: str
    why: str


@dataclass(frozen=True)
class Case:
    id: str
    title: str
    files: Files
    expects: tuple[Expect, ...] = ()
    edges: tuple[Edge, ...] = ()
    decoys: tuple[Decoy, ...] = ()
    symlinks: dict[str, str] = field(default_factory=dict)
    fifos: tuple[str, ...] = ()
    executable: tuple[str, ...] = ()
    home_scope: bool = False
    surface: str = ""
    sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class RiskPair:
    """Two cases that differ only in one risky condition."""

    id: str
    klass: str
    title: str
    clean: Case
    risky: Case
    references: tuple[str, ...] = ()


HostileCheck = Literal[
    "completes",
    "no_execution",
    "no_escape",
    "no_secret_disclosure",
    "no_terminal_escape",
    "bounded_memory",
    "reports_gap",
    "not_steered",
]


@dataclass(frozen=True)
class Hostile:
    """A case built to misuse the scanner.

    ``survivor`` names expected components next to the hostile input. A tool is
    engaged with the case when it finds one of them; safety is scored only then.
    """

    case: Case
    checks: tuple[HostileCheck, ...]
    klass: str
    gap_paths: tuple[str, ...] = ()
    twin: Case | None = None
    cwe: tuple[str, ...] = ()


@dataclass(frozen=True)
class Mutation:
    """A supply-chain relevant change to one discovery case."""

    id: str
    base: str
    title: str
    apply: Apply
    binds: str


@dataclass(frozen=True)
class Corpus:
    discovery: tuple[Case, ...]
    risk: tuple[RiskPair, ...]
    hostile: tuple[Hostile, ...]
    mutations: tuple[Mutation, ...]
    outside: Files

    def case(self, case_id: str) -> Case:
        for case in self.all_cases():
            if case.id == case_id:
                return case
        raise KeyError(case_id)

    def all_cases(self) -> list[Case]:
        cases = list(self.discovery)
        for pair in self.risk:
            cases += [pair.clean, pair.risky]
        for hostile in self.hostile:
            cases.append(hostile.case)
            if hostile.twin is not None:
                cases.append(hostile.twin)
        return cases
