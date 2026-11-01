"""Typed edges between entities (``spec/agentbom-profile.md §4``)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from symbiote.model.base import SymbioteModel
from symbiote.model.common import EntityId, EvidenceRef, Validity
from symbiote.model.enums import AssuranceLevel, EdgeScope, EdgeType


class Edge(SymbioteModel):
    type: EdgeType
    from_ref: EntityId = Field(alias="from")
    to_ref: EntityId = Field(alias="to")
    scope: EdgeScope = EdgeScope.RUNTIME
    qualifiers: dict[str, Any] = Field(default_factory=dict)
    assurance: AssuranceLevel = AssuranceLevel.DECLARED
    validity: Validity | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)
    observed_count: int | None = Field(default=None, ge=0)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    declared_by: str | None = None

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.type.value, self.from_ref, self.to_ref)


__all__ = ["Edge"]
