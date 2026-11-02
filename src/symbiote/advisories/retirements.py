"""Announced hosted-model retirements (``retirements.yaml``), matched like the BOM classifies model identifiers.

A reference is classified with :func:`symbiote.models_identity.hosted.classify_model_ref` (provider attribution
and routing-suffix stripping), then looked up among the entries of the same provider by its requested or base
identifier. No provider is contacted: the table is data shipped with symbiote, and each entry names its source
and a confidence level.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from functools import lru_cache
from importlib import resources
from typing import Any, Literal

import yaml

from symbiote.models_identity.hosted import classify_model_ref

__all__ = ["Retirement", "find_retirement", "load_retirements", "retirements_version"]

Confidence = Literal["high", "medium", "low"]


@dataclass(frozen=True, slots=True)
class Retirement:
    provider: str
    ids: tuple[str, ...]
    retires_on: date | None
    deprecated_on: date | None
    successor: str | None
    confidence: Confidence
    source: str

    def retired(self, now: datetime) -> bool:
        return self.retires_on is not None and now.date() >= self.retires_on

    def days_left(self, now: datetime) -> int | None:
        return None if self.retires_on is None else (self.retires_on - now.date()).days


def _date(value: object) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


def _entry(raw: dict[str, Any]) -> Retirement:
    confidence = str(raw.get("confidence", "low"))
    if confidence not in ("high", "medium", "low"):
        raise ValueError(f"retirements.yaml: bad confidence {confidence!r}")
    ids = tuple(str(i) for i in raw["ids"])
    if not ids or not raw.get("source"):
        raise ValueError("retirements.yaml: every entry needs ids and a source")
    successor = raw.get("successor")
    return Retirement(
        provider=str(raw["provider"]),
        ids=ids,
        retires_on=_date(raw.get("retires_on")),
        deprecated_on=_date(raw.get("deprecated_on")),
        successor=str(successor) if successor else None,
        confidence=confidence,  # type: ignore[arg-type]
        source=str(raw["source"]),
    )


@lru_cache(maxsize=1)
def _load() -> tuple[str, tuple[Retirement, ...]]:
    text = resources.files("symbiote.advisories").joinpath("retirements.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    return str(data.get("version", "")), tuple(_entry(e) for e in data.get("retirements") or ())


def load_retirements() -> tuple[Retirement, ...]:
    """Every entry of the shipped table."""
    return _load()[1]


def retirements_version() -> str:
    return _load()[0]


def find_retirement(
    ref: str, *, provider: str | None = None, endpoint: str | None = None
) -> Retirement | None:
    """The retirement entry for a hosted model reference, or ``None``.

    ``provider`` (a ``providers.yaml`` id) and ``endpoint`` help attribution exactly as in the BOM; an unknown
    provider (``"unknown"``) is ignored and the identifier's shape decides.
    """
    hosted = classify_model_ref(
        ref, provider=provider if provider and provider != "unknown" else None, endpoint=endpoint
    )
    if hosted.provider is None:
        return None
    candidates = {hosted.requested_ref, hosted.base_ref}
    for entry in load_retirements():
        if entry.provider == hosted.provider and candidates.intersection(entry.ids):
            return entry
    return None
