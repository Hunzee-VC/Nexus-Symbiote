"""Base classes shared by every model type.

All AgentBOM entities are immutable Pydantic v2 models that reject unknown fields (``extra="forbid"``) and
serialise with camelCase aliases (the companion document convention, ``spec/companion.md``). Python code uses
snake_case attribute names.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class SymbioteModel(BaseModel):
    """Frozen, strict base model with camelCase JSON aliases."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        alias_generator=to_camel,
        validate_default=True,
        str_strip_whitespace=False,
        ser_json_bytes="base64",
        use_enum_values=False,
    )

    def to_json_dict(self, *, exclude_none: bool = True) -> dict[str, Any]:
        """Return the companion-document JSON form (camelCase keys, enums as values)."""
        return self.model_dump(mode="json", by_alias=True, exclude_none=exclude_none)

    def replace(self, **changes: Any) -> Any:
        """Return a validated copy with ``changes`` applied (models are frozen; validators re-run)."""
        data = self.model_dump(mode="python", by_alias=False)
        data.update(changes)
        return self.__class__.model_validate(data)
