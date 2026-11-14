"""`Generator.save` writes as every other output does, and exports hold no bare NaN.

`AIBOM.save` replaces its destination atomically and never writes through a symbolic
link. `Generator.save` called `Path.write_text`, which follows one, so saving an export
to a path where a checkout had planted a link overwrote the link's target.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import nexus_symbiote.generators as generators
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import PromptComponent
from nexus_symbiote.generators import (
    CycloneDXGenerator,
    ExportResult,
    Generator,
    SARIFGenerator,
    SPDXGenerator,
    VEXGenerator,
)

EXPORTERS = [CycloneDXGenerator, SPDXGenerator, SARIFGenerator, VEXGenerator]


def _bom() -> AIBOM:
    return AIBOM(components=[PromptComponent(bom_ref="prompt:system", name="system")])


@pytest.mark.parametrize("exporter", EXPORTERS)
def test_save_does_not_write_through_a_symbolic_link(tmp_path, exporter):
    kept = tmp_path / "kept.txt"
    kept.write_text("keep me", encoding="utf-8")
    output = tmp_path / "export.json"
    output.symlink_to(kept)
    try:
        exporter().save(_bom(), output)
    except OSError:
        pass
    assert kept.read_text(encoding="utf-8") == "keep me"
    if not output.is_symlink():
        assert json.loads(output.read_text(encoding="utf-8"))


@pytest.mark.parametrize("exporter", EXPORTERS)
def test_save_does_not_write_beneath_a_linked_directory(tmp_path, exporter):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "out").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(OSError):
        exporter().save(_bom(), tmp_path / "out" / "export.json")
    assert list(elsewhere.iterdir()) == []


@pytest.mark.parametrize("exporter", EXPORTERS)
def test_save_replaces_the_destination_with_the_generated_document(tmp_path, exporter):
    output = tmp_path / "export.json"
    output.write_text("stale", encoding="utf-8")
    bom = _bom()
    exporter().save(bom, output)
    text = output.read_text(encoding="utf-8")
    assert json.loads(text).keys() == exporter().generate(bom).keys()
    assert [path.name for path in tmp_path.iterdir()] == ["export.json"]


class _Nonfinite(Generator):
    format_name = "nonfinite"

    def __init__(self, value: float) -> None:
        self.value = value

    def generate(self, bom: AIBOM) -> dict[str, Any]:
        return {"score": self.value}


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_a_nonfinite_number_is_refused_instead_of_written_as_invalid_json(tmp_path, value):
    exporter = _Nonfinite(value)
    with pytest.raises(ValueError):
        exporter.generate_json(_bom())
    with pytest.raises(ValueError):
        exporter.save(_bom(), tmp_path / "export.json")
    assert not Path(tmp_path / "export.json").exists()


def test_the_package_exports_every_generator_and_the_export_result():
    assert set(generators.__all__) == {
        "CycloneDXGenerator",
        "ExportResult",
        "Generator",
        "SARIFGenerator",
        "SPDXGenerator",
        "VEXGenerator",
    }
    result = CycloneDXGenerator().generate_with_report(_bom())
    assert isinstance(result, ExportResult)
