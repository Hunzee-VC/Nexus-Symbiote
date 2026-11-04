"""Common model formats are inventoried and never silently treated as clean."""

from __future__ import annotations

import pickle
import zipfile
from pathlib import Path

import pytest

from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.scanners.model import ModelScanner, model_format

INERT_PICKLE = pickle.dumps({"weights": [0.0, 1.0]}, protocol=4)


def _scan(project: Path) -> dict[str, tuple[SerializationSafety, set[tuple[RiskSeverity, str]]]]:
    result = ModelScanner().scan(project)
    assert not result.scan_failures
    return {
        Path(component.name).name: (
            component.serialization_safety,
            {(risk.severity, risk.category) for risk in component.risks},
        )
        for component in result.components
    }


@pytest.mark.parametrize("name", ["lightning.ckpt", "paddle.pdparams"])
def test_pickle_based_checkpoints_are_rated_code_executing(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_bytes(INERT_PICKLE)
    safety, risks = _scan(tmp_path)[name]
    assert safety == SerializationSafety.UNSAFE_CODE_EXECUTION
    assert (RiskSeverity.CRITICAL, "serialization_format") in risks


@pytest.mark.parametrize("name", ["legacy.h5", "legacy.hdf5", "model.keras", "saved_model.pb"])
def test_formats_without_a_validator_are_reported_unknown(tmp_path: Path, name: str) -> None:
    path = tmp_path / name
    if name.endswith(".keras"):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("config.json", "{}")
    else:
        path.write_bytes(b"\x89HDF\r\n\x1a\n" + b"\0" * 32)
    safety, risks = _scan(tmp_path)[name]
    assert safety == SerializationSafety.UNKNOWN
    assert (RiskSeverity.HIGH, "serialization_format_unknown") in risks


def test_generic_protobuf_files_are_not_models(tmp_path: Path) -> None:
    (tmp_path / "descriptor.pb").write_bytes(b"\x08\x01")
    assert model_format(tmp_path / "descriptor.pb") is None
    assert model_format(tmp_path / "SAVED_MODEL.PB") == ("pb", "tensorflow-savedmodel")
    assert _scan(tmp_path) == {}
