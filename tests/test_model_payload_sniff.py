"""Pickle and object-dtype NumPy payloads are found by content, not only by suffix."""

from __future__ import annotations

import io
import pickle
import random
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from nexus_symbiote import limits
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.scanners.model import (
    MAX_PICKLE_INSPECTION_BYTES,
    NUMPY_HEADER_UNREAD,
    NUMPY_OBJECT_ARRAY,
    ZIP_DIRECTORY_UNREAD,
    ZIP_MEMBER_UNREAD,
    ZIP_OBJECT_ARRAY,
    ZIP_PICKLE_MEMBER,
    ModelScanner,
)
from nexus_symbiote.validators.integrity import IntegrityValidator

UNSAFE = SerializationSafety.UNSAFE_CODE_EXECUTION
BINARY_PICKLE = "Recognized binary pickle opcode stream; object loading can execute code"


class _Boom:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (eval, ("1+1",))


def _reduce_pickle(*tail: object) -> bytes:
    return pickle.dumps([_Boom(), *tail], protocol=4)


def _npy(descr: str, *, version: int = 1, lead: int = 0) -> bytes:
    text = "{" + " " * lead + f"'descr': '{descr}', 'fortran_order': False, 'shape': (1,), }}"
    width = 2 if version == 1 else 4
    text += " " * (-(10 + width + len(text) + 1) % 64) + "\n"
    return (
        b"\x93NUMPY"
        + bytes([version, 0])
        + len(text).to_bytes(width, "little")
        + text.encode()
        + b"\x00" * 8
    )


def _zip(members: list[tuple[str, bytes]], compression: int = zipfile.ZIP_STORED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, data in members:
            archive.writestr(name, data)
    return buffer.getvalue()


def _components(root: Path) -> dict[str, object]:
    result = ModelScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    return {component.source_path or "": component for component in result.components}


def _component(root: Path, relative: str):
    return _components(root).get(relative)


def _critical(component) -> bool:
    return any(
        risk.severity is RiskSeverity.CRITICAL and risk.category == "serialization_format"
        for risk in component.risks
    )


def test_renamed_pickle_and_object_arrays_are_critical(tmp_path: Path) -> None:
    payload = _reduce_pickle()
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "weights").write_bytes(payload)
    (tmp_path / "models" / "model.dat").write_bytes(payload)
    (tmp_path / "tensors").mkdir()
    (tmp_path / "tensors" / "objects.npy").write_bytes(_npy("|O"))
    (tmp_path / "tensors" / "numbers.npy").write_bytes(_npy("<f8"))
    (tmp_path / "checkpoints").mkdir()
    (tmp_path / "checkpoints" / "bundle.bin.not").write_bytes(_zip([("weights/data.pkl", payload)]))

    found = _components(tmp_path)
    assert "tensors/numbers.npy" not in found
    for relative in (
        "models/weights",
        "models/model.dat",
        "tensors/objects.npy",
        "checkpoints/bundle.bin.not",
    ):
        component = found[relative]
        assert component.serialization_safety is UNSAFE
        assert _critical(component)
    assert "1+1" not in found["models/weights"].model_dump_json()
    # The rating carries the same evidence as a file under a model name.
    assert found["models/weights"].properties["format_inspection"] == BINARY_PICKLE
    assert found["tensors/objects.npy"].properties["format_inspection"] == NUMPY_OBJECT_ARRAY
    archive = found["checkpoints/bundle.bin.not"]
    assert archive.properties["format_inspection"] == ZIP_PICKLE_MEMBER
    assert archive.serialization_format == "zip-archive"


def test_a_suffix_list_file_is_still_rated_without_a_recognized_stream(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(b"not a pickle")
    component = _component(tmp_path, "model.pkl")
    assert component is not None
    assert component.serialization_safety is UNSAFE


def test_a_pickle_longer_or_shorter_than_the_sample_is_found_by_the_shared_recognizer(
    tmp_path: Path,
) -> None:
    (tmp_path / "models").mkdir()
    long = _reduce_pickle(b"x" * 117_000)
    assert len(long) > MAX_PICKLE_INSPECTION_BYTES
    (tmp_path / "models" / "long").write_bytes(long)
    # Cut short after more than 16 well-formed opcodes, as a loader still runs them.
    truncated = _reduce_pickle(*range(40))
    (tmp_path / "models" / "truncated").write_bytes(truncated[:-12])
    noise = random.Random(152).randbytes(5000)  # noqa: S311 - fixed test data, not a secret
    (tmp_path / "models" / "random").write_bytes(noise)
    (tmp_path / "models" / "notes").write_bytes(b"(a parenthesised note, not a pickle)\n" * 50)

    found = _components(tmp_path)
    assert sorted(found) == ["models/long", "models/truncated"]
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert component.properties["format_inspection"] == BINARY_PICKLE


def test_a_zip_is_rated_from_the_directory_at_its_end(tmp_path: Path) -> None:
    payload = _reduce_pickle()
    (tmp_path / "models").mkdir()
    # torch.save may write a member longer than any prefix before data.pkl.
    (tmp_path / "models" / "archive").write_bytes(
        _zip([("archive/version", b"3" * 100_000), ("archive/data.pkl", payload)])
    )
    (tmp_path / "models" / "renamed.dat").write_bytes(
        _zip([("version", b"1"), ("weights/data.pickle", payload)])
    )
    (tmp_path / "models" / "notes.dat").write_bytes(
        _zip([("version", b"1"), ("README.txt", b"numbers only")])
    )

    found = _components(tmp_path)
    assert sorted(found) == ["models/archive", "models/renamed.dat"]
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert component.properties["format_inspection"] == ZIP_PICKLE_MEMBER


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_npz_object_arrays_are_inventoried_wherever_they_sit(
    tmp_path: Path, compression: int
) -> None:
    numbers = _npy("<f8") + b"\x00" * 70_000
    (tmp_path / "late.npz").write_bytes(
        _zip([("numbers.npy", numbers), ("objects.npy", _npy("|O"))], compression)
    )
    (tmp_path / "numbers.npz").write_bytes(_zip([("numbers.npy", numbers)], compression))

    found = _components(tmp_path)
    assert sorted(found) == ["late.npz"]
    assert found["late.npz"].serialization_safety is UNSAFE
    assert found["late.npz"].properties["format_inspection"] == ZIP_OBJECT_ARRAY
    assert _critical(found["late.npz"])


def test_npz_with_a_compressed_member_first_is_inventoried(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("numbers.npy", _npy("<f8"), compress_type=zipfile.ZIP_DEFLATED)
        archive.writestr("objects.npy", _npy("|O"), compress_type=zipfile.ZIP_STORED)
    (tmp_path / "arrays.npz").write_bytes(buffer.getvalue())
    component = _component(tmp_path, "arrays.npz")
    assert component is not None
    assert component.serialization_safety is UNSAFE


def test_content_left_unread_at_a_bound_is_inventoried_as_unknown(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "padded.npy").write_bytes(
        _npy("|O", version=2, lead=MAX_PICKLE_INSPECTION_BYTES)
    )
    (tmp_path / "models" / "lzma.npz").write_bytes(
        _zip([("objects.npy", _npy("|O"))], zipfile.ZIP_LZMA)
    )
    whole = _zip([("version", b"3"), ("archive/data.pkl", _reduce_pickle())])
    (tmp_path / "models" / "cut").write_bytes(whole[: whole.index(b"PK\x01\x02")])

    found = _components(tmp_path)
    assert {
        path: component.properties["format_inspection"] for path, component in found.items()
    } == {
        "models/padded.npy": NUMPY_HEADER_UNREAD,
        "models/lzma.npz": ZIP_MEMBER_UNREAD,
        "models/cut": ZIP_DIRECTORY_UNREAD,
    }
    for component in found.values():
        assert component.serialization_safety is SerializationSafety.UNKNOWN
        assert any(risk.category == "serialization_format_unknown" for risk in component.risks)


def test_each_byte_of_a_model_directory_is_charged_once(tmp_path: Path) -> None:
    models = tmp_path / "models"
    models.mkdir()
    (models / "weights").write_bytes(_reduce_pickle(b"y" * 40_000))
    for index in range(20):
        (models / f"notes{index}.txt").write_bytes(b"T" + b"e" * 4_999)
    (models / "config.json").write_text('{"model_type": "demo"}')
    (models / "tokenizer.json").write_text('{"version": "1.0"}')
    total = sum(path.stat().st_size for path in models.iterdir())
    with limits.applied(replace(limits.DEFAULTS, model_total_bytes=total)):
        component = _component(tmp_path, "models/weights")
    assert component is not None
    assert component.serialization_safety is UNSAFE
    assert component.hashes["sha256"].startswith("sha256:")
    assert [entry["path"] for entry in component.properties["config_files"]] == [
        "models/config.json"
    ]


def test_a_model_directory_file_is_not_a_content_candidate(tmp_path: Path) -> None:
    models = tmp_path / "models"
    models.mkdir()
    for name in ("config.json", "vocab.txt", "chat_template.jinja", "loader.py"):
        (models / name).write_bytes(_reduce_pickle())
    assert _components(tmp_path) == {}


def test_validation_observes_a_content_artifact_as_the_scan_did(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "weights").write_bytes(_reduce_pickle())
    (tmp_path / "arrays.npz").write_bytes(_zip([("arr_0.npy", _npy("|O"))]))
    bom = AIBOM(components=ModelScanner().scan(tmp_path).components)
    report = IntegrityValidator(require_model_signatures=False).validate(bom, tmp_path)
    issues = {(issue.component_ref, issue.category) for issue in report.issues}
    for reference in ("model:models/weights", "model:arrays.npz"):
        assert (reference, "unsafe_format") in issues
        assert (reference, "format_subject_mismatch") not in issues
        assert (reference, "format_claim_mismatch") not in issues
