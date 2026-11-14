"""Pickle and object-dtype NumPy payloads are found by content, not only by suffix."""

from __future__ import annotations

import io
import pickle
import pickletools
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
    MAX_PICKLE_OPCODES,
    NUMPY_HEADER_UNREAD,
    NUMPY_OBJECT_ARRAY,
    PICKLE_NAME_UNCALLED,
    PICKLE_UNREAD,
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


# Opcodes through which unpickling resolves or calls an object.
_CODE_OPCODES = {
    "GLOBAL",
    "STACK_GLOBAL",
    "INST",
    "OBJ",
    "REDUCE",
    "NEWOBJ",
    "NEWOBJ_EX",
    "BUILD",
    "EXT1",
    "EXT2",
    "EXT4",
}


def _names_a_callable(data: bytes) -> bool:
    names: set[str] = set()
    stream = io.BytesIO(data[:MAX_PICKLE_INSPECTION_BYTES])
    try:
        # A loader can read the pickles that follow a STOP, so every one of them counts.
        while stream.tell() < len(stream.getbuffer()):
            for opcode, _, _ in pickletools.genops(stream):
                names.add(opcode.name)
    except (ValueError, UnicodeError, OverflowError, RecursionError, IndexError):
        pass
    return bool(names & _CODE_OPCODES)


def test_text_that_reads_as_a_harmless_pickle_is_not_inventoried(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    # "N." is NONE then STOP, "Mar." BININT2 then STOP: well-formed, but they run nothing.
    (tmp_path / "models" / "NOTES.txt").write_bytes(b"N.B. retrain after the next release\n")
    (tmp_path / "samples.dat").write_bytes((11854).to_bytes(2, "little") + bytes(range(64)))
    (tmp_path / "service.dat").write_bytes(b"Mar. 3 12:00:01 service started\n")
    assert _components(tmp_path) == {}
    # A name on the pickle suffix list is still rated by the name.
    (tmp_path / "models" / "notes.pkl").write_bytes(b"N.B.")
    assert _components(tmp_path)["models/notes.pkl"].serialization_safety is UNSAFE


@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_a_pickle_that_reaches_code_is_critical_by_content_at_every_protocol(
    tmp_path: Path, protocol: int
) -> None:
    payload = pickle.dumps(_Boom(), protocol=protocol)
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "weights").write_bytes(payload)
    (tmp_path / "state.dat").write_bytes(payload)
    (tmp_path / "bundle.npz").write_bytes(_zip([("arr_0.npy", _npy("|O")), ("x.pkl", payload)]))
    found = _components(tmp_path)
    assert sorted(found) == ["bundle.npz", "models/weights", "state.dat"]
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert _critical(component)


def test_random_files_are_never_critical_without_an_opcode_that_reaches_code(
    tmp_path: Path,
) -> None:
    rng = random.Random(1520)  # noqa: S311 - fixed test data, not a secret
    starts = [b"N.", b"Mar.", b"I12\n.", b"(l.", b"].", b"}.", b"K\x07.", b"\x80\x02N."]
    (tmp_path / "models").mkdir()
    written: dict[str, bytes] = {}
    for index in range(240):
        kind = index % 4
        if kind == 0:
            data = rng.choice(starts) + bytes(rng.choices(range(32, 127), k=rng.randrange(200)))
        elif kind == 1:
            data = rng.choice(starts) + rng.randbytes(rng.randrange(400))
        elif kind == 2:
            data = bytes([0x80, rng.randrange(2, 6)]) + rng.randbytes(rng.randrange(400))
        else:
            data = b"".join(
                rng.randrange(-(2**15), 2**15).to_bytes(2, "little", signed=True)
                for _ in range(rng.randrange(1, 100))
            )
        relative = f"models/file{index}.txt" if index % 2 else f"data{index}.dat"
        (tmp_path / relative).write_bytes(data)
        written[relative] = data
    for relative, component in _components(tmp_path).items():
        if _critical(component):
            assert _names_a_callable(written[relative]), relative


class _LargeBuffer:
    """Reduces as NumPy does at protocol 5: a callable, then the array's bytes in-band."""

    def __reduce_ex__(self, protocol: object) -> tuple[object, tuple[object]]:
        return (eval, (pickle.PickleBuffer(bytearray(MAX_PICKLE_INSPECTION_BYTES + 4096)),))


def test_a_protocol_5_pickle_of_a_large_buffer_is_critical(tmp_path: Path) -> None:
    payload = pickle.dumps(_LargeBuffer(), protocol=5)
    names = [opcode.name for opcode, _, _ in pickletools.genops(payload)]
    # The bytes run past the inspection bound after fewer than 16 opcodes.
    assert names.index("BYTEARRAY8") < 16
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "array").write_bytes(payload)
    (tmp_path / "array.dat").write_bytes(payload)
    found = _components(tmp_path)
    assert sorted(found) == ["array.dat", "models/array"]
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert component.properties["format_inspection"] == BINARY_PICKLE


def test_a_binary_pickle_with_no_callable_before_the_bound_is_unknown(tmp_path: Path) -> None:
    filler = b"N0" * 20 + b"\x8e" + (MAX_PICKLE_INSPECTION_BYTES).to_bytes(8, "little")
    payload = b"\x80\x04" + filler + b"x" * MAX_PICKLE_INSPECTION_BYTES
    payload += pickle.dumps(_Boom(), protocol=4)[2:]
    (tmp_path / "padded.dat").write_bytes(payload)
    # The same opcodes cut short before the bound run nothing: not a payload.
    (tmp_path / "short.dat").write_bytes(b"\x80\x04" + filler + b"x" * 100)
    found = _components(tmp_path)
    assert sorted(found) == ["padded.dat"]
    component = found["padded.dat"]
    assert component.serialization_safety is SerializationSafety.UNKNOWN
    assert component.properties["format_inspection"] == PICKLE_UNREAD
    assert any(risk.category == "serialization_format_unknown" for risk in component.risks)
    bom = AIBOM(components=list(found.values()))
    report = IntegrityValidator(require_model_signatures=False).validate(bom, tmp_path)
    categories = {issue.category for issue in report.issues}
    assert "format_claim_mismatch" not in categories
    assert "format_subject_mismatch" not in categories


def _legacy_torch(main: object) -> bytes:
    """``torch.save``'s legacy layout: three header pickles, then the main pickle."""
    sys_info = {
        "protocol_version": 1001,
        "little_endian": True,
        "type_sizes": {"short": 2, "int": 4, "long": 4},
    }
    header = [0x1950A86A20F9469CFC6C, 1001, sys_info]
    return b"".join(pickle.dumps(part, protocol=2) for part in [*header, main])


def test_a_pickle_after_harmless_pickles_is_critical_by_content(tmp_path: Path) -> None:
    legacy = _legacy_torch(_Boom())
    # torch's _legacy_load unpickles the three header pickles, then the main one.
    stream = io.BytesIO(legacy)
    for _ in range(3):
        pickle.load(stream)  # noqa: S301 - the test's own bytes
    assert pickle.Unpickler(stream).load() == 2  # noqa: S301 - _Boom evaluates 1+1
    (tmp_path / "models").mkdir()
    files = {
        "models/pytorch_model": legacy,
        "weights.dat": legacy,
        "w.npy": legacy,
        "models/m2": b"\x80\x04N." + pickle.dumps(_Boom(), protocol=4),
        "models/m3": b"N." + pickle.dumps(_Boom(), protocol=0),
        "models/m4": b"N.N.(l." + pickle.dumps(_Boom(), protocol=1),
    }
    for relative, data in files.items():
        (tmp_path / relative).write_bytes(data)
    found = _components(tmp_path)
    assert sorted(found) == sorted(files)
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert _critical(component)


def test_harmless_pickles_in_a_row_are_not_inventoried(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "header").write_bytes(_legacy_torch([1, 2, 3]))
    (tmp_path / "pairs.dat").write_bytes(b"N.N.\x80\x04N.")
    (tmp_path / "trailer.dat").write_bytes(b"N.\x80\x09 not a pickle")
    assert _components(tmp_path) == {}


def test_a_pickle_past_the_bound_after_a_harmless_one_is_unknown(tmp_path: Path) -> None:
    filler = b"\x80\x04\x8e" + (MAX_PICKLE_INSPECTION_BYTES).to_bytes(8, "little")
    payload = b"\x80\x04N." + filler + b"x" * MAX_PICKLE_INSPECTION_BYTES + b"."
    payload += pickle.dumps(_Boom(), protocol=4)
    (tmp_path / "padded.dat").write_bytes(payload)
    component = _components(tmp_path)["padded.dat"]
    assert component.serialization_safety is SerializationSafety.UNKNOWN
    assert component.properties["format_inspection"] == PICKLE_UNREAD


def _padded_legacy_torch(protocol: int, *, by_opcodes: bool) -> bytes:
    """Legacy ``torch.save`` bytes whose ``sys_info`` pickle runs past an inspection bound."""
    sys_info: dict[str, object] = {"protocol_version": 1001, "little_endian": True}
    if by_opcodes:
        sys_info.update({f"k{index}": index for index in range(MAX_PICKLE_OPCODES)})
    else:
        sys_info["note"] = "x" * MAX_PICKLE_INSPECTION_BYTES
    header = [0x1950A86A20F9469CFC6C, 1001, sys_info]
    parts = [pickle.dumps(part, protocol=protocol) for part in header]
    return b"".join([*parts, pickle.dumps(_Boom(), protocol=protocol)])


@pytest.mark.parametrize("protocol", [0, 2])
@pytest.mark.parametrize("by_opcodes", [True, False], ids=["opcodes", "bytes"])
def test_a_padded_header_pickle_after_a_stop_is_unknown(
    tmp_path: Path, protocol: int, by_opcodes: bool
) -> None:
    legacy = _padded_legacy_torch(protocol, by_opcodes=by_opcodes)
    stream = io.BytesIO(legacy)
    for _ in range(3):
        pickle.load(stream)  # noqa: S301 - the test's own bytes
    assert pickle.Unpickler(stream).load() == 2  # noqa: S301 - _Boom evaluates 1+1
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "pytorch_model").write_bytes(legacy)
    (tmp_path / "weights.dat").write_bytes(legacy)
    found = _components(tmp_path)
    assert sorted(found) == ["models/pytorch_model", "weights.dat"]
    for component in found.values():
        assert component.serialization_safety is SerializationSafety.UNKNOWN
        assert component.properties["format_inspection"] == PICKLE_UNREAD


def test_text_cut_short_without_an_earlier_stop_is_not_inventoried(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    # Text-protocol streams that reach a bound before any STOP, or fail before one.
    (tmp_path / "models" / "list.txt").write_bytes(b"(" + b"I1\n" * MAX_PICKLE_OPCODES)
    (tmp_path / "long.dat").write_bytes(b"(S'" + b"x" * MAX_PICKLE_INSPECTION_BYTES + b"'\n")
    # After a STOP, a text segment that fails short of the bound, or ends with the file.
    (tmp_path / "models" / "notes").write_bytes(b"N.(I1\nnot a pickle at all\n")
    (tmp_path / "tail.dat").write_bytes(b"N.(I1\nI2\n")
    assert _components(tmp_path) == {}


# A text-protocol and a binary pickle that call exec and end with no STOP: pickle.load
# runs the REDUCE, then fails at what follows.
_TEXT_CALL = b"c__builtin__\nexec\n(S'import builtins; builtins.HIT=1'\ntR"
_BINARY_CALL = b"\x80\x02c__builtin__\nexec\nX\x1f\x00\x00\x00import builtins; builtins.HIT=1\x85R"


def _header(protocol: int) -> bytes:
    parts = [0x1950A86A20F9469CFC6C, 1001, {"protocol_version": 1001}]
    return b"".join(pickle.dumps(part, protocol=protocol) for part in parts)


def _runs_exec(data: bytes) -> bool:
    import builtins

    builtins.HIT = 0  # type: ignore[attr-defined]
    stream = io.BytesIO(data)
    try:
        for _ in range(8):
            pickle.load(stream)  # noqa: S301 - the test's own bytes
    except Exception:  # noqa: BLE001, S110 - the loader fails after the call
        pass
    hit = getattr(builtins, "HIT", 0)
    del builtins.HIT  # type: ignore[attr-defined]
    return hit == 1


_CUT_SHORT_AFTER_A_STOP = {
    "text-eof": b"N." + _TEXT_CALL,
    "text-invalid-opcode": b"N." + _TEXT_CALL + b"\xff\xff",
    "text-stack-underflow": b"N." + _TEXT_CALL + b"00000.",
    "text-header-eof": _header(0) + _TEXT_CALL,
    "text-header-invalid-opcode": _header(0) + _TEXT_CALL + b"\xff",
    "binary-header-eof": _header(2) + _BINARY_CALL,
    "binary-header-invalid-opcode": _header(2) + _BINARY_CALL + b"\xff",
    "binary-eof": b"N." + _BINARY_CALL,
}


@pytest.mark.parametrize("data", _CUT_SHORT_AFTER_A_STOP.values(), ids=_CUT_SHORT_AFTER_A_STOP)
def test_a_call_after_a_stop_that_fails_later_is_critical(tmp_path: Path, data: bytes) -> None:
    assert _runs_exec(data)
    (tmp_path / "models").mkdir()
    files = ["models/pytorch_model", "legacy.dat", "w.npy", "models/m.pt", "m.pkl", "m.onnx"]
    for relative in files:
        (tmp_path / relative).write_bytes(data)
    found = _components(tmp_path)
    assert sorted(found) == sorted(files)
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert _critical(component)


@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_a_reduce_pickle_with_no_stop_is_critical_under_a_model_name(
    tmp_path: Path, protocol: int
) -> None:
    data = pickle.dumps(_Boom(), protocol=protocol)[:-1]
    for name, tail in {"eof": b"", "invalid": b"\xff", "underflow": b"00000."}.items():
        (tmp_path / f"{name}.onnx").write_bytes(data + tail)
        (tmp_path / f"{name}.after.dat").write_bytes(b"N." + data + tail)
    found = _components(tmp_path)
    assert len(found) == 6
    assert all(component.serialization_safety is UNSAFE for component in found.values())


def test_a_binary_call_with_no_stop_is_critical_by_content(tmp_path: Path) -> None:
    assert _runs_exec(_BINARY_CALL)
    (tmp_path / "w.dat").write_bytes(_BINARY_CALL)
    assert _components(tmp_path)["w.dat"].serialization_safety is UNSAFE


def test_text_that_reads_as_a_name_without_a_call_is_not_critical(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    # Alone, a text-protocol call cut short is as likely prose.
    (tmp_path / "models" / "readme").write_bytes(b"config\nvalues\nbuild\n")
    (tmp_path / "text.dat").write_bytes(_TEXT_CALL)
    # After a STOP: words that are no module name, or no call after the name.
    (tmp_path / "models" / "notes").write_bytes(b"N.c see notes\nfor details\nb")
    (tmp_path / "log.dat").write_bytes(b"N.bad\n")
    (tmp_path / "list.dat").write_bytes(b"N.]\x83\x94\xf3\x81<")
    (tmp_path / "stack.dat").write_bytes(b"\x80\x02N.J\xcaW\x22\x16\x93T\xb1")
    assert _components(tmp_path) == {}


def test_a_name_after_a_stop_with_no_call_is_unknown(tmp_path: Path) -> None:
    (tmp_path / "named.dat").write_bytes(b"N.cos\nsystem\n\xff")
    component = _components(tmp_path)["named.dat"]
    assert component.serialization_safety is SerializationSafety.UNKNOWN
    assert component.properties["format_inspection"] == PICKLE_NAME_UNCALLED


# A STACK_GLOBAL call of exec, and a GLOBAL one, that pickle.load runs.
_STACK_CALL = b"\x8c\x08builtins\x8c\x04exec\x93\x8c\x13builtins.HIT=1;None\x85R."
_GLOBAL_CALL = b"cbuiltins\nexec\n\x8c\x13builtins.HIT=1;None\x85R."

# After a STOP, the next pickle may start with any opcode, not only PROTO 2 to 5 or
# a byte that starts common text-protocol pickles.
_ANY_OPCODE_AFTER_A_STOP = {
    "header-short-binunicode": _header(2) + _STACK_CALL,
    "header-frame": _header(2) + b"\x95" + len(_STACK_CALL).to_bytes(8, "little") + _STACK_CALL,
    "header-proto-1": _header(2) + b"\x80\x01" + _GLOBAL_CALL,
    "header-proto-0": _header(2) + b"\x80\x00" + _GLOBAL_CALL,
    "none-short-binunicode": b"N." + _STACK_CALL,
    "none-newtrue-pop": b"N.\x880" + _GLOBAL_CALL,
    "none-empty-set-pop": b"N.\x8f0" + _GLOBAL_CALL,
}


@pytest.mark.parametrize("data", _ANY_OPCODE_AFTER_A_STOP.values(), ids=_ANY_OPCODE_AFTER_A_STOP)
def test_a_call_after_a_stop_is_critical_whatever_opcode_starts_it(
    tmp_path: Path, data: bytes
) -> None:
    assert _runs_exec(data)
    (tmp_path / "models").mkdir()
    files = ["models/x", "x.dat", "x.npy", "legacy.tar.dat"]
    for relative in files:
        (tmp_path / relative).write_bytes(data)
    found = _components(tmp_path)
    assert sorted(found) == sorted(files)
    for component in found.values():
        assert component.serialization_safety is UNSAFE
        assert _critical(component)


def test_bytes_after_a_stop_that_start_no_opcode_are_not_inventoried(tmp_path: Path) -> None:
    (tmp_path / "invalid.dat").write_bytes(b"N.\xff" + _GLOBAL_CALL)
    (tmp_path / "protocol.dat").write_bytes(b"N.\x80\x06" + _GLOBAL_CALL)
    assert _components(tmp_path) == {}


# Text that reads as a name after a STOP and then an opcode that calls, with nothing on
# the stack for it to call: pickle.load fails at a stack underflow and calls nothing.
_UNCALLED_TEXT = {
    "paths.dat": b"VERSION\n.cache\nlogs\noutputs\n",
    "models/notes.txt": b"N.cache\nbuild\nbin\n",
    "models/llama/MANIFEST": b"Vendored paths:\n.cache\nbuild\nREADME.md\n",
    "models/calls-none": b"N.cos\nsystem\nN)R.",
    "models/obj-without-mark": b"N.cos\nsystem\no.",
}


def _calls_anything(data: bytes) -> bool:
    called: list[str] = []

    class _Record:
        def __init__(self, *_: object) -> None:
            called.append("init")

        def __call__(self, *_: object) -> None:
            called.append("call")

        def __setstate__(self, _: object) -> None:
            called.append("setstate")

    class _Unpickler(pickle.Unpickler):
        def find_class(self, module: str, name: str) -> type:
            return _Record

    stream = io.BytesIO(data)
    for _ in range(8):
        try:
            _Unpickler(stream).load()
        except Exception:  # noqa: BLE001 - the stream fails where pickle.load does
            break
    return bool(called)


def test_a_name_with_no_operands_for_its_call_is_not_critical(tmp_path: Path) -> None:
    (tmp_path / "models" / "llama").mkdir(parents=True)
    for relative, data in _UNCALLED_TEXT.items():
        assert not _calls_anything(data)
        (tmp_path / relative).write_bytes(data)
    found = _components(tmp_path)
    for relative, component in found.items():
        assert component.serialization_safety is SerializationSafety.UNKNOWN, relative
        assert component.properties["format_inspection"] == PICKLE_NAME_UNCALLED
        assert not _critical(component)


@pytest.mark.parametrize(
    "data",
    [
        b"N.(cos\nsystem\nNo.",
        b"N.cos\nsystem\n)\x81.",
        b"N.cos\nsystem\np0\n0g0\n)R.",
        b"N.(cos\nsystem\nN\x85R.",
    ],
    ids=["obj", "newobj", "memo", "inside-a-mark"],
)
def test_a_call_with_its_operands_after_a_stop_is_critical(tmp_path: Path, data: bytes) -> None:
    (tmp_path / "call.dat").write_bytes(data)
    assert _components(tmp_path)["call.dat"].serialization_safety is UNSAFE
