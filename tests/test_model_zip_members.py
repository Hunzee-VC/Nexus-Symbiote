"""ZIP discovery and streamed model inspection agree on pickle-family names."""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path
from typing import BinaryIO

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.enums import SerializationSafety
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.scanners import model


def _archive(member: str, *, padding: int = 0, zip64: bool = False) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("version", b"1")
        archive.writestr("padding", b"x" * padding)
        archive.writestr(member, b"N.")
    raw = output.getvalue()
    if zip64:
        end = raw.rfind(b"PK\x05\x06")
        size, offset = struct.unpack_from("<II", raw, end + 12)
        record = struct.pack("<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0, 3, 3, size, offset)
        locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, end, 1)
        final = bytearray(raw[end:])
        struct.pack_into("<HHII", final, 8, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
        raw = raw[:end] + record + locator + final
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert archive.namelist() == ["version", "padding", member]
    return raw


@pytest.mark.parametrize(
    "member",
    [
        "data.pkl",
        "data.pickle",
        "data.pck",
        "data.dill",
        "data.pt",
        "data.pth",
        "data.bin",
        "data.joblib",
        "data.ckpt",
        "data.pdparams",
        "data.pkl.gz",
        "data.pth.tar",
        "folder/DATA.PICKLE",
        r"folder\data.pickle",
    ],
)
def test_later_pickle_family_members_are_discovered(tmp_path: Path, member: str) -> None:
    (tmp_path / "model.dat").write_bytes(_archive(member))
    result = model.ModelScanner().scan(tmp_path)
    assert not result.scan_failures
    assert len(result.components) == 1
    assert result.components[0].serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION


@pytest.mark.parametrize("zip64", [False, True])
def test_small_zip64_and_normal_archives_are_discovered(tmp_path: Path, zip64: bool) -> None:
    (tmp_path / "model.dat").write_bytes(_archive("data.pickle", zip64=zip64))
    result = model.ModelScanner().scan(tmp_path)
    assert len(result.components) == 1
    assert result.components[0].serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION


class _CountedReader:
    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.bytes_read = 0

    def fileno(self) -> int:
        return self.stream.fileno()

    def read(self, size: int) -> bytes:
        assert 0 < size <= 65536
        data = self.stream.read(size)
        self.bytes_read += len(data)
        return data


@pytest.mark.parametrize("zip64", [False, True])
@pytest.mark.parametrize("extension", [".onnx", ".gguf"])
@pytest.mark.parametrize("member", ["data.pickle", "data.pkl.gz"])
def test_tail_members_keep_streaming_and_whole_file_digest(
    tmp_path: Path, zip64: bool, extension: str, member: str
) -> None:
    raw = _archive(member, padding=1_200_000, zip64=zip64)
    path = tmp_path / ("model" + extension)
    path.write_bytes(raw)
    with path.open("rb") as stream:
        counted = _CountedReader(stream)
        observed = model.observe_model_artifact(path, stream=counted)  # type: ignore[arg-type]
    assert counted.bytes_read == len(raw)
    assert observed.digest == hash_bytes(raw)
    assert observed.safety is SerializationSafety.UNSAFE_CODE_EXECUTION


def test_discovery_keeps_its_prefix_bound_while_known_models_use_the_tail(tmp_path: Path) -> None:
    raw = _archive("data.pickle", padding=70_000)
    (tmp_path / "renamed.dat").write_bytes(raw)
    (tmp_path / "known.onnx").write_bytes(raw)
    result = model.ModelScanner().scan(tmp_path)
    assert not result.scan_failures
    assert [component.source_path for component in result.components] == ["known.onnx"]
    assert result.components[0].serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION


@pytest.mark.parametrize("member", ["README.txt", "folder.pkl/README.txt", "data.pickle.txt"])
def test_ordinary_names_are_not_discovered_or_marked_safe(tmp_path: Path, member: str) -> None:
    raw = _archive(member)
    (tmp_path / "renamed.dat").write_bytes(raw)
    (tmp_path / "known.onnx").write_bytes(raw)
    result = model.ModelScanner().scan(tmp_path)
    assert [component.source_path for component in result.components] == ["known.onnx"]
    assert result.components[0].serialization_safety is SerializationSafety.UNKNOWN


@pytest.mark.parametrize("malformed", [False, True])
def test_directory_bounds_and_malformed_directory_stay_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, malformed: bool
) -> None:
    raw = _archive("data.pickle")
    if malformed:
        data = bytearray(raw)
        end = data.rfind(b"PK\x05\x06")
        struct.pack_into("<I", data, end + 12, len(raw) + 100)
        raw = bytes(data)
    else:
        monkeypatch.setattr(model, "MAX_ZIP_DIRECTORY_BYTES", 64)
    path = tmp_path / "model.onnx"
    path.write_bytes(raw)
    with path.open("rb") as stream:
        observed = model.observe_model_artifact(path, stream=stream)
    assert observed.safety is SerializationSafety.UNKNOWN
    assert observed.explanation == model.ZIP_DIRECTORY_UNREAD
    assert observed.digest == hash_bytes(raw)


@pytest.mark.parametrize("pickle_member", [False, True])
def test_later_pickle_member_reaches_the_default_cli_gate(
    tmp_path: Path, runner: CliRunner, pickle_member: bool
) -> None:
    member = "data.pickle" if pickle_member else "README.txt"
    (tmp_path / "agent.yaml").write_text("name: ZIP test\ninstructions: [CLAUDE.md]\n")
    (tmp_path / "CLAUDE.md").write_text("Use the configured tools.\n")
    (tmp_path / "model.dat").write_bytes(_archive(member))
    result = runner.invoke(main, ["scan", str(tmp_path), "--no-project-policy", "--check"])
    assert result.exit_code == (1 if pickle_member else 0), result.output
