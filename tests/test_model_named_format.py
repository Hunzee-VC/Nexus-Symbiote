"""A file named as GGUF or SafeTensors is recorded as that format only when its header is.

A text file named ``not_a_model.gguf`` was recorded as a ``foundation`` model in
``llama.cpp`` format on its suffix alone. It stays a component with its unknown rating
and finding, and the record says that the format was not established.
"""

from __future__ import annotations

import hashlib
import json
import pickle
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.collection import merge_collected
from nexus_symbiote.core.enums import SerializationSafety
from nexus_symbiote.core.models import ModelComponent
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.scanners.model import (
    GGUF_MISMATCH,
    GGUF_TOO_SHORT,
    MAX_MODEL_HEADER_BYTES,
    PICKLE_NAME_UNEVIDENCED,
    ModelScanner,
)
from nexus_symbiote.validators.risk import RiskScorer, _intrinsic_model_risks

# The reported file, byte for byte.
PLACEHOLDER = b"placeholder used by the upload-validation test\n"
INERT_PICKLE = pickle.dumps({"weights": [0.0, 1.0]}, protocol=4)
NO_VALIDATOR = "No bounded structural validator for this format/loader"
BINARY_PICKLE = "Recognized binary pickle opcode stream; object loading can execute code"
MALFORMED = "Malformed or unsupported SafeTensors structure"
UNREAD = "Artifact could not be inspected"
UNKNOWN_FORMAT = ("high", "serialization_format_unknown")
# Stored for a file named as SafeTensors, so a reader older than the record still fails its gate.
INVALID_SAFETENSORS = ("high", "invalid_safetensors")
UNSIGNED = ("high", "signing_status")
DOCS = Path(__file__).resolve().parents[1] / "docs"


def _unknown(named: str) -> list[tuple[str, str]]:
    """The findings of a file whose format was not established and that carries no payload."""
    stored = [INVALID_SAFETENSORS] if named == "safe-tensors" else []
    return [*stored, UNKNOWN_FORMAT, UNSIGNED]


def _gguf_string(text: bytes) -> bytes:
    return len(text).to_bytes(8, "little") + text


def _gguf() -> bytes:
    """A GGUF v3 header with one metadata key and no tensors."""
    header = b"GGUF" + (3).to_bytes(4, "little") + (0).to_bytes(8, "little")
    header += (1).to_bytes(8, "little") + _gguf_string(b"general.architecture")
    return header + (8).to_bytes(4, "little") + _gguf_string(b"llama") + b"\0" * 32


def _safetensors() -> bytes:
    header = {"w": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}}
    raw = json.dumps(header, separators=(",", ":")).encode()
    raw += b" " * (-len(raw) % 8)
    return len(raw).to_bytes(8, "little") + raw + b"abcd"


def _oversized_safetensors() -> bytes:
    raw = b"{" + b" " * MAX_MODEL_HEADER_BYTES + b"}"
    return len(raw).to_bytes(8, "little") + raw


def _zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("archive/version", "3")


def _scan(root: Path, name: str, content: bytes) -> ModelComponent:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    result = ModelScanner().scan(root)
    assert not result.scan_failures and not result.surfaces_excluded
    (component,) = result.components
    return component


def _findings(component: ModelComponent) -> list[tuple[str, str]]:
    return [(risk.severity.value, risk.category) for risk in component.risks]


def _recorded(component: ModelComponent) -> dict[str, Any]:
    """The native record without its findings."""
    record = component.model_dump(mode="json", exclude_none=True)
    del record["risks"]
    return record


def _unestablished(component: ModelComponent, named: str) -> None:
    """The record names no format and no model type, and says which format its name claims."""
    record = component.model_dump(mode="json", exclude_none=True)
    assert "serialization_format" not in record and "model_type" not in record
    assert component.properties["named_format"] == named


# The valid twins: these records are what the collector wrote before the change.
VALID = {
    "model.gguf": (
        _gguf(),
        {
            "model_type": "foundation",
            "serialization_format": "llama.cpp",
            "serialization_safety": "unknown",
            "properties": {"format_inspection": NO_VALIDATOR, "gguf_architecture": "llama"},
        },
        [UNKNOWN_FORMAT, UNSIGNED],
    ),
    "model.safetensors": (
        _safetensors(),
        {
            "model_type": "foundation",
            "serialization_format": "safe-tensors",
            "serialization_safety": "safe",
            "properties": {
                "format_inspection": "Bounded SafeTensors header, shapes and offsets checked"
            },
            "tensor_inventory_hash": (
                "sha256:e75daa9b2b82b010a00f0fc6064759eaa37a5cf4a2ca51ede82cba4e63a5b895"
            ),
            "safetensors_header_hash": (
                "sha256:47e0b94b82e4fe3db5cbded5f6a68ba65ee25a8751b612b4f4044011eeb23dec"
            ),
        },
        [UNSIGNED],
    ),
}


@pytest.mark.parametrize("name", sorted(VALID))
def test_a_file_with_its_formats_header_is_recorded_as_before(tmp_path: Path, name: str) -> None:
    content, fields, findings = VALID[name]
    component = _scan(tmp_path, name, content)
    assert _recorded(component) == {
        "bom_ref": f"model:{name}",
        "component_type": "model",
        "name": name,
        "source_path": name,
        "hashes": {"sha256": "sha256:" + hashlib.sha256(content).hexdigest()},
        "trust_tier": "unknown",
        "assurance_level": "declared",
        "signing_status": "signature-not-found",
        "claims": {},
        **fields,
    }
    assert _findings(component) == findings


@pytest.mark.parametrize(
    ("name", "named", "explanation"),
    [
        ("tests/fixtures/not_a_model.gguf", "llama.cpp", GGUF_MISMATCH),
        ("models/weights.safetensors", "safe-tensors", MALFORMED),
    ],
)
def test_a_header_of_another_format_establishes_neither_format_nor_model_type(
    tmp_path: Path, name: str, named: str, explanation: str
) -> None:
    component = _scan(tmp_path, name, PLACEHOLDER)
    _unestablished(component, named)
    assert component.properties["format_inspection"] == explanation
    assert component.serialization_safety is SerializationSafety.UNKNOWN
    assert component.hashes == {"sha256": "sha256:" + hashlib.sha256(PLACEHOLDER).hexdigest()}
    assert _findings(component) == _unknown(named)


@pytest.mark.parametrize(
    ("name", "content", "named", "explanation"),
    [
        ("model.gguf", b"", "llama.cpp", GGUF_TOO_SHORT),
        ("model.gguf", b"GGU", "llama.cpp", GGUF_TOO_SHORT),
        ("model.safetensors", b"", "safe-tensors", MALFORMED),
        ("model.safetensors", b"\x10\0\0\0\0\0\0", "safe-tensors", MALFORMED),
        (
            "model.safetensors",
            _oversized_safetensors(),
            "safe-tensors",
            "SafeTensors header exceeds the inspection limit",
        ),
    ],
    ids=["gguf-empty", "gguf-three-bytes", "safetensors-empty", "safetensors-short", "over-limit"],
)
def test_a_header_too_short_or_too_long_to_read_stays_an_explicit_unknown(
    tmp_path: Path, name: str, content: bytes, named: str, explanation: str
) -> None:
    component = _scan(tmp_path, name, content)
    _unestablished(component, named)
    assert component.properties["format_inspection"] == explanation
    assert component.serialization_safety is SerializationSafety.UNKNOWN
    assert _findings(component) == _unknown(named)


@pytest.mark.parametrize(
    ("name", "named"), [("model.gguf", "llama.cpp"), ("model.safetensors", "safe-tensors")]
)
def test_a_file_that_cannot_be_read_stays_an_explicit_unknown(
    tmp_path: Path, name: str, named: str
) -> None:
    (tmp_path / name).write_bytes(VALID[name][0])
    with limits.applied(replace(limits.DEFAULTS, model_bytes=8)):
        result = ModelScanner().scan(tmp_path)
    assert f"{name}: model inspection or hashing failed" in result.scan_failures
    (component,) = result.components
    _unestablished(component, named)
    assert component.properties["format_inspection"] == UNREAD
    assert component.serialization_safety is SerializationSafety.UNKNOWN
    assert component.hashes == {}
    assert _findings(component) == _unknown(named)


@pytest.mark.parametrize(
    "content",
    [b"GGUF", b"GGUF\x09\0\0\0 not a supported version", _gguf()[:40]],
    ids=["magic-only", "unsupported-version", "truncated-metadata"],
)
def test_the_gguf_magic_establishes_the_format_when_its_metadata_cannot_be_read(
    tmp_path: Path, content: bytes
) -> None:
    component = _scan(tmp_path, "model.gguf", content)
    assert component.serialization_format == "llama.cpp"
    assert component.model_type == "foundation"
    assert component.properties == {
        "format_inspection": NO_VALIDATOR,
        "gguf_metadata": "not inspected: GGUF metadata could not be read",
    }


@pytest.mark.parametrize(
    ("name", "named"), [("model.gguf", "llama.cpp"), ("model.safetensors", "safe-tensors")]
)
def test_a_pickle_under_the_name_keeps_its_rating_and_is_not_recorded_as_the_named_format(
    tmp_path: Path, name: str, named: str
) -> None:
    component = _scan(tmp_path, name, INERT_PICKLE)
    _unestablished(component, named)
    assert component.serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert "pickle" in component.properties["format_inspection"]
    assert _findings(component) == [("critical", "serialization_format"), UNSIGNED]


def test_the_gguf_magic_before_a_code_executing_pickle_is_not_a_gguf_file(tmp_path: Path) -> None:
    # The magic also opens a pickle: G reads the next eight bytes as a float, and 0 pops it.
    disguised = b"GGUF" + (3).to_bytes(4, "little") + b"\0" + b"0" + b"cos\nsystem\n(S'id'\ntR."
    component = _scan(tmp_path, "model.gguf", disguised)
    _unestablished(component, "llama.cpp")
    assert component.serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert _findings(component) == [("critical", "serialization_format"), UNSIGNED]


def test_an_unestablished_safetensors_file_stores_the_finding_older_readers_derive(
    tmp_path: Path,
) -> None:
    # A reader before named_format derives invalid_safetensors from serialization_format,
    # which this record withholds; the stored finding keeps its gate closed, and the
    # current reader does not count it twice.
    component = _scan(tmp_path, "model.safetensors", PLACEHOLDER)
    stored = [risk for risk in component.risks if risk.category == "invalid_safetensors"]
    assert [(risk.severity.value, risk.detail) for risk in stored] == [
        ("high", "The declared SafeTensors artifact has no corroborated structural safety.")
    ]
    derived = _intrinsic_model_risks(component)
    assert [risk.category for risk in derived].count("invalid_safetensors") == 1
    older = component.model_copy(update={"properties": {}})
    assert "invalid_safetensors" in [risk.category for risk in older.risks]


def test_a_zip_archive_named_as_gguf_is_not_recorded_as_gguf(tmp_path: Path) -> None:
    _zip(tmp_path / "model.gguf")
    (component,) = ModelScanner().scan(tmp_path).components
    _unestablished(component, "llama.cpp")
    assert component.properties["format_inspection"].startswith("ZIP archive")
    assert component.properties["gguf_metadata"] == "not inspected: the file is a ZIP archive"
    assert component.serialization_safety is SerializationSafety.UNKNOWN


@pytest.mark.parametrize(
    ("name", "content", "recorded", "rating", "explanation"),
    [
        ("model.onnx", PLACEHOLDER, "onnx", "unknown", NO_VALIDATOR),
        ("model.tflite", PLACEHOLDER, "tensorflow-lite", "unknown", NO_VALIDATOR),
        ("model.ggml", PLACEHOLDER, "llama.cpp-legacy", "unknown", NO_VALIDATOR),
        # The content of a pickle-family name decides its rating, not what is recorded.
        ("model.pkl", PLACEHOLDER, "pickle", "unknown", PICKLE_NAME_UNEVIDENCED),
        ("model.pkl", INERT_PICKLE, "pickle", "unsafe-code-execution", BINARY_PICKLE),
    ],
    ids=["onnx", "tflite", "ggml", "pickle-name-without-a-pickle", "pickle-name-with-a-pickle"],
)
def test_a_suffix_without_a_header_check_is_recorded_from_the_name(
    tmp_path: Path, name: str, content: bytes, recorded: str, rating: str, explanation: str
) -> None:
    component = _scan(tmp_path, name, content)
    assert component.serialization_format == recorded
    assert component.model_type == "foundation"
    assert component.serialization_safety.value == rating
    assert component.properties == {"format_inspection": explanation}


def _guide(page: str) -> str:
    return " ".join((DOCS / page).read_text(encoding="utf-8").split())


def test_the_documented_rating_of_a_pickle_family_name_is_the_one_its_content_gets(
    tmp_path: Path,
) -> None:
    # The name still gives the record its format; since #254 it no longer gives the rating.
    text = _scan(tmp_path / "text", "model.pkl", PLACEHOLDER)
    zeros = _scan(tmp_path / "zeros", "embeddings.bin", b"\0" * 64)
    pickled = _scan(tmp_path / "pickle", "model.pkl", INERT_PICKLE)
    assert [
        (component.serialization_format, component.serialization_safety.value)
        for component in (text, zeros, pickled)
    ] == [
        ("pickle", "unknown"),
        ("pytorch-legacy", "unknown"),
        ("pickle", "unsafe-code-execution"),
    ]
    limitations = _guide("known-limitations.md")
    assert "pickle-family name the same, rated `unsafe-code-execution`" not in limitations
    assert (
        "one under a pickle-family name the same, rated by its first 64 KiB: that text saved "
        "as `model.pkl` is `unknown`, and a pickle is `unsafe-code-execution`"
    ) in limitations
    assert (
        "the content of a pickle-family name decides its rating only, and a zero-filled "
        "`embeddings.bin` rated `unknown` is still recorded as `pytorch-legacy`"
    ) in _guide("model-integrity.md")


def test_the_documented_unknown_format_names_both_names_the_content_does_not_bear_out(
    tmp_path: Path,
) -> None:
    for name in ("model.pkl", "model.gguf"):
        component = _scan(tmp_path / name, name, PLACEHOLDER)
        assert component.serialization_safety is SerializationSafety.UNKNOWN
        assert UNKNOWN_FORMAT in _findings(component)
    (row,) = [
        line
        for line in (DOCS / "finding-catalog.md").read_text(encoding="utf-8").splitlines()
        if line.startswith("| `serialization_format_unknown` |")
    ]
    assert "a pickle-family name whose inspected prefix shows no pickle evidence" in row
    assert "a file named as GGUF that is not one" in row
    classes = _guide("security-model.md")
    assert "are rated by their inspected content, not by the name alone" in classes
    assert "on file name alone" not in classes
    assert (
        "A record's format and model type come from the file name, except under `.gguf` "
        "and `.safetensors`"
    ) in classes


def test_the_adapter_type_of_a_directory_is_not_given_to_an_unestablished_file(
    tmp_path: Path,
) -> None:
    (tmp_path / "adapter_config.json").write_text(json.dumps({"peft_type": "LORA"}))
    (tmp_path / "adapter_model.safetensors").write_bytes(_safetensors())
    (tmp_path / "notes.safetensors").write_bytes(PLACEHOLDER)
    adapter, notes = ModelScanner().scan(tmp_path).components
    assert (adapter.model_type, adapter.serialization_format) == ("adapter", "safe-tensors")
    assert (notes.model_type, notes.serialization_format) == (None, None)
    assert notes.derivation_type == adapter.derivation_type == "LORA"


def _scanned(root: Path) -> AIBOM:
    scanner = ModelScanner()
    collected: dict[str, Any] = {}
    for component in scanner.scan(root).components:
        merge_collected(collected, component, scanner.name, None)
    return AIBOM(components=list(collected.values()))


def test_a_file_named_as_safetensors_still_fails_the_risk_gate_at_any_score(
    tmp_path: Path,
) -> None:
    (tmp_path / "model.safetensors").write_bytes(PLACEHOLDER)
    (tmp_path / "model.gguf").write_bytes(PLACEHOLDER)
    bom = _scanned(tmp_path)
    for stripped in (False, True):
        if stripped:
            for component in bom.components:
                component.risks = []
        passed, report = RiskScorer(fail_threshold=1000, fail_on_severity="none").passes_gate(bom)
        assert not passed
        assert "SafeTensors structural safety is unverified" in report.gate_reasons
        assert [
            f.component_ref for f in report.findings if f.category == "invalid_safetensors"
        ] == ["model:model.safetensors"]


def _properties(component: dict[str, Any]) -> dict[str, str]:
    return {entry["name"]: entry["value"] for entry in component["properties"]}


def test_exports_name_no_format_or_model_type_that_was_not_established(tmp_path: Path) -> None:
    (tmp_path / "model.gguf").write_bytes(_gguf())
    (tmp_path / "not_a_model.gguf").write_bytes(PLACEHOLDER)
    bom = _scanned(tmp_path)
    document = CycloneDXGenerator().generate(bom)
    assert [component["type"] for component in document["components"]] == [
        "machine-learning-model",
        "machine-learning-model",
    ]
    valid, disguised = (
        _properties(component)
        for component in sorted(document["components"], key=lambda c: c["name"])
    )
    assert valid["nexus-symbiote:serializationFormat"] == "llama.cpp"
    assert valid["nexus-symbiote:modelType"] == "foundation"
    assert not {"nexus-symbiote:serializationFormat", "nexus-symbiote:modelType"} & set(disguised)
    assert disguised["nexus-symbiote:serializationSafety"] == "unknown"
    native = json.loads(disguised["nexus-symbiote:component"])
    assert native["properties"]["named_format"] == "llama.cpp"
    assert native["properties"]["format_inspection"] == GGUF_MISMATCH
    assert CycloneDXGenerator.recover(document).components == bom.components
    elements = {
        node["name"]: node
        for node in SPDXGenerator().generate(bom)["@graph"]
        if node.get("type") == "ai_AIPackage"
    }
    assert elements["model.gguf"]["ai_typeOfModel"] == ["foundation"]
    assert "ai_typeOfModel" not in elements["not_a_model.gguf"]


def _scan_to(runner: CliRunner, project: Path, out: Path) -> dict[str, Any]:
    """Scan with the CLI and return the document it wrote."""
    result = runner.invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    document: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    return document


def _model_record(document: dict[str, Any]) -> dict[str, Any]:
    (record,) = [c for c in document["components"] if c["component_type"] == "model"]
    return record


def test_the_reported_file_is_inventoried_without_a_format(
    runner: CliRunner, tmp_path: Path
) -> None:
    project = tmp_path / "project"
    (project / "tests" / "fixtures").mkdir(parents=True)
    (project / "tests" / "fixtures" / "not_a_model.gguf").write_bytes(PLACEHOLDER)
    out = tmp_path / "bom.json"
    record = _model_record(_scan_to(runner, project, out))
    assert record["name"] == "tests/fixtures/not_a_model.gguf"
    assert "serialization_format" not in record and "model_type" not in record
    assert record["serialization_safety"] == "unknown"
    assert record["properties"] == {
        "format_inspection": GGUF_MISMATCH,
        "named_format": "llama.cpp",
        "gguf_metadata": "not inspected: GGUF metadata could not be read",
    }
    assert [risk["category"] for risk in record["risks"]] == [
        "serialization_format_unknown",
        "signing_status",
    ]
    validated = runner.invoke(main, ["validate", str(out), "--project", str(project)])
    assert f"UNKNOWN [model:tests/fixtures/not_a_model.gguf] {GGUF_MISMATCH}" in validated.output


def test_an_inventory_collected_before_differs_from_a_new_collection(
    runner: CliRunner, tmp_path: Path
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "not_a_model.gguf").write_bytes(PLACEHOLDER)
    new, old = tmp_path / "new.json", tmp_path / "old.json"
    document = _scan_to(runner, project, new)
    record = _model_record(document)
    # The record that releases up to 0.2.0 wrote for the same file.
    record |= {"serialization_format": "llama.cpp", "model_type": "foundation"}
    record["properties"] = {
        "format_inspection": NO_VALIDATOR,
        "gguf_metadata": record["properties"]["gguf_metadata"],
    }
    old.write_text(json.dumps(document), encoding="utf-8")
    drift = runner.invoke(main, ["diff", str(old), str(new)])
    assert drift.exit_code == 1, drift.output
    assert (
        "[MEDIUM] Medium change in 'not_a_model.gguf': properties.format_inspection changed.; "
        "properties.named_format added.; model_type changed.; serialization_format changed."
    ) in drift.output
    mismatch = "Missing or mismatched local component from model files: model:not_a_model.gguf"
    reconcile = ["validate", "--project", str(project)]
    assert mismatch in runner.invoke(main, [*reconcile, str(old)]).output
    assert mismatch not in runner.invoke(main, [*reconcile, str(new)]).output
