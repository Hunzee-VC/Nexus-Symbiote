"""Scanner failures retain useful codes without publishing hostile input values."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import ModelComponent
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.scanners.prompt import PromptScanner

CANARY = "SCANNER_ERROR_SECRET_712f41"


@pytest.mark.parametrize(
    ("error_type", "code"),
    [
        (ValueError, "scanner-input-error"),
        (TypeError, "scanner-input-error"),
        (RecursionError, "scanner-input-error"),
        (OSError, "scanner-io-error"),
        (RuntimeError, "scanner-internal-error"),
    ],
)
def test_exception_payload_is_absent_from_console_and_saved_bom(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error_type: type[Exception], code: str
) -> None:
    def fail(*args, **kwargs):
        raise error_type(f"input payload: api_key={CANARY}")

    monkeypatch.setattr(PromptScanner, "scan", fail)
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--scanner", "prompt", "--no-project-policy", "-o", str(output)],
    )
    assert result.exit_code == 1
    assert CANARY not in result.output + output.read_text(encoding="utf-8")
    coverage = json.loads(output.read_text(encoding="utf-8"))["metadata"]["completeness"]
    assert coverage["scanner_status"]["prompt"] == "failed"
    assert len(coverage["scan_failures"]) == 1
    assert coverage["scan_failures"][0].startswith("prompt: ")
    assert code in coverage["scan_failures"][0]


def test_pydantic_input_values_are_absent_from_saved_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args, **kwargs):
        ModelComponent(bom_ref="model:bad", name="bad", derivation_type={"api_key": CANARY})

    monkeypatch.setattr(PromptScanner, "scan", fail)
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--scanner", "prompt", "--no-project-policy", "-o", str(output)],
    )
    assert result.exit_code == 1
    assert CANARY not in result.output + output.read_text(encoding="utf-8")
    assert "scanner-validation-error" in output.read_text(encoding="utf-8")
    failures = json.loads(output.read_text(encoding="utf-8"))["metadata"]["completeness"][
        "scan_failures"
    ]
    assert "input_value" not in repr(failures)


def test_failure_boundary_does_not_evaluate_exception_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class HostileError(Exception):
        def __str__(self):
            raise AssertionError("exception text must not be evaluated")

    def fail(*args, **kwargs):
        raise HostileError()

    monkeypatch.setattr(PromptScanner, "scan", fail)
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--scanner", "prompt", "--no-project-policy", "-o", str(output)],
    )
    assert result.exit_code == 1
    assert "scanner-internal-error" in output.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "field", ["peft_type", "quantization_method", "quant_method", "trust_remote_code"]
)
def test_invalid_model_config_retains_artifact_and_safe_failure_location(
    tmp_path: Path, field: str
) -> None:
    (tmp_path / "model.pkl").write_bytes(b"\x80\x04N.")
    (tmp_path / "config.json").write_text(json.dumps({field: {"api_key": CANARY}}))
    collected = ModelScanner().scan(tmp_path)
    assert len(collected.components) == 1
    assert collected.scan_failures
    assert field in collected.scan_failures[0]
    assert CANARY not in repr(collected)

    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--scanner", "model", "--no-project-policy", "-o", str(output)],
    )
    assert result.exit_code == 1
    assert CANARY not in result.output + output.read_text(encoding="utf-8")
    assert (
        json.loads(output.read_text(encoding="utf-8"))["metadata"]["completeness"][
            "scanner_status"
        ]["model"]
        == "failed"
    )


@pytest.mark.parametrize("config", [[], True, "SCANNER_ERROR_SECRET_712f41"])
def test_nonobject_model_configuration_is_a_coverage_failure(tmp_path: Path, config) -> None:
    (tmp_path / "model.pkl").write_bytes(b"\x80\x04N.")
    (tmp_path / "config.json").write_text(json.dumps(config))
    collected = ModelScanner().scan(tmp_path)
    assert len(collected.components) == 1
    assert any("model configuration must be an object" in e for e in collected.scan_failures)
    assert CANARY not in repr(collected)
