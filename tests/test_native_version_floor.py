"""Native format 1.2.0: the fields it adds, the version floor on write, and older readers."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core import models
from nexus_symbiote.core.aibom import AIBOM, NativeFormatError, required_spec_version
from nexus_symbiote.core.models import (
    NATIVE_SPEC_VERSION,
    AIBOMMetadata,
    CompletenessClaim,
    MCPServerComponent,
    ModelComponent,
    supported_spec_versions,
)
from nexus_symbiote.validators.completeness import CompletenessValidator
from tests.support import misbehaving_launcher

MODEL_REF = "model-ref:huggingface/acme/encoder"
PACKAGE_URL = "pkg:huggingface/acme/encoder@0123456789abcdef0123456789abcdef01234567"


def _model(**fields: str) -> ModelComponent:
    return ModelComponent(bom_ref=MODEL_REF, name="acme/encoder", **fields)


def _shadowscan_v2() -> AIBOM:
    claim = CompletenessClaim(
        scope="shadowscan-imported",
        source_report_content_profile="nexus-symbiote/shadowscan-content/v2",
    )
    return AIBOM(metadata=AIBOMMetadata(completeness=claim))


# Each field 1.2.0 added: an inventory that records it, where the native document holds
# it, and the value written there.
FEATURES: dict[str, tuple[Callable[[], AIBOM], Callable[[dict], object], str]] = {
    "model licence": (
        lambda: AIBOM(components=[_model(license="Apache-2.0")]),
        lambda document: document["components"][0]["license"],
        "Apache-2.0",
    ),
    "model package URL": (
        lambda: AIBOM(components=[_model(package_url=PACKAGE_URL)]),
        lambda document: document["components"][0]["package_url"],
        PACKAGE_URL,
    ),
    "ShadowScan content v2": (
        _shadowscan_v2,
        lambda document: document["metadata"]["completeness"]["source_report_content_profile"],
        "nexus-symbiote/shadowscan-content/v2",
    ),
}


def _document(bom: AIBOM, version: str) -> dict:
    """The native document of ``bom`` as a producer that declared ``version`` wrote it."""
    document = bom.to_dict()
    document["metadata"]["spec_version"] = version
    return document


def test_this_build_writes_1_2_0_and_reads_every_earlier_minor():
    assert NATIVE_SPEC_VERSION == "1.2.0"
    assert supported_spec_versions() == "1.0.x, 1.1.x, 1.2.x"
    assert AIBOM().metadata.spec_version == "1.2.0"


def test_the_new_model_fields_are_absent_unless_set(tmp_path):
    path = tmp_path / "bom.json"
    AIBOM(components=[_model()]).save(path)
    [model] = json.loads(path.read_text(encoding="utf-8"))["components"]
    assert "package_url" not in model and "license" not in model
    assert set(ModelComponent.model_fields) >= {"package_url", "license"}


@pytest.mark.parametrize("version", ["1.0.0", "1.1.0", "1.1.9"])
@pytest.mark.parametrize("feature", sorted(FEATURES))
def test_an_earlier_declared_format_with_a_1_2_field_loads_but_is_not_written(
    tmp_path, feature, version
):
    build, _, _ = FEATURES[feature]
    source = tmp_path / "declared.json"
    source.write_text(json.dumps(_document(build(), version)), encoding="utf-8")
    loaded = AIBOM.load(source)
    assert loaded.metadata.spec_version == version
    assert required_spec_version(loaded) == "1.2.0"
    message = (
        f"It declares native format {version} but uses fields of 1.2.0, which readers of "
        f"{version} refuse."
    )
    with pytest.raises(NativeFormatError) as raised:
        loaded.to_native_json()
    assert str(raised.value) == message
    target = tmp_path / "rewritten.json"
    with pytest.raises(NativeFormatError, match="uses fields of 1.2.0"):
        loaded.save(target)
    assert not target.exists()


@pytest.mark.parametrize("feature", sorted(FEATURES))
def test_a_1_2_document_with_a_1_2_field_round_trips(tmp_path, feature):
    build, recorded, value = FEATURES[feature]
    path = tmp_path / "bom.json"
    build().save(path)
    written = path.read_text(encoding="utf-8")
    assert recorded(json.loads(written)) == value
    loaded = AIBOM.load(path)
    assert loaded.metadata.spec_version == "1.2.0"
    assert loaded.to_native_json() == written


@pytest.mark.parametrize("version", ["1.0.0", "1.1.0"])
def test_without_a_1_2_field_an_earlier_format_is_written_as_declared(tmp_path, version):
    bom = AIBOM(components=[_model(resolved_revision="0" * 40)])
    bom.metadata.spec_version = version
    assert required_spec_version(bom) == version
    path = tmp_path / "bom.json"
    bom.save(path)
    assert AIBOM.load(path).metadata.spec_version == version


def test_the_required_version_never_lowers_the_declared_one():
    later = AIBOM(components=[_model(license="MIT")])
    later.metadata.spec_version = "1.2.5"
    assert required_spec_version(later) == "1.2.5"
    later.to_native_json()
    earlier = AIBOM(components=[_model(license="MIT")])
    earlier.metadata.spec_version = "1.1.0"
    assert required_spec_version(earlier) == "1.2.0"


@pytest.mark.parametrize(
    ("version", "shown"), [("1.3.0", "version 1.3.0"), ("\x1b[2J", "an unrecognised version")]
)
def test_a_version_this_build_cannot_read_is_not_written(tmp_path, version, shown):
    bom = AIBOM(components=[_model()])
    bom.metadata.spec_version = version
    with pytest.raises(NativeFormatError) as raised:
        bom.save(tmp_path / "bom.json")
    assert f"Native format {shown} is not supported by this build" in str(raised.value)
    assert "\x1b" not in str(raised.value)
    assert not (tmp_path / "bom.json").exists()


def test_a_reader_of_1_1_refuses_a_1_2_inventory_and_says_to_upgrade(tmp_path, monkeypatch):
    # The reader check of builds that write 1.1.0 is this one with 1.2 left out.
    path = tmp_path / "bom.json"
    AIBOM(components=[_model(license="MIT")]).save(path)
    monkeypatch.setattr(models, "SUPPORTED_SPEC_MINORS", {1: (0, 1)})
    with pytest.raises(NativeFormatError) as raised:
        AIBOM.load(path)
    assert str(raised.value) == (
        "Native format version 1.2.0 is not supported by this build (supported: 1.0.x, "
        "1.1.x); upgrade nexus-symbiote or re-collect the inventory."
    )


# verify-live --record rewrites a loaded inventory.


def _record(tmp_path: Path, document: dict) -> dict:
    project = tmp_path / "checkout"
    project.mkdir(parents=True)
    inventory = project / "bom.json"
    inventory.write_text(json.dumps(document), encoding="utf-8")
    operator = tmp_path / "operator"
    operator.mkdir()
    launcher = operator / "launcher"
    pin = misbehaving_launcher(launcher, operator / "launcher.log")
    policy = operator / "launch-policy.json"
    policy.write_text(json.dumps({"mcp:weather": {"command": str(launcher), "sha256": pin}}))
    args = ["--live", "verify-live", str(inventory), "--project", str(project)]
    args += ["--launch-policy", str(policy), "--record", "--accept-drift"]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    candidate: dict = json.loads(result.stdout)
    return candidate


def _stdio_inventory(*components: ModelComponent) -> AIBOM:
    server = MCPServerComponent(bom_ref="mcp:weather", name="weather", transport="stdio")
    return AIBOM(components=[server, *components])


@pytest.mark.usefixtures("nonisolated_pinned_fixtures")
def test_verify_live_record_raises_a_1_1_inventory_to_the_version_its_content_needs(tmp_path):
    licensed = _document(_stdio_inventory(_model(license="Apache-2.0")), "1.1.0")
    candidate = _record(tmp_path / "licensed", licensed)
    assert candidate["metadata"]["spec_version"] == "1.2.0"
    [model] = [c for c in candidate["components"] if c["bom_ref"] == MODEL_REF]
    assert model["license"] == "Apache-2.0"
    AIBOM.from_native(candidate)
    plain = _document(_stdio_inventory(_model()), "1.1.0")
    assert _record(tmp_path / "plain", plain)["metadata"]["spec_version"] == "1.1.0"


# validate --project explains a mismatch with an inventory of an earlier format.


def _mismatched(tmp_path: Path, version: str) -> tuple[AIBOM, Path]:
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Read-only triage.\n")
    target = tmp_path / "bom.json"
    scanned = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(target)]
    )
    assert scanned.exit_code == 0, scanned.output
    document = json.loads(target.read_text(encoding="utf-8"))
    for component in document["components"]:
        if component["bom_ref"] == "prompt:CLAUDE.md":
            component["content_hash"] = "sha256:" + "0" * 64
    document["metadata"]["spec_version"] = version
    target.write_text(json.dumps(document), encoding="utf-8")
    return AIBOM.load(target), project


RECOLLECT_1_1 = (
    "The inventory uses native format 1.1, written by an earlier release whose collectors "
    "record less; re-collect it with this version before reconciling it with a project."
)
RECOLLECT_1_0 = (
    "The inventory uses native format 1.0, which records absolute scan-host paths; "
    "re-collect it with this version before reconciling it with a project."
)


@pytest.mark.parametrize(
    ("version", "hint"),
    [("1.0.0", RECOLLECT_1_0), ("1.1.0", RECOLLECT_1_1), ("1.1.3", RECOLLECT_1_1), ("1.2.0", None)],
)
def test_a_mismatched_inventory_of_an_earlier_format_is_told_to_re_collect(tmp_path, version, hint):
    bom, project = _mismatched(tmp_path, version)
    report = CompletenessValidator().validate_against_project(bom, project)
    assert report.basis == "project-reconciliation-failed"
    hints = [
        (issue.severity, issue.description) for issue in report.issues if issue.surface == "format"
    ]
    assert hints == ([] if hint is None else [("info", hint)])


def test_validate_prints_the_1_1_re_collect_hint(tmp_path):
    _, project = _mismatched(tmp_path, "1.1.0")
    result = CliRunner().invoke(
        main,
        ["validate", str(tmp_path / "bom.json"), "--project", str(project), "--no-project-policy"],
    )
    assert result.exit_code == 1
    assert "written by an earlier release whose collectors record less" in result.output
