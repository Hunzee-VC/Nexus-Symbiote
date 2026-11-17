"""The comparative benchmark's corpus, matching rules and scorer.

These tests run no third-party tool. They check that the corpus agrees with its
ground truth, that the scorer's range is 0 to 100, and that each rule rejects the
output it is meant to reject.
"""

from __future__ import annotations

import json
import stat
import struct
import sys
import zlib
from dataclasses import asdict
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
BENCH_ROOT = ROOT / "benchmarks" / "comparative"


@pytest.fixture(scope="module")
def bench() -> ModuleType:
    sys.path.insert(0, str(BENCH_ROOT))
    try:
        import bench as package
        from bench import baselines, build, cdx, corpus, runner, score, tools

        del baselines, build, cdx, corpus, runner, score, tools
        return package
    finally:
        sys.path.remove(str(BENCH_ROOT))


@pytest.fixture(scope="module")
def built(bench: ModuleType) -> Any:
    return bench.corpus.build()


def _write_runs(bench: ModuleType, built: Any, work: Path, tool: Any, document: Any) -> None:
    """Record ``document(case, files)`` as the tool's CycloneDX output for every planned run."""
    for job in bench.runner.plan(tool, built):
        directory = bench.runner.run_dir(work, job)
        (directory / "out").mkdir(parents=True, exist_ok=True)
        files = job.case.files if job.files is None else job.files
        (directory / "out" / "bom.cdx.json").write_text(json.dumps(document(job.case, files)))
        (directory / "stdout.bin").write_bytes(b"")
        (directory / "stderr.bin").write_bytes(b"")
        record = bench.runner.Record(tool.id, job.case.id, job.variant, job.fmt, [], exit_code=0)
        (directory / "record.json").write_text(json.dumps(asdict(record)))


def test_corpus_agrees_with_its_ground_truth_and_its_pinned_digest(
    bench: ModuleType, built: Any
) -> None:
    assert bench.corpus.check(built) == []
    assert bench.corpus.digest(built) == bench.CORPUS_DIGEST
    assert len(built.discovery) == 41
    domains = {expect.domain for case in built.discovery for expect in case.expects}
    assert domains == set(bench.model.DOMAINS)


def test_committed_sources_hold_no_token_shaped_secret_and_no_invisible_character(
    bench: ModuleType,
) -> None:
    secrets = bench.cases_hostile.secret_values()
    assert len(set(secrets)) == len(secrets) == 10
    for path in sorted((BENCH_ROOT / "bench").glob("*.py")):
        source = path.read_text(encoding="utf-8")
        assert source.isascii(), path.name
        for value in secrets:
            assert value not in source, path.name


def test_binary_control_is_a_valid_image(bench: ModuleType) -> None:
    png = bench.build.PNG
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    offset = 8
    kinds = []
    while offset < len(png):
        (length,) = struct.unpack(">I", png[offset : offset + 4])
        kind = png[offset + 4 : offset + 8]
        data = png[offset + 8 : offset + 8 + length]
        (crc,) = struct.unpack(">I", png[offset + 8 + length : offset + 12 + length])
        assert zlib.crc32(kind + data) == crc
        kinds.append(kind)
        offset += 12 + length
    assert kinds == [b"IHDR", b"IDAT", b"IEND"]


def test_materialize_writes_links_pipes_and_modes(
    bench: ModuleType, built: Any, tmp_path: Path
) -> None:
    special = built.case("h13-special-files")
    bench.corpus.materialize(special, tmp_path / "special")
    assert stat.S_ISFIFO((tmp_path / "special" / "models" / "pipe.gguf").stat().st_mode)
    assert (tmp_path / "special" / "models" / "endless.safetensors").is_symlink()
    state = bench.corpus.tree_state(tmp_path / "special")
    assert state["models/pipe.gguf"] == "special"
    assert state["models/endless.safetensors"] == "link:/dev/zero"

    settings = built.case("a06-coding-agent-settings")
    bench.corpus.materialize(settings, tmp_path / "settings")
    assert (tmp_path / "settings" / ".claude" / "hooks" / "guard.sh").stat().st_mode & 0o100


def test_oracle_scores_one_hundred_and_an_empty_document_scores_zero(
    bench: ModuleType, built: Any, tmp_path: Path
) -> None:
    pytest.importorskip("cyclonedx")
    for tool, expected, letter in (
        (bench.baselines.ORACLE, 100.0, "A"),
        (bench.baselines.NULL, 0.0, "F"),
    ):
        bench.baselines.write(tool, built, tmp_path)
        result = bench.score.Scorer(built, tool, tmp_path).all()
        assert result["composite"] == expected
        assert result["grade"] == letter
        assert {pillar["score"] for pillar in result["pillars"].values()} == {expected / 100}
    conformance = bench.score.Scorer(built, bench.baselines.ORACLE, tmp_path).conformance()
    assert conformance["schema_checked"] == conformance["schema_valid"] == len(built.discovery)


def test_listing_every_file_the_same_way_is_not_discovery(
    bench: ModuleType, built: Any, tmp_path: Path
) -> None:
    def lister(case: Any, files: dict[str, bytes]) -> dict[str, Any]:
        components = [
            {
                "type": "file",
                "name": path,
                "properties": [{"name": "size", "value": str(len(data))}],
            }
            for path, data in files.items()
        ]
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": components,
        }

    tool = bench.tools.Tool("lister", "Lister", "-", "-", "test", {"cdx": ("lister",)})
    _write_runs(bench, built, tmp_path, tool, lister)
    scorer = bench.score.Scorer(built, tool, tmp_path)
    assert scorer.discovery()["found"] == 0
    assert scorer.precision()["score"] == 0.0
    assert scorer.hostile()["engaged"] == 0


def test_a_reported_decoy_is_not_rejected(bench: ModuleType, built: Any, tmp_path: Path) -> None:
    def credulous(case: Any, files: dict[str, bytes]) -> dict[str, Any]:
        document = bench.baselines.oracle_document(case, files)
        for decoy in case.decoys:
            document["components"].append({"type": "application", "name": " ".join(decoy.tokens)})
        return document

    tool = bench.tools.Tool("credulous", "Credulous", "-", "-", "test", {"cdx": ("credulous",)})
    _write_runs(bench, built, tmp_path, tool, credulous)
    precision = bench.score.Scorer(built, tool, tmp_path).precision()
    assert precision["reported"] == precision["total"] == 7
    assert precision["score"] == 0.0


def test_hostile_checks_fail_on_execution_disclosure_escape_and_control_sequences(
    bench: ModuleType, built: Any, tmp_path: Path
) -> None:
    tool = bench.baselines.ORACLE
    bench.baselines.write(tool, built, tmp_path)

    def run_dir(case_id: str) -> Path:
        return tmp_path / "runs" / tool.id / case_id / "base" / "cdx"

    def edit_record(case_id: str, **changes: Any) -> None:
        path = run_dir(case_id) / "record.json"
        record = json.loads(path.read_text())
        record.update(changes)
        path.write_text(json.dumps(record))

    edit_record("h03-launch-commands", canaries=["h03-mcp-launched"])
    edit_record("h07-parser-bombs", max_rss_kb=3 * 1024 * 1024)
    edit_record("h13-special-files", timed_out=True, exit_code=-9)
    edit_record("r07-literal-secrets-risky", secrets_in_state=1)
    (run_dir("h04-symlink-escape") / "stdout.bin").write_bytes(b"read outside-zx81-notes")
    secret = bench.cases_hostile.secret_values()[-1].encode()
    (run_dir("h09-secret-disclosure") / "stderr.bin").write_bytes(b"token=" + secret)
    (run_dir("h08-terminal-escapes") / "stdout.bin").write_bytes(
        b"server \x1b]0;h08-title-marker\x07"
    )

    hostile = bench.score.Scorer(built, tool, tmp_path).hostile()
    assert hostile["failed_checks"] == [
        "h03-launch-commands: no_execution",
        "h04-symlink-escape: no_escape",
        "h07-parser-bombs: bounded_memory",
        "h08-terminal-escapes: no_terminal_escape",
        "h09-secret-disclosure: no_secret_disclosure",
        "h13-special-files: completes",
        "r07-literal-secrets-risky: no_secret_disclosure",
    ]
    assert hostile["score"] < 1.0


def test_an_escaped_control_sequence_in_console_output_passes(
    bench: ModuleType, built: Any, tmp_path: Path
) -> None:
    tool = bench.baselines.ORACLE
    bench.baselines.write(tool, built, tmp_path)
    stdout = tmp_path / "runs" / tool.id / "h08-terminal-escapes" / "base" / "cdx" / "stdout.bin"
    stdout.write_bytes(b"server \\x1b]0;h08-title-marker and h08-clear-marker")
    assert bench.score.Scorer(built, tool, tmp_path).hostile()["failed_checks"] == []


def test_risk_credit_needs_a_machine_readable_difference(
    bench: ModuleType, built: Any, tmp_path: Path
) -> None:
    def silent(case: Any, files: dict[str, bytes]) -> dict[str, Any]:
        document = bench.baselines.oracle_document(case, files)
        document.pop("vulnerabilities", None)
        return document

    tool = bench.tools.Tool("silent", "Silent", "-", "-", "test", {"cdx": ("silent",)})
    _write_runs(bench, built, tmp_path, tool, silent)
    assert bench.score.Scorer(built, tool, tmp_path).risk()["score"] == 0.0

    risky = tmp_path / "runs" / tool.id / "r06-plaintext-server-risky" / "base" / "cdx"
    (risky / "stderr.bin").write_bytes(b"warning: plain HTTP endpoint")
    risk = bench.score.Scorer(built, tool, tmp_path).risk()
    assert risk["items"]["r06-plaintext-server"]["credit"] == 0.5
    assert risk["console_only"] == 1 and risk["machine_readable"] == 0


def test_random_identifiers_cost_strict_reproducibility_but_not_change_detection(
    bench: ModuleType, built: Any, tmp_path: Path
) -> None:
    counter = iter(range(10**6))

    def restless(case: Any, files: dict[str, bytes]) -> dict[str, Any]:
        document = bench.baselines.oracle_document(case, files)
        document["serialNumber"] = f"urn:uuid:00000000-0000-4000-8000-{next(counter):012d}"
        document["components"].append(
            {
                "type": "library",
                "name": "run",
                "bom-ref": f"11111111-2222-4333-8444-{next(counter):012d}",
            }
        )
        return document

    tool = bench.tools.Tool("restless", "Restless", "-", "-", "test", {"cdx": ("restless",)})
    _write_runs(bench, built, tmp_path, tool, restless)
    scorer = bench.score.Scorer(built, tool, tmp_path)
    assert scorer.reproducibility()["score"] == 0.5
    assert scorer.change()["score"] == 1.0


@pytest.mark.parametrize(
    ("left", "right", "equal"),
    [
        ("pkg:npm/%40scope/name@1.0.0", "pkg:npm/@scope/name@1.0.0", True),
        ("pkg:pypi/Mcp_Server.Git@2025.9.25", "pkg:pypi/mcp-server-git@2025.9.25", True),
        ("pkg:pypi/openai@1.51.2?repository_url=x#sub", "pkg:pypi/openai@1.51.2", True),
        ("pkg:pypi/openai@1.51.2", "pkg:pypi/openai@1.51.3", False),
        ("pkg:pypi/openai", "pkg:pypi/openai@1.51.2", False),
        ("pkg:npm/openai@1.51.2", "pkg:pypi/openai@1.51.2", False),
    ],
)
def test_package_urls_compare_by_type_name_and_version(
    bench: ModuleType, left: str, right: str, equal: bool
) -> None:
    assert (bench.cdx.normalize_purl(left) == bench.cdx.normalize_purl(right)) is equal


def test_package_url_syntax_check_rejects_spaces_and_missing_names(bench: ModuleType) -> None:
    assert bench.cdx.PURL.match("pkg:huggingface/sentence-transformers/all-MiniLM-L6-v2@abc")
    assert not bench.cdx.PURL.match("pkg:pypi/openai (import: openai)")
    assert not bench.cdx.PURL.match("pkg:pypi/")
    assert bench.cdx.normalize_purl("openai==1.0") is None


def test_version_and_word_matching_respect_boundaries(bench: ModuleType) -> None:
    assert bench.score._version("1.4.2", "version 1.4.2 of the bundle")
    assert not bench.score._version("1.4.2", "version 11.4.2")
    assert not bench.score._version("1.4.2", "version 1.4.2.1")
    assert not bench.score._version("1.4.2", "version 1.4.20")
    assert bench.score._word("mit", "license: mit")
    assert not bench.score._word("mit", "permit all")
    assert not bench.score._word("http", "https://example.org")


def test_elements_exclude_the_text_of_nested_elements(bench: ModuleType) -> None:
    document = {
        "metadata": {"component": {"type": "application", "name": "root"}},
        "components": [
            {
                "type": "application",
                "name": "outer",
                "bom-ref": "outer",
                "components": [{"type": "library", "name": "inner", "bom-ref": "inner"}],
            }
        ],
        "services": [{"name": "endpoint", "bom-ref": "svc"}],
        "dependencies": [{"ref": "outer", "dependsOn": ["svc"]}],
    }
    found = {
        element.ref or element.obj["name"]: element for element in bench.cdx.elements(document)
    }
    assert set(found) == {"root", "outer", "inner", "svc"}
    assert "inner" not in found["outer"].text
    assert found["inner"].parent == found["outer"].index
    assert bench.cdx.links(document)["svc"] == {"outer"}


def test_grades_and_weights_are_the_published_ones(bench: ModuleType) -> None:
    assert sum(bench.score.WEIGHTS.values()) == 100
    assert [bench.score.grade(value) for value in (85, 84.9, 70, 55, 40, 39.9)] == [
        "A",
        "B",
        "B",
        "C",
        "D",
        "F",
    ]
    low, high = bench.score.wilson(5, 10)
    assert 0.23 < low < 0.24 and 0.76 < high < 0.77
    assert bench.score.wilson(0, 0) == (0.0, 0.0)


def test_every_tool_adapter_writes_to_the_sandbox_output_directory(bench: ModuleType) -> None:
    measured = [tool for tool in bench.tools.TOOLS if tool.measured]
    assert len(bench.tools.TOOLS) == 12 and len(measured) == 9
    for tool in measured:
        argv = tool.argv("cdx", "/tools")
        assert argv[0].startswith("/tools/")
        assert any(part.endswith("/mnt/bench/out/bom.cdx.json") for part in argv)
    for tool in bench.tools.TOOLS:
        if not tool.measured:
            assert tool.not_measured and not tool.commands


def test_method_page_names_every_case_and_the_published_weights(
    bench: ModuleType, built: Any
) -> None:
    method = (BENCH_ROOT / "METHOD.md").read_text(encoding="utf-8")
    identifiers = [case.id for case in built.discovery]
    identifiers += [pair.id for pair in built.risk]
    identifiers += [hostile.case.id for hostile in built.hostile]
    identifiers += [mutation.id for mutation in built.mutations]
    for identifier in identifiers:
        assert f"`{identifier}`" in method, identifier
    for name, weight in bench.score.WEIGHTS.items():
        assert f"| {weight} |" in method, name
    readme = (BENCH_ROOT / "README.md").read_text(encoding="utf-8")
    assert bench.CORPUS_DIGEST in readme


def test_an_element_that_names_everything_states_no_relationship(
    bench: ModuleType, built: Any, tmp_path: Path
) -> None:
    def aggregating(case: Any, files: dict[str, bytes]) -> dict[str, Any]:
        document = bench.baselines.oracle_document(case, files)
        document["dependencies"] = []
        references = [
            {"name": "ref", "value": " ".join(expect.any_of[0])} for expect in case.expects
        ]
        document["components"].insert(
            0, {"type": "application", "name": "agent", "properties": references}
        )
        return document

    tool = bench.tools.Tool("aggregating", "Aggregating", "-", "-", "test", {"cdx": ("x",)})
    _write_runs(bench, built, tmp_path, tool, aggregating)
    scorer = bench.score.Scorer(built, tool, tmp_path)
    assert scorer.discovery()["score"] == 1.0
    assert scorer.fidelity()["score"] == 1.0
    assert scorer.relationships()["score"] == 0.0
    described = scorer.discovery()["items"]["a01.fs"]["as"]
    assert described == "component/application: fs-workspace"


def test_the_digest_of_its_file_identifies_a_component(
    bench: ModuleType, built: Any, tmp_path: Path
) -> None:
    import hashlib

    def anonymous(case: Any, files: dict[str, bytes]) -> dict[str, Any]:
        components = [
            {
                "type": "machine-learning-model",
                "name": f"artifact-{index}",
                "hashes": [
                    {"alg": "SHA-256", "content": hashlib.sha256(files[attr.values[0]]).hexdigest()}
                ],
            }
            for index, (expect, attr) in enumerate(
                (expect, attr)
                for expect in case.expects
                for attr in expect.attrs
                if attr.kind == "sha256"
            )
        ]
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": components,
        }

    tool = bench.tools.Tool("anonymous", "Anonymous", "-", "-", "test", {"cdx": ("x",)})
    _write_runs(bench, built, tmp_path, tool, anonymous)
    items = bench.score.Scorer(built, tool, tmp_path).discovery()["items"]
    hashed = {
        expect.id
        for case in built.discovery
        for expect in case.expects
        if any(attr.kind == "sha256" for attr in expect.attrs)
    }
    assert {key for key, value in items.items() if value["found"]} == hashed
    assert "m02.weights" in hashed and "a01.fs" not in hashed


def test_hostile_cases_that_target_model_files_have_a_model_survivor(built: Any) -> None:
    by_id = {hostile.case.id: hostile.case for hostile in built.hostile}
    for case_id in (
        "h04-symlink-escape",
        "h06-malformed-inputs",
        "h07-parser-bombs",
        "h10-filename-injection",
        "h13-special-files",
    ):
        domains = {expect.domain for expect in by_id[case_id].expects}
        assert {"agent", "model"} <= domains, case_id
