"""The environment SBOM describes exactly what pip reports and validates against the schema."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nexus_symbiote.generators.validation import validate_cyclonedx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from environment_sbom import build_sbom  # noqa: E402

LINUX = {
    "implementation_name": "cpython",
    "implementation_version": "3.12.13",
    "os_name": "posix",
    "platform_machine": "x86_64",
    "platform_python_implementation": "CPython",
    "platform_release": "6.8.0",
    "platform_system": "Linux",
    "platform_version": "#1 SMP",
    "python_full_version": "3.12.13",
    "python_version": "3.12",
    "sys_platform": "linux",
}

INSPECT = {
    "version": "1",
    "pip_version": "26.0",
    "environment": LINUX,
    "installed": [
        {
            "metadata": {
                "name": "Nexus_Symbiote",
                "version": "0.1.0",
                "summary": "AgentBOM",
                "requires_dist": ["click<9,>=8.1", "sigstore>=4.4; extra == 'sigstore'"],
                "license_expression": "MIT AND Apache-2.0",
            }
        },
        {
            "metadata": {
                "name": "click",
                "version": "8.5.0",
                "classifier": ["License :: OSI Approved :: BSD License"],
            }
        },
    ],
}


def test_sbom_is_valid_deterministic_and_limited_to_installed_dependencies():
    when = datetime(2026, 11, 4, 21, 30, 8, tzinfo=UTC)
    first = build_sbom(INSPECT, timestamp=when)
    second = build_sbom(json.loads(json.dumps(INSPECT)), timestamp=when)
    assert first == second
    assert validate_cyclonedx(first) == []
    assert first["metadata"]["timestamp"] == "2026-11-04T21:30:08Z"
    refs = {c["bom-ref"] for c in first["components"]}
    assert refs == {"pkg:pypi/nexus-symbiote@0.1.0", "pkg:pypi/click@8.5.0"}
    edges = {d["ref"]: d["dependsOn"] for d in first["dependencies"]}
    assert edges["pkg:pypi/nexus-symbiote@0.1.0"] == ["pkg:pypi/click@8.5.0"]
    assert set(edges) == refs
    assert first["components"][1]["licenses"] == [{"expression": "MIT AND Apache-2.0"}]
    assert first["components"][0]["licenses"] == [
        {"license": {"name": "OSI Approved :: BSD License"}}
    ]


def _dist(name, *requires):
    return {"metadata": {"name": name, "version": "1.0", "requires_dist": list(requires)}}


def _edges(environment, *records):
    document = build_sbom(
        {"environment": environment, "installed": list(records)}, timestamp=datetime.now(UTC)
    )
    return {
        d["ref"].removeprefix("pkg:pypi/").removesuffix("@1.0"): [
            ref.removeprefix("pkg:pypi/").removesuffix("@1.0") for ref in d["dependsOn"]
        ]
        for d in document["dependencies"]
    }


def test_edges_follow_markers_and_active_extras_not_mere_presence():
    records = (
        _dist(
            "nexus-symbiote",
            "click",
            "hatchling; extra == 'dev'",
            "tomli; python_version < '3.11'",
            "pywin32; sys_platform == 'win32'",
            "nexus-symbiote[cyclonedx]; extra == 'all'",
        ),
        _dist("root", "app[full]"),
        _dist("app", "lib", "lib[Fast]; extra == 'full'", "cli-only; extra == 'cli'"),
        _dist(
            "lib",
            "speedups; extra == 'fast'",
            "slowpath; extra == 'slow'",
            "lib[more]; extra == 'fast'",
            "other; extra == 'more'",
        ),
        *(_dist(name) for name in ("click", "hatchling", "tomli", "pywin32")),
        *(_dist(name) for name in ("speedups", "slowpath", "other", "cli-only")),
    )
    edges = _edges(LINUX, *records)
    assert edges["nexus-symbiote"] == ["click"]
    assert edges["root"] == ["app"]
    assert edges["app"] == ["lib"]
    assert edges["lib"] == ["other", "speedups"]
    windows = _edges({**LINUX, "sys_platform": "win32"}, *records)
    assert windows["nexus-symbiote"] == ["click", "pywin32"]


@pytest.mark.parametrize(
    "broken",
    [
        {"environment": LINUX, "installed": "no"},
        {"environment": LINUX, "installed": [{"metadata": {"name": "a", "version": "1"}}] * 2},
        {"installed": []},
        {"environment": {"python_full_version": "3.12.13"}, "installed": []},
    ],
)
def test_malformed_or_duplicate_inventories_are_rejected(broken):
    with pytest.raises(ValueError):
        build_sbom(broken, timestamp=datetime.now(UTC))


def test_cli_writes_a_file_from_pip_inspect(tmp_path):
    source = tmp_path / "inspect.json"
    source.write_text(json.dumps(INSPECT))
    out = tmp_path / "environment.cdx.json"
    script = Path(__file__).resolve().parents[1] / "scripts" / "environment_sbom.py"
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-I", str(script), str(source), "--out", str(out)],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
        env={
            "PATH": "",
            "SOURCE_DATE_EPOCH": "1793827808",
            "PYTHONPATH": str(script.parents[1] / "src"),
        },
    )
    assert completed.returncode == 0, completed.stderr
    document = json.loads(out.read_text())
    assert document["metadata"]["timestamp"] == "2026-11-04T21:30:08Z"
    assert validate_cyclonedx(document) == []


def test_every_installed_distribution_must_be_locked_at_its_version():
    from environment_sbom import locked_versions

    root = Path(__file__).resolve().parents[1]
    lock = (locked_versions((root / "requirements-action.lock").read_text()), "0" * 64)
    click = locked_versions((root / "requirements-action.lock").read_text())["click"]
    inspect = json.loads(json.dumps(INSPECT))
    inspect["installed"][1]["metadata"]["version"] = next(iter(click))
    document = build_sbom(inspect, timestamp=datetime.now(UTC), lock=lock)
    assert document["metadata"]["properties"] == [
        {"name": "nexus-symbiote:lock-sha256", "value": "0" * 64}
    ]
    inspect["installed"][1]["metadata"]["version"] = "0.0.1"
    with pytest.raises(ValueError, match="click==0.0.1 is installed but not locked"):
        build_sbom(inspect, timestamp=datetime.now(UTC), lock=lock)


@pytest.mark.parametrize(
    "record",
    [
        {"metadata": None},
        {"metadata": {"name": "x y", "version": "1"}},
        {"metadata": {"name": "a"}},
    ],
)
def test_a_record_that_cannot_be_represented_fails_instead_of_vanishing(record):
    inspect = {**INSPECT, "installed": [*INSPECT["installed"], record]}
    with pytest.raises(ValueError):
        build_sbom(inspect, timestamp=datetime.now(UTC))


def test_a_legacy_license_name_is_kept_but_pasted_licence_text_is_not():
    def licences(value):
        record = {"metadata": {"name": "legacy", "version": "1", "license": value}}
        document = build_sbom(
            {"environment": LINUX, "installed": [record]}, timestamp=datetime.now(UTC)
        )
        return document["components"][0].get("licenses")

    assert licences("MIT") == [{"license": {"name": "MIT"}}]
    assert licences("Copyright (c) 2020\nPermission is hereby granted...") is None
