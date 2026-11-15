"""A report's repository and commit reach no inventory, export or log with a credential.

A clone URL in CI can carry a token as user information, and a producer may paste one
anywhere in either field. The report digest still binds the exact bytes, so recording
the values redacted loses nothing verification needs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.shadowscan import ShadowScanImporter
from nexus_symbiote.utils import secrets

FIXTURES = Path(__file__).parent / "fixtures"
CYCLONEDX = FIXTURES / "shadowscan-producer/cyclonedx-agent-model.json"
TOKEN = "ghs_" + "Q7" * 18
PASSWORD = "FakeClonePassw0rd"  # noqa: S105 - synthetic sentinel
SECRETS = (TOKEN, PASSWORD, TOKEN[:12])

NATIVE = {
    "version": "0.1.4",
    "started_at": "2026-01-01T00:00:00Z",
    "finished_at": "2026-01-01T00:00:01Z",
    "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
    "stats": [
        {
            "connector": "code.filesystem",
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:00:01Z",
            "errors": [],
            "skipped": False,
            "incomplete": False,
        }
    ],
    "findings": [
        {
            "id": "ss-1",
            "kind": "agent",
            "surface": "code",
            "confidence": 0.5,
            "first_seen": None,
            "last_seen": "2026-01-01T00:00:01Z",
        }
    ],
}

REDACTED_REPOSITORIES = [
    (
        f"https://x-access-token:{TOKEN}@github.example.test/o/r",
        "https://***@github.example.test/o/r",
    ),
    (f"https://ci:{PASSWORD}@git.example.test/o/r.git", "https://***@git.example.test/o/r.git"),
    (f"https://{PASSWORD}@git.example.test/o/r", "https://***@git.example.test/o/r"),
    ("ssh://git@git.example.test/o/r.git", "ssh://***@git.example.test/o/r.git"),
    (f"https://u:{PASSWORD}@x@git.example.test/o/r", "https://***@git.example.test/o/r"),
    (f"git+https://ci:{PASSWORD}@git.example.test/o/r", "git+https://***@git.example.test/o/r"),
    (f"HTTPS://ci:{PASSWORD}@git.example.test:8443/o/r", "HTTPS://***@git.example.test:8443/o/r"),
    (f"https://git.example.test/o/r?private_token={PASSWORD}", "https://git.example.test/o/r?***"),
    (f"https://git.example.test/o/r#access_token={PASSWORD}", "https://git.example.test/o/r#***"),
    (f"https://git.example.test/{TOKEN}/o/r", "https://git.example.test/***/o/r"),
    (
        f"https://git.example.test/o/r;password={PASSWORD}",
        "https://git.example.test/o/r;password=***",
    ),
    (f"https://{TOKEN}.git.example.test/o/r", "https://***.git.example.test/o/r"),
    (f"{TOKEN}@github.example.test:o/r.git", "***@github.example.test:o/r.git"),
    (
        f"repository https://ci:{PASSWORD}@git.example.test/o/r",
        "repository https://git.example.test",
    ),
    (f"https://ci:{PASSWORD}@evil.example.test\\@git.example.test/o/r", "[redacted-url]"),
    (f"https://ci:{PASSWORD}@git.example.test:x/o/r", "[redacted-url]"),
    (f"https://ci:{PASSWORD}@/o/r", "[redacted-url]"),
]
PLAIN_REPOSITORIES = [
    "https://example.test/acme/repo",
    "https://example.test:8443/acme/repo.git",
    "ssh://git.example.test/acme/repo.git",
    "https://[2001:db8::1]/acme/repo",
    "github.com/org/repo",
    "git@github.com:org/repo.git",
    "/path/to/repository",
    "räpö/repo",
    "https://example.test/acme/repo?",
]


def _native(**fields: str) -> bytes:
    return json.dumps({**NATIVE, **fields}).encode()


def _cyclonedx(**properties: str) -> bytes:
    data = json.loads(CYCLONEDX.read_text())
    data["metadata"]["properties"].extend(
        {"name": f"shadowscan:{name}", "value": value} for name, value in properties.items()
    )
    return json.dumps(data).encode()


@pytest.mark.parametrize(("value", "expected"), REDACTED_REPOSITORIES)
def test_a_repository_locator_keeps_its_path_and_loses_its_credentials(value, expected):
    assert secrets.redact_locator(value) == expected
    assert secrets.redact_locator(expected) == expected
    assert PASSWORD not in expected and TOKEN not in expected


@pytest.mark.parametrize("value", PLAIN_REPOSITORIES)
def test_a_repository_locator_without_credentials_is_kept_as_written(value):
    assert secrets.redact_locator(value) == value


@pytest.mark.parametrize("report", [_native, _cyclonedx], ids=["native", "cyclonedx"])
@pytest.mark.parametrize(("value", "expected"), REDACTED_REPOSITORIES)
def test_a_report_records_its_repository_without_credentials(report, value, expected):
    imported = ShadowScanImporter().parse_report(report(repository=value, commit=TOKEN))
    record = imported.discovery_verification
    assert record is not None
    assert (record.repository, record.commit) == (expected, "***")
    assert not any(secret in imported.to_native_bom().model_dump_json() for secret in SECRETS)


@pytest.mark.parametrize("report", [_native, _cyclonedx], ids=["native", "cyclonedx"])
@pytest.mark.parametrize("value", PLAIN_REPOSITORIES)
def test_a_report_records_an_ordinary_repository_and_commit_as_written(report, value):
    commit = "0123456789abcdef0123456789abcdef01234567"
    record = ShadowScanImporter().parse_report(report(repository=value, commit=commit))
    assert record.discovery_verification is not None
    assert record.discovery_verification.repository == value
    assert record.discovery_verification.commit == commit


@pytest.mark.parametrize("commit", [TOKEN, f"password={PASSWORD}", f"Bearer {PASSWORD}"])
def test_a_report_records_its_commit_without_credentials(commit):
    record = ShadowScanImporter().parse_report(_native(commit=commit)).discovery_verification
    assert record is not None
    assert TOKEN not in record.commit and PASSWORD not in record.commit
    assert "***" in record.commit


def _clear_ci(monkeypatch) -> None:
    for name in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "TF_BUILD", "JENKINS_URL"):
        monkeypatch.delenv(name, raising=False)
    for name in ("BUILDKITE", "DRONE", "TRAVIS"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("report", [_native, _cyclonedx], ids=["native", "cyclonedx"])
def test_no_inventory_export_or_warning_carries_a_report_credential(tmp_path, monkeypatch, report):
    _clear_ci(monkeypatch)
    project = tmp_path / "project"
    project.mkdir()
    repository = f"https://x-access-token:{TOKEN}@github.example.test/o/r"
    (project / "shadowscan.json").write_bytes(report(repository=repository, commit=TOKEN))
    runner = CliRunner()
    outputs = []
    for output_format in ("json", "cyclonedx", "spdx"):
        output = tmp_path / f"bom.{output_format}"
        result = runner.invoke(
            main,
            [
                "scan",
                str(project),
                "--no-project-policy",
                "--scanner",
                "shadowscan",
                "--report-only",
                "-f",
                output_format,
                "-o",
                str(output),
            ],
        )
        assert result.exit_code == 0, result.output
        outputs.append(output.read_text() + result.output)
    native = json.loads((tmp_path / "bom.json").read_text())
    record = native["metadata"]["completeness"]["discovery_verification"]
    assert record["repository"] == "https://***@github.example.test/o/r"
    assert record["commit"] == "***"
    validated = runner.invoke(main, ["validate", str(tmp_path / "bom.json")])
    assert "repository https://***@github.example.test/o/r, commit ***" in validated.output
    outputs.append(validated.output)
    assert not any(secret in text for secret in SECRETS for text in outputs)


def test_the_warning_redacts_a_credential_an_earlier_inventory_recorded(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)
    project = tmp_path / "project"
    project.mkdir()
    (project / "shadowscan.json").write_bytes(_native())
    bom = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        ["scan", str(project), "--no-project-policy", "--scanner", "shadowscan", "-o", str(bom)],
    )
    assert bom.exists(), result.output
    document = json.loads(bom.read_text())
    record = document["metadata"]["completeness"]["discovery_verification"]
    record["repository"] = f"https://ci:{PASSWORD}@git.example.test/o/r?token={TOKEN}"
    record["commit"] = TOKEN
    bom.write_text(json.dumps(document))
    validated = CliRunner().invoke(main, ["validate", str(bom)])
    assert "repository https://***@git.example.test/o/r?***, commit ***" in validated.output
    assert not any(secret in validated.output for secret in SECRETS)
