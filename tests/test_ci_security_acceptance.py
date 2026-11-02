"""Adversarial acceptance cases for incomplete advisory and CodeQL evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

from nexus_symbiote.scanners.live_mcp import HTTPReply

ROOT = Path(__file__).resolve().parents[1]


def script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


advisories = script("check_dependency_advisories")
codeql = script("check_codeql_sarif")
release_checksums = script("release_checksums")


class Transport:
    def __init__(self, *responses):
        self.responses = iter(responses)
        self.queries = []

    def request(self, endpoint, body, headers, *, timeout, max_bytes):
        assert endpoint == "https://api.osv.dev/v1/querybatch"
        assert 0 < timeout <= 20
        self.queries.append(json.loads(body)["queries"])
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return HTTPReply(200, {}, json.dumps(response).encode())


PACKAGES = [{"name": "requests", "version": "2.19.0"}]


def test_dependency_policy_follows_pages_without_losing_an_earlier_advisory():
    transport = Transport(
        {"results": [{"vulns": [{"id": "GHSA-example"}], "next_page_token": "second"}]},
        {"results": [{}]},
    )
    report = advisories.audit(PACKAGES, transport=transport)
    assert report["complete"] is True and report["passed"] is False
    assert report["advisories"] == [{**PACKAGES[0], "advisory_id": "GHSA-example"}]
    assert transport.queries[1][0] == {**transport.queries[0][0], "page_token": "second"}


@pytest.mark.parametrize(
    "responses",
    [
        ({"results": []},),
        ({"results": [{}], "error": {"message": "unknown query failure"}},),
        ({"results": [{"error": "unavailable"}]},),
        ({"results": [{"vulns": None}]},),
        ({"results": [{"vulns": [{"id": ""}]}]},),
        ({"results": [{"next_page_token": 1}]},),
        ({"results": [{"next_page_token": "cycle"}]}, {"results": [{"next_page_token": "cycle"}]}),
        (OSError("remote failure"),),
    ],
)
def test_dependency_policy_never_approves_incomplete_or_malformed_lookup(responses):
    report = advisories.audit(PACKAGES, transport=Transport(*responses))
    assert report["complete"] is False and report["passed"] is False
    assert report["errors"]


def test_dependency_policy_checks_every_batch_with_the_exact_version():
    packages = [{"name": f"package-{i}", "version": "1.0"} for i in range(101)]
    transport = Transport({"results": [{} for _ in range(100)]}, {"results": [{}]})
    report = advisories.audit(packages, transport=transport)
    assert report["complete"] and report["passed"]
    assert [len(batch) for batch in transport.queries] == [100, 1]
    assert transport.queries[-1] == [
        {"package": {"ecosystem": "PyPI", "name": "package-100"}, "version": "1.0"}
    ]


def sarif(score="7.5"):
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/example",
                                "properties": {"tags": ["security"], "security-severity": score},
                            }
                        ],
                    }
                },
                "results": [{"ruleId": "py/example"}],
                "versionControlProvenance": [{"revisionId": "a" * 40}],
            }
        ],
    }


@pytest.mark.parametrize("score", ["7.0", "9.8", "10"])
def test_codeql_analysis_success_does_not_approve_high_critical_or_suppressed_findings(score):
    document = sarif(score)
    document["runs"][0]["results"][0].update(
        baselineState="unchanged", suppressions=[{"kind": "external", "status": "accepted"}]
    )
    report = codeql.evaluate(document, "a" * 40)
    assert report["complete"] is True and report["passed"] is False
    assert report["blocking_findings"]


def test_codeql_policy_accepts_no_high_security_findings_and_standard_extension_rules():
    document = sarif("6.9")
    driver = document["runs"][0]["tool"]["driver"]
    document["runs"][0]["tool"]["extensions"] = [{"rules": driver.pop("rules")}]
    assert codeql.evaluate(document, "a" * 40)["passed"]
    document["runs"][0]["results"] = []
    assert codeql.evaluate(document, "a" * 40)["passed"]


@pytest.mark.parametrize(
    "change",
    [
        "source",
        "no-results",
        "no-runs",
        "unknown-rule",
        "failed-invocation",
        "no-severity",
        "invalid-severity",
    ],
)
def test_codeql_policy_denies_ambiguous_incomplete_or_wrong_revision_evidence(change):
    document = copy.deepcopy(sarif())
    run = document["runs"][0]
    if change == "source":
        run["versionControlProvenance"][0]["revisionId"] = "b" * 40
    elif change == "no-results":
        del run["results"]
    elif change == "no-runs":
        document["runs"] = []
    elif change == "unknown-rule":
        run["results"][0]["ruleId"] = "py/unknown"
    elif change == "failed-invocation":
        run["invocations"] = [{"executionSuccessful": False}]
    elif change == "no-severity":
        del run["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
    else:
        run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] = "NaN"
    with pytest.raises(ValueError):
        codeql.evaluate(document, "a" * 40)


def test_codeql_cli_denies_a_pr_head_sha_when_checkout_is_the_merge_commit(monkeypatch, tmp_path):
    path = tmp_path / "python.sarif"
    path.write_text(json.dumps(sarif()))
    output = tmp_path / "report.json"
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setattr(codeql.subprocess, "check_output", lambda *_args, **_kw: "b" * 40)
    monkeypatch.setattr("sys.argv", ["check_codeql_sarif", str(path), "--out", str(output)])
    assert codeql.main() == 1
    assert json.loads(output.read_text())["complete"] is False


def test_candidate_checksums_bind_the_exact_source_and_evidence(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "candidate.whl").write_bytes(b"reviewable candidate")
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "dependency-advisories.json").write_text('{"passed": true}')
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setattr(
        release_checksums.subprocess, "check_output", lambda *_args, **_kw: "a" * 40
    )
    monkeypatch.setattr(release_checksums.subprocess, "run", lambda *_args, **_kw: None)
    release_checksums.main()
    source = json.loads((tmp_path / "evidence" / "source-revision.json").read_text())
    assert source["source_sha"] == "a" * 40
    manifest = (tmp_path / "evidence" / "SHA256SUMS").read_text()
    assert "dist/candidate.whl" in manifest
    assert "evidence/source-revision.json" in manifest
    assert "evidence/dependency-advisories.json" in manifest
    monkeypatch.setattr(
        release_checksums.subprocess, "check_output", lambda *_args, **_kw: "b" * 40
    )
    with pytest.raises(ValueError, match="exact commit"):
        release_checksums.main()
