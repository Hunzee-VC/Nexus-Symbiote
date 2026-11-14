"""A ShadowScan report behind a symbolic link must not replace the report a pipeline wrote.

The collector lists the supported report paths by the identity of what each path names
without following links, but reads a report through one in-root directory link. A
checkout that commits ``.shadowscan -> vendor`` with a clean ``vendor/report.json`` beside
the pipeline's ``shadowscan.json`` would otherwise import its own report, at the highest
precedence path, as a complete observation.
"""

from __future__ import annotations

import json
from pathlib import Path

from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

REPORT = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"


def _clean_report() -> bytes:
    return json.dumps(
        {
            "version": "0.1.4",
            "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
            "stats": [{"errors": [], "skipped": False, "incomplete": False}],
            "findings": [],
        }
    ).encode()


def _link_report_directory(root: Path) -> None:
    (root / "vendor").mkdir()
    (root / "vendor" / "report.json").write_bytes(_clean_report())
    (root / ".shadowscan").symlink_to("vendor", target_is_directory=True)


def test_a_report_behind_a_symlinked_directory_cannot_hide_the_pipeline_report(tmp_path):
    (tmp_path / "shadowscan.json").write_bytes(REPORT.read_bytes())
    _link_report_directory(tmp_path)
    result = ShadowScanImporter().scan(tmp_path)
    assert any("symbolic link" in failure for failure in result.scan_failures)
    assert not result.components
    assert result.source_report_digest is None
    assert result.source_report_path is None


def test_a_report_reached_only_through_a_symlinked_directory_is_refused(tmp_path):
    _link_report_directory(tmp_path)
    result = ShadowScanImporter().scan(tmp_path)
    assert result.scan_failures == [
        ".shadowscan/report.json: ShadowScan report is reached through a symbolic link; "
        "not imported"
    ]
    assert not result.components
    assert result.source_report_path is None


def test_a_report_in_a_real_directory_is_still_imported(tmp_path):
    (tmp_path / ".shadowscan").mkdir()
    (tmp_path / ".shadowscan" / "report.json").write_bytes(REPORT.read_bytes())
    result = ShadowScanImporter().scan(tmp_path)
    assert not result.scan_failures
    assert result.source_report_path == ".shadowscan/report.json"
