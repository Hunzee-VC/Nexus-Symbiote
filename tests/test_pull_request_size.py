"""The pull-request size cap counts product changes and ignores the test trees."""

from __future__ import annotations

from pathlib import Path

from tests.support import load_script

checker = load_script("check_pull_request_size")


def test_tests_and_binaries_are_not_counted() -> None:
    listing = "\n".join(
        [
            "10\t2\tsrc/nexus_symbiote/cli.py",
            "1000\t0\ttests/test_cli.py",
            "3\t1\tbenchmarks/case.json",
            "-\t-\tdocs/assets/banner.jpg",
            "4\t0\tREADME.md",
        ]
    )
    assert checker.changed_lines(listing) == 16


def test_the_command_fails_above_the_limit(tmp_path: Path, capsys) -> None:
    listing = tmp_path / "numstat.txt"
    listing.write_text("1600\t0\tsrc/nexus_symbiote/cli.py\n")
    assert checker.main(["--numstat-file", str(listing), "--limit", "1500"]) == 1
    assert "1600" in capsys.readouterr().out
