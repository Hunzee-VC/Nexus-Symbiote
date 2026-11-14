"""Local secret scans must retain upstream detection in source and test trees."""

import tomllib

from tests.support import ROOT


def test_gitleaks_keeps_default_detection_without_blanket_fixture_exemptions():
    config = tomllib.loads((ROOT / ".gitleaks.toml").read_text())
    assert config.get("extend") == {"useDefault": True}
    assert not config.get("allowlist") and not config.get("allowlists")
    assert not config.get("rules")
