"""Local secret scans must retain upstream detection in source and test trees."""

import hashlib
import re
import tomllib

import pytest

from tests.support import ROOT

# The hashes pin the individually reviewed full values, without adding more
# token-shaped fixtures. Expanding this set requires origin and scope review.
REVIEWED = [
    (
        "docs/inventory-attestation.md",
        "generic-api-key",
        "5d71becee59b155abd936e283d87c8490cf3c2a6f8b838c19f32d08c280453b4",
    ),
    (
        "tests/test_a2a_binding.py",
        "generic-api-key",
        "605eb571f653fb9f16b8dff42fd30209c95e0e7fd0f1d3e63576f929ff9a43e5",
    ),
    (
        "tests/test_a2a_collection.py",
        "generic-api-key",
        "2fc34706e91a2916e8b08d521dc4e1739e7b0396ad92b8cdc23f37ff83683d4a",
    ),
    (
        "tests/test_a2a_collection.py",
        "github-pat",
        "620e24b631970fdc64de36b73f4ce2206a2e3fe2d040e02f2d0d7d88fdc198b8",
    ),
    (
        "tests/test_collector_security.py",
        "generic-api-key",
        "fc5951419ae9e4b7f57d1dae9d5c51943363c63d986a278e9cc2c027bfbbce02",
    ),
    (
        "tests/test_confined_bounds.py",
        "generic-api-key",
        "dd517eadd712d55b15914e9046fcb3183526d9bb07e7d0fb3a1aadb0fa909fa6",
    ),
    (
        "tests/test_mcp_environment_sources.py",
        "github-pat",
        "dfa3334824c2f9a8218eedb8dc92db0953fe2f809afdfabbf8b3ab633f9c31ac",
    ),
    (
        "tests/test_mcp_source_binding.py",
        "generic-api-key",
        "dc47c15c0740150acdb21d539e47bd147e2e8331ba71468ddde7b9e8f6b28564",
    ),
    (
        "tests/test_rag_identifier_redaction.py",
        "generic-api-key",
        "76b4100ba2539966efd524a0b032ed668e9dcbb8b4c52a4b4f92264bf40055c2",
    ),
    (
        "tests/test_scanners.py",
        "generic-api-key",
        "5e79faf2be378c3bf73f1d99f8c9b371646acd5bdc557a5634e73df4d34bc736",
    ),
    (
        "tests/test_secret_name_redaction.py",
        "github-pat",
        "60a1bd967c577258dea73009553a45e41f3ce4fa83bd5999d5c4ae2391f429c5",
    ),
    (
        "tests/test_secret_name_redaction.py",
        "jwt",
        "1659ca774d059db891642ae3a6109ec8012cf8d02e29c5d6a8043e8550099d53",
    ),
    (
        "tests/test_secret_name_redaction.py",
        "private-key",
        "e26f678f742f255605c0880adc1e3836182744f7db760a37812cdba4c3e26474",
    ),
]


def test_gitleaks_keeps_default_detection_without_blanket_fixture_exemptions():
    config = tomllib.loads((ROOT / ".gitleaks.toml").read_text())
    assert set(config) == {"title", "minVersion", "extend", "allowlists"}
    assert config["minVersion"] == "8.30.1"
    assert config.get("extend") == {"useDefault": True}
    assert len(config["allowlists"]) == len(REVIEWED)


@pytest.mark.parametrize(("path", "rule", "digest"), REVIEWED)
def test_each_fixture_exception_requires_exact_path_rule_and_full_value(path, rule, digest):
    config = tomllib.loads((ROOT / ".gitleaks.toml").read_text())
    exceptions = [
        entry
        for entry in config["allowlists"]
        if entry.get("paths") == ["^" + re.escape(path) + "$"]
        and entry.get("targetRules") == [rule]
    ]
    assert len(exceptions) == 1
    entry = exceptions[0]
    assert set(entry) == {
        "description",
        "condition",
        "targetRules",
        "regexTarget",
        "paths",
        "regexes",
    }
    assert entry["condition"] == "AND"
    assert entry["regexTarget"] == "secret"
    assert entry["description"]
    assert len(entry["regexes"]) == 1
    pattern = entry["regexes"][0]
    assert re.fullmatch(r"\^(?:\\x[0-9a-f]{2})+\$", pattern)
    value = bytes.fromhex(pattern[1:-1].replace("\\x", ""))
    assert hashlib.sha256(value).hexdigest() == digest
    assert value in (ROOT / path).read_bytes()
    literal = value.decode()
    assert re.fullmatch(pattern, literal)
    for changed in (literal + "x", "x" + literal, "x" + literal[1:]):
        assert not re.fullmatch(pattern, changed)
    for changed_path in ("outside/" + path, path + ".other", "other/" + path.split("/", 1)[1]):
        assert not re.fullmatch(entry["paths"][0], changed_path)
