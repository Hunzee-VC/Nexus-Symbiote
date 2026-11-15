"""Malformed inventories produce a short CLI error, never a traceback or echoed input."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, NativeFormatError, parse_native_bytes

CANARY = "\x1b]8;;https://attacker.example\x07canary-input\x1b]8;;\x07"


@pytest.fixture(params=["schema", "truncated", "not-utf8", "deep"])
def malformed(request, tmp_path):
    path = tmp_path / "bom.json"
    if request.param == "schema":
        path.write_text(json.dumps({"metadata": CANARY}))
        parsed = parse_native_bytes(path.read_bytes())
        assert parsed["metadata"] == CANARY
        with pytest.raises(NativeFormatError, match="native AgentBOM schema"):
            AIBOM.from_native(parsed)
    elif request.param == "truncated":
        path.write_text('{"metadata": {"spec_version": ')
    elif request.param == "not-utf8":
        path.write_bytes(b'{"metadata": "\xff\xfe"}')
    else:
        path.write_text("[" * 100_000 + "]" * 100_000)
    return path


@pytest.mark.parametrize(
    "command",
    [
        ["summary"],
        ["validate", "--no-project-policy"],
        ["risk", "--no-project-policy"],
        ["blast-radius", "{bom}", "agent:example"],
        ["diff", "{valid}"],
    ],
)
def test_malformed_inventory_is_a_clean_error(tmp_path, malformed, command):
    valid = tmp_path / "valid.json"
    valid.write_text(AIBOM().to_json())
    args = [part.format(bom=malformed, valid=valid) for part in command]
    if "{bom}" not in command:
        args.insert(1, str(malformed))
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 1, result.output
    assert f"{malformed} is not a valid native AIBOM file." in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.output
    assert "canary-input" not in result.output
