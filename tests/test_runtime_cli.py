from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import click
from click.testing import CliRunner

from nexus_symbiote.runtime import TrustStatus
from nexus_symbiote.runtime_cli import register_runtime_commands


def test_cli_sign_verify_and_wrong_purpose(tmp_path):
    main = click.Group()
    register_runtime_commands(main)
    runner = CliRunner()
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    result = runner.invoke(
        main, ["runtime", "keygen", "--private-key", str(private), "--public-key", str(public)]
    )
    assert result.exit_code == 0, result.output
    now = datetime.now(UTC)
    contract = TrustStatus(
        tenant="acme",
        serial=1,
        not_before=now - timedelta(seconds=1),
        not_after=now + timedelta(minutes=5),
    )
    body, signed = tmp_path / "status.json", tmp_path / "signed.json"
    body.write_text(contract.model_dump_json())
    result = runner.invoke(
        main,
        [
            "runtime",
            "sign",
            str(body),
            "--kind",
            "trust",
            "--key",
            str(private),
            "--out",
            str(signed),
        ],
    )
    assert result.exit_code == 0, result.output
    result = runner.invoke(
        main, ["runtime", "verify", str(signed), "--kind", "trust", "--public-key", str(public)]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["invocation_authorized"] is False
    result = runner.invoke(
        main, ["runtime", "verify", str(signed), "--kind", "snapshot", "--public-key", str(public)]
    )
    assert result.exit_code != 0
    result = runner.invoke(
        main, ["runtime", "keygen", "--private-key", str(private), "--public-key", str(public)]
    )
    assert result.exit_code != 0
