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


def test_keygen_creates_both_key_files_owner_only(tmp_path):
    import os
    import stat

    main = click.Group()
    register_runtime_commands(main)
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    previous = os.umask(0)
    try:
        result = CliRunner().invoke(
            main, ["runtime", "keygen", "--private-key", str(private), "--public-key", str(public)]
        )
    finally:
        os.umask(previous)
    assert result.exit_code == 0, result.output
    # Even with a permissive umask, neither file is group- or world-accessible.
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert stat.S_IMODE(public.stat().st_mode) == 0o600
