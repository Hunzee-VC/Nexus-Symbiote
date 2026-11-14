from __future__ import annotations

import json
import os
import subprocess
import sys

import click
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.runtime_cli import _InputTooLargeError, _read, register_runtime_commands


def test_runtime_input_accepts_exact_byte_limit_and_rejects_overflow(tmp_path):
    path = tmp_path / "contract.json"
    path.write_bytes(b"1234")
    assert _read(path, maximum=4) == b"1234"
    with pytest.raises(_InputTooLargeError):
        _read(path, maximum=3)


@pytest.mark.parametrize("parent_link", [False, True])
def test_runtime_input_rejects_final_and_parent_symlinks(tmp_path, parent_link):
    real = tmp_path / "real"
    real.mkdir()
    contract = real / "contract.json"
    contract.write_bytes(b"{}")
    alias = tmp_path / "alias"
    if parent_link:
        alias.symlink_to(real, target_is_directory=True)
        path = alias / contract.name
    else:
        alias.symlink_to(contract)
        path = alias
    with pytest.raises(OSError):
        _read(path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFOs")
def test_runtime_input_rejects_fifo_without_waiting_for_writer(tmp_path):
    path = tmp_path / "contract.fifo"
    os.mkfifo(path)
    # Bound the test itself so a regression cannot hang the test runner.
    code = """
import sys
from pathlib import Path
from nexus_symbiote.runtime_cli import _read
try:
    _read(Path(sys.argv[1]))
except OSError:
    raise SystemExit(0)
raise SystemExit(1)
"""
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code, str(path)],
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("operation", ["sign", "verify"])
def test_runtime_validation_errors_show_field_names_without_input_values(tmp_path, operation):
    canary = "RUNTIME_INPUT_SECRET_754f91"
    key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "key.pem"
    main = click.Group()
    register_runtime_commands(main)
    document = tmp_path / "input.json"
    if operation == "sign":
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        document.write_text(
            json.dumps(
                {
                    "tenant": {"api_key": canary},
                    "serial": 1,
                    "not_before": "2026-11-02T00:00:00Z",
                    "not_after": "2026-11-02T00:10:00Z",
                    canary: "unsupported extra field",
                }
            )
        )
        command = [
            "runtime",
            "sign",
            str(document),
            "--kind",
            "trust",
            "--key",
            str(key_path),
            "--out",
            str(tmp_path / "signed.json"),
        ]
        expected_field = "tenant"
    else:
        key_path.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        document.write_text(
            json.dumps({"payload": {"api_key": canary}, "signatures": [], canary: True})
        )
        command = [
            "runtime",
            "verify",
            str(document),
            "--kind",
            "trust",
            "--public-key",
            str(key_path),
        ]
        expected_field = "payload"
    result = CliRunner().invoke(main, command)
    assert result.exit_code == 1
    assert canary not in result.output
    assert expected_field in result.output
    assert "unsupported field" in result.output
    assert "runtime-input-error" in result.output


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX ownership")
def test_owner_only_file_must_be_owned_by_the_caller(tmp_path, monkeypatch):
    from nexus_symbiote.runtime_cli import _KeyFileError

    path = tmp_path / "key.pem"
    path.write_bytes(b"k")
    path.chmod(0o600)
    assert _read(path, owner_only="the key file") == b"k"
    owner = os.stat(path).st_uid
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1)
    with pytest.raises(_KeyFileError, match="owned by the user"):
        _read(path, owner_only="the key file")
