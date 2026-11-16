"""Registry inputs that are, or lead to, credential files are gaps, never read."""

from __future__ import annotations

import json
import secrets
import string
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.generators import CycloneDXGenerator, SPDXGenerator
from nexus_symbiote.scanners.registry import RegistryScanner


def _value(length: int = 40) -> str:
    # Random, so no fixture can be token-shaped by accident or by design.
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))


def _everything(root: Path) -> str:
    result = RegistryScanner().scan(root)
    bom = AIBOM()
    for component in result.components:
        bom.add_component(component)
    return "\n".join(
        [
            json.dumps([c.model_dump(mode="json") for c in result.components]),
            json.dumps(result.scan_failures + result.surfaces_excluded),
            CycloneDXGenerator().generate_json(bom),
            SPDXGenerator().generate_json(bom),
        ]
    )


@pytest.mark.parametrize(
    "name", ["requirements-dev.txt", "requirements.txt", "package-lock.json", "poetry.lock"]
)
def test_a_registry_input_that_links_to_dotenv_is_a_gap_and_is_not_read(
    tmp_path: Path, name: str
) -> None:
    value = _value()
    (tmp_path / ".env").write_text(f"COHERE_API_KEY={value}\nOPENAI_ORG=org-{value[:12]}\n")
    # Declarations that make the collector consult each lockfile.
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"4.52.0"}}')
    if name != "requirements.txt":
        (tmp_path / "requirements.txt").write_text("openai==1.0.0\n")
    (tmp_path / name).symlink_to(".env")
    result = RegistryScanner().scan(tmp_path)
    assert f"{name}: a symlink leads to .env, whose name says it holds credentials; " in "\n".join(
        result.surfaces_excluded
    )
    text = _everything(tmp_path)
    assert value not in text
    assert value[:12] not in text


def test_an_invalid_requirement_is_redacted_before_its_name_is_removed(tmp_path: Path) -> None:
    # The name is what marks the value as a credential; cutting it off first left the
    # value to the token shapes alone.
    value = _value(12)
    (tmp_path / "requirements.txt").write_text(f"transformers_token={value}\nopenai==1.0.0\n")
    text = _everything(tmp_path)
    assert value not in text


def test_a_package_json_that_links_to_a_credential_file_is_a_gap(tmp_path: Path) -> None:
    (tmp_path / "secrets.json").write_text('{"dependencies":{"openai":"4.52.0"}}')
    (tmp_path / "package.json").symlink_to("secrets.json")
    result = RegistryScanner().scan(tmp_path)
    assert result.components == []
    assert any(
        entry.startswith("package.json: a symlink leads to secrets.json")
        for entry in (result.surfaces_excluded)
    )
