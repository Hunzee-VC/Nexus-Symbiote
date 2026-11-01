"""Security properties must not be inferred from missing evidence."""

import json

import pytest

from nexus_symbiote.core.enums import ExecutionIsolation, HumanInTheLoop
from nexus_symbiote.core.models import (
    AgentComponent,
    AuthorizationRecord,
    CapabilityDeclaration,
    MemoryStoreComponent,
    ModelComponent,
    RegistryEntryComponent,
)
from nexus_symbiote.scanners.model import ModelScanner


def test_missing_security_configuration_is_unknown():
    memory = MemoryStoreComponent(bom_ref="memory:a", name="a")
    model = ModelComponent(bom_ref="model:a", name="a")
    registry = RegistryEntryComponent(bom_ref="registry:a", name="a")
    capabilities = CapabilityDeclaration()
    auth = AuthorizationRecord(principal="p", action="read")
    assert memory.tenant_isolated is None
    assert memory.encryption_at_rest is None
    assert model.trust_remote_code is None
    assert registry.publisher_verified is None
    assert capabilities.execution_isolation is None
    assert capabilities.human_in_the_loop is None
    assert auth.approval_required is None


def test_explicit_security_values_are_preserved():
    memory = MemoryStoreComponent(
        bom_ref="memory:a", name="a", tenant_isolated=False, encryption_at_rest=True
    )
    capability = CapabilityDeclaration(
        execution_isolation=ExecutionIsolation.NONE, human_in_the_loop=HumanInTheLoop.NONE
    )
    assert memory.tenant_isolated is False
    assert memory.encryption_at_rest is True
    assert capability.execution_isolation is ExecutionIsolation.NONE
    assert capability.human_in_the_loop is HumanInTheLoop.NONE
    component = AgentComponent(bom_ref="agent:a", name="a", capabilities=capability)
    restored = AgentComponent.model_validate_json(component.model_dump_json())
    assert restored.capabilities == capability
    assert (
        AuthorizationRecord(principal="p", action="read", approval_required=False).approval_required
        is False
    )


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ({}, None),
        ({"trust_remote_code": False}, False),
        ({"trust_remote_code": True}, True),
        ({"trust_remote_code": "false"}, None),
        ({"trust_remote_code": None}, None),
    ],
)
def test_model_scanner_preserves_unknown_and_explicit_boolean(tmp_path, config, expected):
    (tmp_path / "model.safetensors").write_bytes(b"test fixture")
    (tmp_path / "config.json").write_text(json.dumps(config))
    components = ModelScanner().scan(tmp_path).components
    assert len(components) == 1
    assert components[0].trust_remote_code is expected
