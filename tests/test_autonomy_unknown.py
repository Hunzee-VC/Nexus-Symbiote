"""Missing autonomy evidence cannot become an invented L2 declaration."""

import json

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AutonomyLevel
from nexus_symbiote.core.models import AgentComponent


def test_missing_autonomy_is_unknown_for_construction_and_external_native_boms(tmp_path):
    assert AgentComponent(bom_ref="a", name="a").autonomy_level is None
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps({"components": [{"bom_ref": "a", "component_type": "agent", "name": "a"}]})
    )
    bom = AIBOM.load(path)
    assert bom.components[0].autonomy_level is None
    assert bom.to_dict()["components"][0]["autonomy_level"] is None
    assert AIBOM.model_validate(bom.to_dict()).components[0].autonomy_level is None


def test_existing_explicit_legacy_autonomy_is_retained_as_a_declaration():
    bom = AIBOM.model_validate(
        {
            "components": [
                {
                    "bom_ref": "a",
                    "component_type": "agent",
                    "name": "a",
                    "autonomy_level": "L2-agent",
                }
            ]
        }
    )
    assert bom.components[0].autonomy_level == AutonomyLevel.L2_AGENT
    assert bom.components[0].claims == {}
