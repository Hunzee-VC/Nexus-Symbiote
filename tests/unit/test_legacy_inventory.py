import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from symbiote.cli import app
from symbiote.digest import bytes_digest
from symbiote.export.companion import load_companion
from symbiote.imp.legacy import import_legacy
from symbiote.snapshot import verify_document

FIXTURE = Path(__file__).parents[1] / "fixtures/legacy/customer-support-agent.json"


def test_native_example_migrates_without_upgrading_trust(tmp_path):
    out = tmp_path / "converted.json"
    run = CliRunner().invoke(app, ["import-legacy", str(FIXTURE), "-o", str(out)])
    assert run.exit_code == 0, (run.exception, run.output)
    bom = load_companion(out)
    assert verify_document(bom) and bom.snapshot.kind.value == "declared"
    assert len(bom.models) == 2 and len(bom.tools) == 2 and len(bom.tool_servers) == 1
    assert all(m.hosted.value.resolved_ref.state.value == "unknown" for m in bom.models)
    assert all(t.state.value == "declared" and not t.digest.ok for t in bom.tools)
    assert all(e.scope.value == "design" for e in bom.edges)
    assert not bom.grants and not bom.deployments
    assert bom.evidence[0].digest == bytes_digest(FIXTURE.read_bytes())
    assert any(p.name == "unmapped-component" for p in bom.foreign_properties)
    assert all(c.status.value == "not-attempted" for c in bom.coverage.surfaces.values())


def test_reject_ambiguous_and_dangling_refs():
    data = json.loads(FIXTURE.read_bytes())
    data["components"].append(data["components"][0])
    with pytest.raises(ValueError, match="duplicate"):
        import_legacy(json.dumps(data).encode())
    data["components"].pop()
    data["dependencies"][0]["target_ref"] = "missing"
    with pytest.raises(ValueError, match="dangling"):
        import_legacy(json.dumps(data).encode())
