# AgentBOM schemas

These JSON Schemas (draft 2020-12) describe the native Nexus SymBiote formats. They are generated from the package's Pydantic models, and tests fail when a schema and its model disagree.

| File | Describes | Kept in sync by |
| --- | --- | --- |
| [`nexus-symbiote-aibom-1.0.schema.json`](nexus-symbiote-aibom-1.0.schema.json) | A native AgentBOM document: `metadata`, `components` and `dependencies` | `tests/test_native_contract.py` |
| [`deployment-profile-1.0.schema.json`](deployment-profile-1.0.schema.json) | The optional `deployment_profile` on an agent component; see [deployment evidence](../docs/deployment-evidence.md) | `tests/test_deployment_evidence_profile.py` |
| [`agent-manifest-1.0.schema.json`](agent-manifest-1.0.schema.json) | The optional `agent.yaml` at a project root; see [agent manifest](../docs/agent-manifest.md) | `tests/test_agent_manifest.py` |
| [`examples/minimal-aibom.json`](examples/minimal-aibom.json) | A minimal valid AgentBOM: one agent, an MCP server and its tools, a model, a prompt and a registry entry | `tests/test_native_contract.py` |

## Validate a document

The schemas check structure. The Python model additionally enforces cross-field rules, rejects duplicate JSON keys and bounds input size, so prefer the CLI for anything you rely on:

```bash
nexus-symbiote validate agentbom.json --no-project-policy
```

To check structure alone, for example in another toolchain, validate with any draft 2020-12 validator. With the `jsonschema` package that the CLI already depends on:

```bash
python - schemas/nexus-symbiote-aibom-1.0.schema.json agentbom.json <<'PY'
import json, sys
from jsonschema import Draft202012Validator
schema, document = (json.load(open(path, encoding="utf-8")) for path in sys.argv[1:3])
errors = list(Draft202012Validator(schema).iter_errors(document))
for error in errors:
    print("/".join(map(str, error.absolute_path)) or "<root>", error.message)
sys.exit(bool(errors))
PY
```

A schema-valid document is not a verified one. Validity says nothing about whether collection was complete, whether digests match the project, or whether a signer is trusted. See [what results do and do not establish](../docs/security-model.md#what-results-do-and-do-not-establish).

## Compatibility

Unknown fields are rejected rather than ignored, so a producer cannot smuggle unreviewed semantics into a document. Missing security values mean **unknown**, not `false`; see the [security defaults migration](../docs/security-defaults-migration.md). Standard exports (CycloneDX 1.7 and SPDX 3.0.1) are validated against the official schemas vendored under `src/nexus_symbiote/generators/schemas/vendor/`, whose provenance digests the hygiene check and the package verify. [Standard exports](../docs/standard-exports.md#extension-properties) lists the properties that carry the native semantics.

When a model changes, regenerate the affected schema from it and review the diff together with the model change. These commands reproduce the committed files byte for byte:

```bash
python -c "import json; from nexus_symbiote.core.aibom import AIBOM; print(json.dumps(AIBOM.model_json_schema(), indent=2))" > schemas/nexus-symbiote-aibom-1.0.schema.json
python -c "import json; from nexus_symbiote.core.models import DeploymentProfile; print(json.dumps(DeploymentProfile.model_json_schema(), indent=2, sort_keys=True))" > schemas/deployment-profile-1.0.schema.json
python -c "import json; from nexus_symbiote.graph import AgentDeclaration; print(json.dumps(AgentDeclaration.model_json_schema(), indent=2, sort_keys=True))" > schemas/agent-manifest-1.0.schema.json
```

Do not edit a schema by hand to make a test pass.
