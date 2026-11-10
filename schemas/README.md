# AgentBOM schemas

These JSON Schemas (draft 2020-12) describe the native Nexus SymBiote formats. They are generated from the package's Pydantic models, and tests fail when a schema and its model disagree.

| File | Describes | Kept in sync by |
| --- | --- | --- |
| [`nexus-symbiote-aibom-1.0.schema.json`](nexus-symbiote-aibom-1.0.schema.json) | A native AgentBOM document of format 1.x (this build writes 1.1.0): `metadata`, `components` and `dependencies` | `tests/test_native_contract.py` |
| [`deployment-profile-1.0.schema.json`](deployment-profile-1.0.schema.json) | The optional `deployment_profile` on an agent component; see [deployment evidence](../docs/deployment-evidence.md) | `tests/test_deployment_evidence_profile.py` |
| [`agent-manifest-1.0.schema.json`](agent-manifest-1.0.schema.json) | The optional `agent.yaml` at a project root; see [agent manifest](../docs/agent-manifest.md) | `tests/test_agent_manifest.py` |
| [`examples/minimal-aibom.json`](examples/minimal-aibom.json) | A minimal valid AgentBOM: one agent, an MCP server and its tools, a model, a prompt and a registry entry | `tests/test_native_contract.py` |

## Validate a document

The schemas check structure. The Python model additionally enforces cross-field rules, rejects duplicate JSON keys, checks the format version and bounds input size, so prefer the CLI for anything you rely on. `summary` loads a document exactly as every other command does and exits 1, naming the class of problem, when it cannot:

```bash
nexus-symbiote summary agentbom.json
```

That is a structural check only. To check a document's claims, reconcile it with the checkout it describes: `nexus-symbiote validate agentbom.json --project /reviewed/checkout --no-project-policy`. Without `--project`, `validate` can only check the document against itself (its assessment basis is `supplied-bom`), and integrity cannot pass for prompts, models and tool descriptors, because nothing local corroborates them.

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

Unknown fields are rejected rather than ignored, on every object including dependency edges, so a producer cannot smuggle unreviewed semantics into a document. Booleans, integers and timestamps are as strict as the schema: the model refuses `"no"` or `0` for a boolean, `"3"` for an integer and a number for a timestamp. Missing security values mean **unknown**, not `false`; see the [security defaults migration](../docs/security-defaults-migration.md). Standard exports (CycloneDX 1.7 and SPDX 3.0.1) are validated against the official schemas vendored under `src/nexus_symbiote/generators/schemas/vendor/`, whose provenance digests the hygiene check and the package verify. [Standard exports](../docs/standard-exports.md#extension-properties) lists the properties that carry the native semantics.

### Format versions

`metadata.spec_version` is the native format version, `MAJOR.MINOR.PATCH`. The schema file keeps its `1.0` name for the whole 1.x family and carries `$schema` and `$id`.

| Version | Written by | Change |
| --- | --- | --- |
| 1.0.0 | 0.1.0 | Initial format. Collectors recorded absolute scan-host paths. |
| 1.1.0 | this build | Collectors record POSIX paths relative to the scan root (`source_path`, claim locators, `surfaces_scanned`), so the same tree produces the same inventory wherever it is checked out. Adds `metadata.policy_source` and `metadata.policy_weakened`; dependency edges refuse unknown fields; `bom_ref` and edge endpoints are limited to 16,384 characters. |

The rule for readers:

- A build reads every minor version of its major version up to its own. This build reads 1.0.x and 1.1.x.
- A newer minor or major version, or a malformed version, is refused with a message that names the supported versions, rather than the generic schema error an unknown field would cause. Upgrade the tool or re-collect the inventory.
- A minor version only adds optional fields or narrows what collectors record; a major version changes or removes meaning.

A 1.0.0 inventory still loads, so `summary`, `diff` and the exports read it, but it does not reconcile: its absolute paths, provenance locators and assurance labels differ from a fresh collection, so `validate --project` and `risk --project` report its components as mismatched and say that the inventory must be re-collected. `diff` against a 1.1.0 inventory reports those differences too. Re-collect inventories, and regenerate drift baselines, with this version.

Native documents are limited to 16 MiB. `scan`, `import-shadowscan` and `AIBOM.save` write a document no reader would accept compactly when the indented form exceeds the limit, and refuse to write it when even the compact form does. `AIBOM.load` opens only a regular file, without following a symbolic link or blocking on a FIFO.

### Reserved types and fields

`guardrail-policy`, `memory-store` and `data-source` components, `egress_domains` and `filesystem_paths` in capability declarations, `registry_source` on MCP servers, and the `huggingface`, `mcp-registry` and `skill-marketplace` registry types are defined for supplied inventories. No built-in collector emits them; their descriptions in the schema say so.

When a model changes, regenerate the affected schema from it and review the diff together with the model change. These commands reproduce the committed files byte for byte:

```bash
python -c "import json; from nexus_symbiote.core.aibom import AIBOM; print(json.dumps(AIBOM.model_json_schema(), indent=2))" > schemas/nexus-symbiote-aibom-1.0.schema.json
python -c "import json; from nexus_symbiote.core.models import DeploymentProfile; print(json.dumps(DeploymentProfile.model_json_schema(), indent=2, sort_keys=True))" > schemas/deployment-profile-1.0.schema.json
python -c "import json; from nexus_symbiote.graph import AgentDeclaration; print(json.dumps(AgentDeclaration.model_json_schema(), indent=2, sort_keys=True))" > schemas/agent-manifest-1.0.schema.json
```

Do not edit a schema by hand to make a test pass.
