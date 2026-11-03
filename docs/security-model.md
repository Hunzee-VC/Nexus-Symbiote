# Security model

Nexus SymBiote connects an agent's inventory to evidence and policy. Keep the following states separate:

| State | Meaning |
| --- | --- |
| Declared composition | A repository, supplier, or configuration says a component is used. |
| Observed composition | A named collector measured a component in a stated scope and time. |
| Approved configuration | An authorized approver accepted a specific configuration and capabilities. |
| Mediated execution | An enforcement adapter checked an actual action against its trusted policy and approval. |

Nexus-ShadowScan is the primary discovery source; importing its report into Nexus SymBiote preserves the distinction between a supplied claim and a new local measurement. A2A Agent Cards, IDE configuration, and extension manifests are declarations until their relevant identity and evidence are separately verified.

An inventory entry never grants permission by itself. A schema hash pins an interface; it does not constrain a backend's hidden side effects. A signed malicious artifact remains malicious. Runtime metadata emitted by the agent itself has a different trust basis from an independent observation.

Collectors must preserve coverage limitations, denied reads, unsupported inputs, exclusions, and failures. Missing information means unknown, not verified absence. Secrets are references, not values. Avoid default capture of raw prompts, retrieved documents, tool arguments, or results. Tenant and deployment identifiers must remain part of approval and observation scope.

When a supplier gives you an inventory and you have the corresponding checkout,
use both commands against the same project root.

```sh
nexus-symbiote validate inventory.json --project /reviewed/checkout --no-project-policy
nexus-symbiote risk inventory.json --project /reviewed/checkout --no-project-policy --json-output
```

Project reconciliation reruns the supported static collectors and compares
their security-relevant fields and findings with the supplied BOM. A mismatch
makes the project-backed risk command exit unsuccessfully with an unknown risk
level and a null score. Without a project, `risk` scores the supplied claims
and labels the result `supplied-bom`. For an operator-configured signature
check, supply the trusted signer policy when validating the project.

A mediated action needs a trusted approver, snapshot binding, authenticated workload and endpoint, action/resource constraints, validity, current revocation state, rollback protection, and any action-specific approval. One-use approval must bind to the action and arguments it authorizes. Adapter checks cannot govern tools invoked through an unmediated route; deployments need their own network, identity, and sandbox controls to make mediation complete.

For hosted models, an alias is a locator. Provider-reported revisions and behavioral canaries do not establish measured weight identity. Preserve identity assurance and unknowns explicitly. For retrieval and memory, record the source and index versions, effective reader/writer permissions, and derived records requiring invalidation after withdrawal.

## Known false-positive and false-negative classes

These are current behaviors, not guarantees. Review them before relying on a gate.

- **Model format by extension.** `.pkl`, `.pickle`, `.pt`, `.pth`, `.bin` and `.joblib` are rated as potentially code-executing on file extension alone, before any content is read. A non-pickle `.bin` file (firmware, game data) is therefore a critical finding, which fails the default gate. Formats with no structural validator (`.onnx`, `.gguf`, `.ggml`) are reported as unknown, not safe.
- **Risk score scale.** The aggregate score is the uncapped sum of finding weights (critical 10, high 7, medium 4, low 1). It grows with inventory size and is not a percentage, although the Action accepts thresholds from 0 to 100. Any critical finding fails the default gate regardless of the aggregate.
- **Free-text redaction.** Redaction removes known secret values and `name=value` or `name: value` pairs whose name contains `api_key`, `access_key`, `secret_key`, `private_key`, `token`, `password`, `passwd` or `secret`. Credentials in other shapes, such as quoted JSON keys or values containing spaces, are not recognized by pattern; structured collectors rely on scrubbing known environment values instead.
- **Hosted CI.** A configured workflow is not evidence that it ran; see `docs/repository-controls.md`.
