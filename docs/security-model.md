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
