# Import a native SymBiote inventory

The foundation CLI accepts native 1.0.0 inventory files from the historical `symbote` and current `symbiote` CLI. To convert one, run:

```sh
symbiote import-legacy customer-support-agent.json -o declared.agentbom.json
symbiote validate declared.agentbom.json
```

Select a root with `--agent BOM_REF` when a document lists several agents. The migration supports the chosen root, MCP servers and tools, explicitly hosted API models, and data-source declarations. It translates supported relationships into design-time edges with stable identifiers. The source file's SHA-256 is attached as evidence. Keep that file to recover details listed as unmapped in `foreignProperties`.

A legacy signature label, mutable model alias, completeness percentage or tool fingerprint supplies no independent verification. The result is a declared snapshot. Coverage remains unattempted, unresolved model identity stays unknown, and missing full descriptors are undigestable. The command rejects duplicate and dangling references. It does not authorize gateway admission.

The test fixture is the published customer-support example from `examples/customer-support-agent.json` at commit `26b25d20fb2924aa40a524f732e6cabf68b69933`.
