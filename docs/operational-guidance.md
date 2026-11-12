# Operational guidance

This page collects the practices that keep a Nexus SymBiote deployment inside the guarantees the security model and known limitations actually provide. It is written for operators and CI owners. Read the [security model](security-model.md), [threat model](threat-model.md) and [known limitations](known-limitations.md) first.

## Required practices

- **Use `--no-project-policy` on untrusted checkouts.** A pull request can change `.nexus-symbiote.yaml` or the workflow file. The Action and pre-commit hooks already ignore project policy; standalone commands do not. Pass `--no-project-policy` whenever the scanned tree is not fully trusted. See [policy reference](policy-reference.md) and [GitHub Action](known-limitations.md#github-action).
- **Set job timeouts.** Collection limits bound size, not time. Within the defaults an SPDX export of a crafted project can run for hours. Set a timeout on every CI job and local invocation that scans untrusted input. See [resource use](known-limitations.md#resource-use).
- **Sandbox untrusted scans.** The offline guard is a tripwire for this process and its Python dependencies, not a sandbox. Native code (tree-sitter) and any code that calls the OS directly can bypass it. Run scans of untrusted repositories in a network-restricted sandbox or container with no deployment credentials. See [security boundaries](../SECURITY.md#security-boundaries) and [offline and live modes](offline-and-live-modes.md).
- **Keep operator-owned files outside the scanned tree.** Signer policy, launch policy, the source-binding key, and reviewed baselines must live outside the checkout and be writable only by their owner. The tools refuse them when they lie inside the project. See [model integrity](model-integrity.md) and [drift gate](drift-gate.md).
- **Treat results as inventory evidence.** A passing gate does not establish that a model is benign, that a tool backend matches its description, or that every agent action is mediated. Surfaces no collector reads pass every gate. See [what results do and do not establish](security-model.md#what-results-do-and-do-not-establish).

## Recommended practices

- Run collection with the content author's privileges, not as root, on hosts with `fs.protected_hardlinks=1`. Extract untrusted archives with a tool that refuses link targets outside the destination.
- For `verify-live`, execute the pinned launchers in an externally isolated worker with resource limits and restricted filesystem, identity and network access. Pins do not cover the interpreter, libraries or operating system.
- Require the CI gate through an organization ruleset or a `pull_request_target` job so a pull request cannot weaken its own check.
- Review changes to instruction files, launcher commands and unrecognized surfaces by other means; the collectors record only the forms they support.
- Prefer the verified install path in the README (attestation + exact commit lock) over a plain `pip install`.

## Continuity

The project currently has a single maintainer. Organizations with supplier-continuity requirements should treat that as an unresolved risk until a second owner is added to the organization, the PyPI project and the security contacts. See [governance](../GOVERNANCE.md#continuity).

## Larger engineering items (not yet implemented)

The following are tracked for future work and are not part of the current guarantees:

- Broader collector coverage for high-value unrecognized forms (or explicit gaps).
- Optional tighter time budgets or progressive timeout signaling.
- Sandboxed or pure-Python alternative for the tree-sitter TypeScript parser.
- Optional signed baselines and inventory attestations.
- Additional runtime mediation adapters beyond the reference gateway.

These do not change the current security model. A way around a documented control remains a private vulnerability report.