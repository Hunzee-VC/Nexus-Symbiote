# Roadmap

Nexus SymBiote is an alpha Agent Bill of Materials (AgentBOM) tool with one maintainer. This roadmap consolidates seven planning inputs written between 9 and 12 November 2026: five strategy write-ups, a twenty-fix plan and the end-to-end audit of v0.1.0. Each recommendation was checked against the code and, where it cites another tool or a standard, against that source. Recommendations that contradict the [security model](docs/security-model.md) are adapted or declined, with the reason.

- [Where the project stands](#where-the-project-stands)
- [Principles every item must keep](#principles-every-item-must-keep)
- [Corrections to the planning inputs](#corrections-to-the-planning-inputs)
- [Now: finish what is in flight](#now-finish-what-is-in-flight)
- [Next: the work that differentiates](#next-the-work-that-differentiates)
- [Later](#later)
- [Declined](#declined)
- [How progress is measured](#how-progress-is-measured)
- [Non-goals](#non-goals)
- [Historical experimental work](#historical-experimental-work)

## Where the project stands

- **Released.** 0.1.0 is on PyPI (8 November 2026) through trusted publishing, with publish attestations on both files.
- **In review.** The audit remediation that this roadmap builds on closes most of the v0.1.0 audit: native format 1.1.0 with portable paths, classified MCP launchers, operator collection limits, inert CI output, corroborated gates and conformant exports. A re-check of the audit's first three appendices against that work found 166 of 206 findings fixed, 32 narrowed and 7 still present but disclosed in the [known limitations](docs/known-limitations.md); one could not be settled. The audit's 141 other findings (CI, tests, architecture, cross-cutting and documentation) have not been re-checked independently.
- **Rankings.** The inputs place SymBiote anywhere from first to ninth among open AI-BOM tools. Those ranks are judgments from reading code and documentation, not measurements, and this roadmap adopts none of them. [How progress is measured](#how-progress-is-measured) lists what can be checked instead.
- **Lane.** SymBiote is strongest as the evidence and verification layer that other generators feed: every claim is declared, observed or verified, coverage gaps fail closed, and nothing scanned is executed. Breadth of discovery belongs to Nexus-ShadowScan and to imports from other tools.

## Principles every item must keep

1. Static collection never executes, imports or loads what it reads.
2. Every command is offline unless the operator selects live mode for a live command.
3. No language model on the trusted path, and no network service inside the package.
4. An imported claim never raises assurance. Telemetry written by an agent is that agent's claim.
5. Unknown never becomes a pass, and a number never stands in for an approval.
6. Signer, launch and trust policy belong to the operator and live outside the checkout.
7. Inventories stay deterministic and portable. No dependency is added without regenerating the three hash locks.
8. The collector set stays closed and small enough for one maintainer to keep correct.

## Corrections to the planning inputs

| Input said | Verified position |
| --- | --- |
| Rename the repository to `Nexus-SymBiote` | Declined. The canonical name is `Hunzee-VC/Nexus-Symbiote`; the PyPI trusted publisher, the 0.1.0 attestations, the schema identifier and every absolute link are bound to it. |
| Open the README with "Not the Linux malware. Runtime Agent BOM observer." | Add a disambiguation note, without that tagline: the tool is not a runtime observer. The malware, reported in June 2022, is a shared object loaded through `LD_PRELOAD` that hooks packet filtering; it is not an eBPF program. |
| Add an `nsb` command alias | Declined. A PyPI distribution named `nsb` already installs a console script of that name. |
| There is no CI gate, no SARIF, no pickle detection, no secret redaction, and offline is not the default | False at 0.1.0. All five exist. |
| `observe --agent ./my_agent.py` as the one-line demo | Declined as written: it executes project code. See [recorded telemetry](#next-the-work-that-differentiates). |
| Nobody ships runtime observation | False. k8s-aibom inventories running Kubernetes workloads, and ShadowScan reads gateway telemetry. |
| The G7 minimum elements could not be counted | Two independent enumerations list 50 elements in seven clusters (10, 9, 13, 10, 2, 4 and 2). The guidance is voluntary and defines no score or pass mark; the primary document was not reachable during this check. |
| k8s-aibom has three confidence tiers and is at 1.7 | Four tiers (`declared`, `verified`, `inferred`, `unresolved`); the latest release is 1.6.2. |
| Cisco AI BOM has a deterministic tier with optional LLM classification | Its `analyze` command always requires an LLM. The figure of 23 scanners is current. |
| Sigstore signature, in-toto attestation and SLSA provenance on every BOM | These are not three artifacts: a Sigstore bundle is a signature over an in-toto statement, and SLSA provenance has no scan-hash fields. Keyless signing needs a network identity, so it cannot be a default of an offline tool. |
| OpenSSF Model Signing is 1.0 stable | The `model-signing` package is at 1.1.1 and still classified alpha. SymBiote refuses its bundles today. |
| Publish against the AIBOM-CDX-Eval benchmark | No benchmark of that name was found. |
| Stale links to the former owner remain in the README | None do; the hygiene check rejects them. |

## Now: finish what is in flight

- [ ] Review and merge the audit remediation after a human reads the full diff; then re-check the audit's remaining 141 findings.
- [ ] Apply the release-tag ruleset and turn off administrator bypass on the `testpypi` and `pypi` environments ([repository controls](docs/repository-controls.md)).
- [x] Sign inventories and baselines offline: `attest` and `verify-attestation` write and check a detached in-toto statement in a DSSE envelope with Ed25519 keys ([CLI reference](docs/cli-reference.md#attest)).
- [ ] Let `diff`, `validate` and the Action require an attestation, with the trusted keys named in the operator signer policy.
- [ ] Add an opt-in Action input that attests the uploaded inventory with the platform's artifact attestation. The calling job must grant `id-token: write` and `attestations: write`, so it cannot be a default.
- [ ] Add a short disambiguation note to the README and SECURITY.md.
- [ ] Close the audit findings that remain narrow and contained: TypeScript tool registrations that are dropped without a gap, a root lockfile without its manifest, imported MCP servers that fail `verify-live`, an Action input for `--require-discovery-signature`, and a warning for an unknown category in `ignore_categories`.
- [ ] Decide which collectors, export formats and runtime adapters are supported for 0.1.x and which stay experimental.
- [ ] Name a second maintainer or a successor, and publish the scope and reviewer of the pre-publication review.

**Done when:** an unsigned or altered baseline fails a gate that the pull request under review cannot switch off, and a release is cut from a protected tag.

## Next: the work that differentiates

Each item names the adaptation that makes it fit the principles above.

1. **Recorded telemetry as source-reported evidence.** Import OpenTelemetry trace files (OTLP JSON) offline, bounded and strictly parsed, and compare what they name with the inventory: tools, models, MCP servers and agents used but not declared, and declared but not seen. Imported spans stay imported claims and are never `observed` or `verified`. Content-bearing attributes are refused by a deny-list. Under sampling, absence from a trace is not evidence of non-use, so "declared but not seen" is a report and never a gate. The GenAI conventions have moved to their own repository and are not yet stable, so the import format is versioned. k8s-aibom documents import the same way. *Done when:* a trace naming an undeclared MCP tool fails a gate and the report cites the span, without the tool ever starting an agent.
2. **Close the ShadowScan loop.** The importer maps three of ShadowScan's finding kinds. Map framework and agent-configuration findings next, then identity kinds as declared claims without token values. Export an inventory that ShadowScan's `--inventory` accepts, settle one autonomy vocabulary on the ISO/IEC 22989 ladder, and record a report's signer in the inventory as a declared note. The two tools stay separate processes with one documented, fixture-tested contract. *Done when:* ShadowScan's demo report imports with no unmapped entry and an approved SymBiote inventory is accepted as ShadowScan's inventory.
3. **Import other tools' documents.** Generalize the ShadowScan importer to CycloneDX and SPDX documents from Syft, Trivy, cdxgen, the OWASP AIBOM Generator and k8s-aibom: record the source digest, keep claims declared, bind a claim to local evidence only by matching digest, and report disagreement between sources as a finding. An imported finding may add to a local rating and never lowers one. This also fills the three component types no collector emits.
4. **Derived capability classes.** Derive exfiltration, write, code-execution and credential-access classes from the existing capability declarations, launch context and IDE permissions, labelled as heuristics; an absent class means unknown. Alert in `diff` when a component with such a class is added.
5. **Evidence breakdown and documentation coverage.** Per component, list the separate facts (pinned, digest recorded, signature verified under policy, format validated) instead of one trust number. Report coverage of the 50 G7 elements with a field-level list of what is missing and how to supply it, named documentation coverage so that it is not confused with the coverage gate, and never as a pass mark.
6. **Standard fields.** Emit MCP and A2A servers as CycloneDX `services` and a `modelCard` from locally collected fields, as a new projection version with recovery tests; add a 1.6 output; complete the SARIF rule catalog for the 21 categories that have only a generic rule. Claim the SPDX AI and Dataset profiles only for fields that have a source.
7. **Operator-recorded VEX decisions**, from a file outside the checkout with an owner and an expiry.
8. **Typed policy rules.** Extend the strict YAML policy with typed rules (required assurance per component type, required attestation, denied capability classes) instead of embedding a general policy language.
9. **Static attack-path view.** One self-contained HTML file with no remote scripts, every inventory string escaped, byte-identical for the same inventory, and paths labelled as associations.
10. **Model integrity depth.** Verify OpenSSF Model Signing bundles offline under the signer policy; name the imports a pickle stream requests; inspect Keras archives for Lambda layers. Implemented natively, without loading a model or calling another scanner.
11. **Platforms.** Qualify macOS in the required CI matrix and document the Windows position.

## Later

- Verify supplied training and dataset attestations offline, as declared lineage.
- A typosquat finding for package names close to a catalog entry.
- An opt-in Hugging Face Hub lookup as a new live command; local model cards are read first.
- A mapping to CycloneDX 2.0 once it is ratified, and a contribution to the OWASP AgBOM SPDX mapping.
- A scheduled, non-gating job that uploads the exports to Dependency-Track.
- Coverage and noise measurements on public agent projects, run by someone other than the maintainer, with denominators and corpus digests published.
- A versioning and compatibility policy for the native format, with fixtures per version.

## Declined

| Proposal | Reason |
| --- | --- |
| An in-process or eBPF runtime observer, and running the agent under observation | Executes project code and adds a privileged collector. Recorded telemetry is imported instead. |
| LLM-assisted enrichment | Non-deterministic and sends project content to a vendor. |
| An embedded OPA or Cedar engine | A new dependency or a subprocess the offline guard refuses. Typed policy rules cover the stated gates. |
| A TrustScore from 0 to 100 | A single number that can reach 100 reads as an approval, and a bonus for runtime observation lets an agent's own telemetry raise it. |
| Envelope encryption of redacted secrets | Secrets never enter the inventory; a keyed digest detects change. Encrypting them would store recoverable values. |
| Running ShadowScan or its live connectors inside a scan | A scan starts no process and reaches no network. |
| A registry proxy, hosted registry, dashboard, multi-tenancy or SSO | Different products; a consumer such as Dependency-Track stores and serves inventories. |
| Collectors for containers, cloud, IaC, notebooks and low-code platforms | Discovery expansion goes through ShadowScan and imports. |
| GHSA, NVD, EPSS and KEV as further live origins | OSV records already carry aliases, severity and fixed versions; surface those. |

## How progress is measured

| Measure | Target | Today |
| --- | --- | --- |
| Silent skips | No recognized input is skipped without a gap | Launchers, lockfile precedence and case variants are gaps; some TypeScript registrations are not |
| Signed evidence | A gate can require an attested baseline | Signing and verification exist; no gate requires them yet |
| Runtime evidence | A declared-versus-reported comparison from recorded telemetry | Not started |
| ShadowScan bridge | The demo report imports with no unmapped entry | 3 finding kinds mapped |
| Standards | Exports validate against the pinned schemas and load in Dependency-Track | Schema validation in place; ingestion untested |
| Independent review | A release reviewed and a benchmark rerun by an outside party | None |
| Maintainers | Two | One |
| Platforms | Linux and macOS in required CI | Linux |

## Non-goals

- Claiming that an inventory, a signature or a low risk score proves an agent or model is benign.
- Default execution of untrusted project code, MCP launchers, or model loaders.
- Long-term support commitments while the project remains alpha.

Contributions that advance the items above (especially tested collector coverage, documentation, and regression fixtures) are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Historical experimental work

The [closed-PR audit](docs/audits/closed-pr-review-2026-11-02.md) records what reached the supported package and what remains separate. The experimental foundation's salted Merkle disclosure protocol, full snapshot chain format, OPA/Rego export and parity suite, and Kubernetes/trace import contracts are not supported interfaces on `main`. Evaluate any future port against the current threat model and version its wire format; a merge into an experimental branch does not establish shipped compatibility. Discovery expansion should continue through Nexus-ShadowScan.
