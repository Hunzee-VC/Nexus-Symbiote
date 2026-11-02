# Research and design inputs

Artefacts produced while designing Symbiote on 2026-11-01. They are inputs, not the specification; the
normative text lives in `spec/`, and the publishable synthesis of the gap analysis is
[`docs/gap-analysis.md`](../gap-analysis.md).

| File | What it is |
|---|---|
| `design-brief.md` | The shared brief (thesis, hard requirements R1–R12, verified facts) every architecture proposal worked from |
| `proposals/enforcement-first.md` | Independent proposal designed backwards from the gateway, policy engine and incident responder (adopted as the backbone) |
| `proposals/standards-purist.md` | Independent proposal maximising native CycloneDX/SPDX constructs and upstreamability (adopted: `agentbom:` namespace, encoding ladder, verified-facts table) |
| `proposals/adoption-first.md` | Independent proposal optimising zero-config scanning and developer experience (adopted: collector parsing rules, conformance-level progression, SARIF, integrations) |
| `exporter-notes-ihvm.md` | Pre-M0 exporter research (CycloneDX taxonomy, SPDX 3.0.1 mapping, companion and loss model) with primary-source-verified standards facts; where it disagrees with `spec/`, the spec wins |
| `gap-register-attack-lens.json` | 22 gaps in CycloneDX 1.7 / SPDX 3.0.1 for agentic supply chains, extracted from the source analysis through the attack-and-incident lens, each mapped to OWASP ASI / MITRE ATLAS and to the Symbiote feature that closes it |
| `verified-claims-ihvm.json` | 64 claims from the source analysis and the Medium article checked against primary sources (verdict, what is actually true, suggested fix, sources), grouped by topic; the basis of the corrections table in the gap analysis |
| `document-review.md` | WP17 review and verification report on the original Medium article and working document: method, verdict counts, the 15 most consequential corrections, contradictions, and what version 2 changes |
| `verified-claims.json` | WP17 claim register: 149 claims (61 article, 88 document), each with verdict, severity, what the sources show, suggested rewrite and evidence URLs; high-impact claims were re-checked by an adversarial second pass and reconciled with `verified-claims-ihvm.json` |
| `claim-register.md` | The register as tables, generated from `verified-claims.json` |
| `gap-analysis-v2.md` | Part I of the fact-checked SymBiote document (version 2): gap analysis of CycloneDX 1.7 and SPDX 3.0.1 by layer, after a section-by-section fact-check and red-team pass; offered as the replacement for `docs/gap-analysis.md` |
| `landscape.md`, `landscape.json` | Capability matrix of 31 AgentBOM-adjacent tools and specifications against gaps G1-G10, every cell justified with a cited source; the SymBiote row is a self-assessment |
| `gap-analysis.docx` | Word export of `docs/gap-analysis.md` (`pandoc docs/gap-analysis.md -o docs/research/gap-analysis.docx`) for republication |

The two proposals marked "incomplete" stop before their later sections because the account's API rate limit
interrupted them; their completed sections were used in the synthesis.
