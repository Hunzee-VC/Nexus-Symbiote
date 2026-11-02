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
| `gap-analysis.docx` | Word export of `docs/gap-analysis.md` (`pandoc docs/gap-analysis.md -o docs/research/gap-analysis.docx`) for republication |

The two proposals marked "incomplete" stop before their later sections because the account's API rate limit
interrupted them; their completed sections were used in the synthesis.
