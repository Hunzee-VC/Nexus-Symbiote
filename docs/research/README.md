# Research and design inputs

Artefacts produced while designing Symbiote on 2026-11-01. They are inputs, not the specification; the
normative text lives in `spec/`.

| File | What it is |
|---|---|
| `design-brief.md` | The shared brief (thesis, hard requirements R1–R12, verified facts) every architecture proposal worked from |
| `proposals/enforcement-first.md` | Independent proposal designed backwards from the gateway, policy engine and incident responder (adopted as the backbone) |
| `proposals/standards-purist.md` | Independent proposal maximising native CycloneDX/SPDX constructs and upstreamability (adopted: `agentbom:` namespace, encoding ladder, verified-facts table) |
| `proposals/adoption-first.md` | Independent proposal optimising zero-config scanning and developer experience (adopted: collector parsing rules, conformance-level progression, SARIF, integrations) |
| `gap-register-attack-lens.json` | 22 gaps in CycloneDX 1.7 / SPDX 3.0.1 for agentic supply chains, extracted from the source analysis through the attack-and-incident lens, each mapped to OWASP ASI / MITRE ATLAS and to the Symbiote feature that closes it |

The two proposals marked "incomplete" stop before their later sections because the account's API rate limit
interrupted them; their completed sections were used in the synthesis.
