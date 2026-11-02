# CLI reference

Every command, flag and exit code of the `symbiote` command as it exists on this branch (`symbiote 0.1.0`,
AgentBOM profile `0.1`). The outputs below were produced by running the commands against the example agent in
[`examples/triage-agent`](https://github.com/aisecnomad/symbiote/tree/main/examples/triage-agent); long lines are
trimmed with `…`. The normative command surface, including commands that are specified but not implemented yet,
is [`spec/cli.md`](../spec/cli.md); the differences are listed at the [end of this page](#specified-but-not-yet-implemented).

```text
$ symbiote --help
 Usage: symbiote [OPTIONS] COMMAND [ARGS]...

 Symbiote — the Agent Bill of Materials (AgentBOM) toolkit. Generates, validates, diffs,
 verifies, attests and enforces AgentBOMs; extends CycloneDX 1.7 and SPDX 3.0.1 without
 forking them.

╭─ Commands ───────────────────────────────────────────────────────────────────────────────╮
│ version      Show the tool and profile versions.                                         │
│ scan         Zero-config collection: produce a declared AgentBOM snapshot (companion,    │
│              CycloneDX 1.7, SPDX 3.0.1) from a repository.                               │
│ validate     Validate companion documents (AgentBOM schema) and CycloneDX 1.6/1.7        │
│              documents (official schemas).                                               │
│ verify       Verify a DSSE envelope (key-based) or a Sigstore bundle (keyless) and its   │
│              binding to a companion document.                                            │
│ conformance  Evaluate AgentBOM conformance requirements (spec/conformance.md) up to the  │
│              requested level.                                                            │
│ score        Completeness score (a BOM-quality number, never a trust score) with         │
│              per-area reasons.                                                           │
│ diff         Typed delta between two companion documents of any snapshot kinds — the    │
│              diff is the finding.                                                        │
│ schema       Export the schemas and vocabularies Symbiote implements.                    │
│ allowlist    Enforcement exports for tool gateways and policy engines.                   │
│ digest       Compute digests exactly as the BOM does (spec/digests.md).                  │
│ merkle       Merkle commitment: verify documents and produce inclusion proofs.           │
│ attest       Build and sign in-toto statements (DSSE).                                   │
│ policy       Built-in policy checks (SYM-*), SARIF output and check documentation.       │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

## Conventions

- **`--json`** is accepted by every command that produces a result. Machine-readable JSON goes to **stdout**;
  human-readable output (rendered with `rich`) goes to **stderr**, so `symbiote … --json > out.json` is safe.
- **Secrets never appear in output.** Collectors record credential and header *names*, never values.
- **Paths** are plain file or directory arguments; there is no configuration file or global `--store` default on
  this branch (the chain store is opt-in per command with `--store DIR`).

### Exit codes

The codes are stable (`spec/cli.md`). The third column says which commands on this branch actually produce each
code; 6 and 8 are reserved for commands that are specified but not yet implemented.

| Code | Meaning | Produced by |
|---|---|---|
| 0 | success; no finding at or above `--fail-on`; every served tool allowed | all |
| 1 | findings at or above the threshold, or a requested change event, or an `undigestable` input | `policy check`, `conformance` (a requirement **failed**), `diff --fail-on-change`, `allowlist check`, `digest tooldef` |
| 2 | usage error (unknown command or value, missing `--key`/`--public-key`/`--policy`) | all |
| 3 | schema validation failure of an input or an emitted document | `validate`, `scan` (an exported document failed the official schema) |
| 4 | verification failure: signature, digest binding, identity constraint or Merkle root | `verify`, `merkle verify` |
| 5 | coverage insufficient for the requested conformance level (only `unknown` requirements block it) | `conformance` |
| 6 | collector / I-O error (reserved) | — |
| 7 | anti-rollback conflict: the snapshot's serial does not exceed the recorded chain head | `verify --store`, `scan --store` |
| 8 | a loss report dropped a security-relevant field under `--strict` (reserved) | — |

`scan` deliberately exits 0 when policy findings exist: collection succeeded, and the findings are recorded in the
document. Gate a pipeline with `policy check`, `conformance` or `diff`, not with `scan`.

## `symbiote version`

```text
$ symbiote version
symbiote 0.1.0 (AgentBOM profile 0.1)
$ symbiote version --json
{
  "symbiote": "0.1.0",
  "agentbomSpecVersion": "0.1"
}
```

## `symbiote scan`

```text
 Usage: symbiote scan [OPTIONS] [path]

 Zero-config collection: produce a declared AgentBOM snapshot (companion, CycloneDX 1.7, SPDX 3.0.1)
 from a repository.

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────╮
│   path      <path>  Repository or agent directory to scan. [default: .]                  │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────────────────╮
│ --out            -o      <path>  Output directory. [default: .]                          │
│ --name                   <str>   Agent name (defaults to symbiote.yaml/agent.yaml or the │
│                                  directory name).                                        │
│ --format                 <str>   companion | cyclonedx | spdx | all [default: all]       │
│ --include-text                   Embed tool descriptions and schemas (digests only by    │
│                                  default).                                               │
│ --deterministic                  Pin timestamps and the Merkle nonce for byte-identical  │
│                                  output.                                                 │
│ --user-scope                     Also read user-scope client configuration from the home │
│                                  directory.                                              │
│ --store                  <path>  Chain store directory: allocate serial/prev and enforce │
│                                  anti-rollback.                                          │
│ --no-policy                      Skip the built-in policy checks (derived flags/findings │
│                                  stay empty).                                            │
│ --shadowscan-report      <path>  Fold a Nexus ShadowScan report (JSON or CycloneDX) into │
│                                  the scan: observed tool servers, autonomy interval,     │
│                                  coverage.                                               │
│ --shadowscan-scope       <str>   root (findings about this repository) | estate (every   │
│                                  finding). [default: root]                               │
│ --valid-for              <int>   Validity window in days (sets                           │
│                                  snapshot.validity.not_after; AB-STD-05).                │
│ --profile                <str>   Evaluate conformance at this level after the scan:      │
│                                  minimal | standard | verified (exit 5 when not attained).│
│ --json                           Machine-readable JSON on stdout.                        │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

`scan` reads the agent declaration (`symbiote.yaml` or `agent.yaml`: name, version, purpose, owner, framework),
runs every collector whose `detect()` fires (see the [collectors guide](../guides/collectors.md)), runs the
built-in policy checks, seals the document with a salted Merkle commitment and writes:

| File | Content |
|---|---|
| `agentbom.json` | the companion document (`application/vnd.agentbom+json`), the structured source of truth |
| `agentbom.cdx.json` | CycloneDX 1.7, validated against the official `bom-1.7` schema before it is written |
| `agentbom.spdx.json` | SPDX 3.0.1 JSON-LD, validated against the official 3.0.1 JSON schema |
| `agentbom.cdx.loss.json`, `agentbom.spdx.loss.json` | loss reports: every model field without a native home in the target format and where it was preserved |
| `agentbom.validation.json` | validation evidence (`symbiote.validation/v1`): whether each export validated against its official schema, the companion and snapshot digests; `symbiote conformance` reads it automatically |

The companion is written **last**: its `links` bind the CycloneDX document (serial number, `urn:cdx` BOM-Link,
SHA-256 of the written bytes) and the SPDX document (document IRI, SHA-256), and its `lossReport` carries the
CycloneDX loss report. The exports reference the companion by its snapshot digest (the Merkle root), so the
binding has no cycle: `links` and `lossReport` are not committed leaves and adding them after sealing leaves the
root — and `symbiote verify` — intact. With `--profile minimal` a zero-config scan of `examples/triage-agent`
attains **Minimal** conformance; `--valid-for 90` satisfies the validity-window requirement of Standard.

```text
$ symbiote scan examples/triage-agent -o /tmp/out --deterministic
agent:triage-agent  snapshot sha256:1672f9d2fa7b0364…  (declared, serial 1)
entities: agents=1, tool_servers=7, identities=3, credential_bindings=3, parties=1
coverage: tools=partial  (other surfaces: not-attempted)
collectors: mcp-config:ok, mcp-live:skipped, mcp-registry:skipped, otel-traces:skipped
written: /tmp/out/agentbom.json
written: /tmp/out/agentbom.cdx.json
written: /tmp/out/agentbom.spdx.json
policy: 11 failing finding(s), 2 indeterminate — run `symbiote policy check /tmp/out/agentbom.json` for details
  high     SYM-COV-001  agent:triage-agent  Not fully covered: code, data, identity, instructions, model-gateway, …
  high     SYM-MCP-002  server:claude-code-filesystem  Server 'filesystem' launches pkg:npm/%40modelcontextprotocol/server-filesystem without pin…
  high     SYM-TOOL-001  server:claude-code-github  Server 'github': no tool definition is pinned (tools were never observed or approved).
  …
CycloneDX 1.7 validates against the official schema
SPDX 3.0.1 validates against the official schema
```

With `--json` the same run reports the snapshot digest, serial and kind, entity counts, per-surface coverage,
collector statuses, the files written, `cyclonedxValid` / `spdxValid`, the finding counts by severity and state,
the derived flags that are not `false`, and any chain issues:

```json
{
  "agent": "agent:triage-agent",
  "snapshot": "sha256:1672f9d2fa7b0364833f857df21f0930e73ce68f2e051c1c51af466a3146651f",
  "serial": 1,
  "kind": "declared",
  "entities": {"agents": 1, "tool_servers": 7, "identities": 3, "credential_bindings": 3, "parties": 1},
  "edges": 10,
  "coverage": {"code": "not-attempted", "registry": "not-attempted", "identity": "not-attempted",
               "model-gateway": "not-attempted", "tools": "partial", "data": "not-attempted",
               "runtime": "not-attempted", "network": "not-attempted", "instructions": "not-attempted",
               "policy": "not-attempted"},
  "cyclonedxValid": true,
  "spdxValid": true,
  "findings": {"fail": {"critical": 0, "high": 10, "medium": 1, "low": 0, "info": 0},
               "indeterminate": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0}},
  "flags": {"lethal-trifecta": "unknown", "rule-of-two-violation": "unknown", "unpinned-tool": "true",
            "unauthenticated-tool-server": "unknown", "static-long-lived-credential": "unknown"},
  "chainIssues": []
}
```

Notes:

- `--deterministic` pins `producedAt` to `2000-01-01T00:00:00Z` and the Merkle nonce to all zeros, so two scans of
  identical inputs are byte-identical. **A deterministic document is not suitable for redaction**: with a known
  nonce every leaf salt is derivable. Use the default (random nonce) for documents you intend to redact.
- `--store DIR` allocates `serial` and `prev` from the chain store and commits the new head (`chains.json`). A
  serial that would regress or fork the recorded head aborts with exit 7. See
  [attestation and enforcement](../guides/attestation-and-enforcement.md#anti-rollback-the-chain-store).
- `--user-scope` additionally reads `~/.claude.json`, `~/.cursor/mcp.json`, Claude Desktop, VS Code user,
  Windsurf, `~/.codex/config.toml` and `~/.gemini/settings.json`. Without it, user scope is recorded as
  `not-attempted` coverage rather than silently skipped.
- `--format companion` skips the CycloneDX/SPDX exporters; the JSON summary then still reports
  `cyclonedxValid: true` / `spdxValid: true` because nothing was validated (nothing failed), which is a known
  wart.
- Exit codes: 0 on success (even with findings); 3 if an exported document fails official schema validation; 7
  on a chain conflict; 2 for an unknown `--format`.

## `symbiote validate`

```text
 Usage: symbiote validate [OPTIONS] {files}...
 Validate companion documents (AgentBOM schema) and CycloneDX 1.6/1.7 documents (official schemas).
```

The format is detected from the content: `bomFormat: CycloneDX` → the official JSON Schema for its
`specVersion` (and `cyclonedx-python-lib`'s strict validator when available); `specVersion` plus `snapshot` → the
committed companion JSON Schema (Draft 2020-12, `additionalProperties: false`); an SPDX `@context` → the official
SPDX 3.0.1 JSON schema. Anything else fails as `unknown`, including the `*.loss.json` loss reports, so validate
the three documents rather than `out/*.json`:

```text
$ symbiote validate /tmp/out/agentbom.json /tmp/out/agentbom.cdx.json /tmp/out/agentbom.spdx.json
ok  /tmp/out/agentbom.json (agentbom-companion)
ok  /tmp/out/agentbom.cdx.json (cyclonedx-1.7)
ok  /tmp/out/agentbom.spdx.json (spdx-3.0.1)
```

A schema error names the JSON path and the offending value (exit 3):

```text
$ symbiote validate bad.cdx.json
FAIL bad.cdx.json (cyclonedx-1.7)
   components/0/type: 'agent' is not one of ['application', 'framework', 'library', 'container', 'platform',
'operating-system', 'device', 'device-driver', 'firmware', 'file', 'machine-learning-model', 'data',
'cryptographic-asset']
```

`--json` returns `[{"file", "format", "ok", "errors"}]`. Exit 3 if any file fails or cannot be read.

## `symbiote digest`

Compute digests exactly as the BOM and a gateway do (`spec/digests.md`). Four subcommands:

| Subcommand | Digest kind | Options |
|---|---|---|
| `digest tooldef SOURCE` | `tooldef/v1` over a raw MCP tool definition (`SOURCE` is a file or `-` for stdin) | `--full` for `tooldef-full/v1` (adds `_meta`, `icons`, `execution`), `--json` |
| `digest file PATH` | SHA-256 of the exact bytes plus `size`, `lineEndings` and a `triageDigest` | `--json` |
| `digest dir PATH` | `dirmanifest/v1` with an OpenSSF model-signing compatible root | `--allow-symlinks`, `--json` |
| `digest prompt PATH` | `prompt/v1` over a template | `--engine`, `--role`, `--variables-schema PATH`, `--json` |

```text
$ symbiote digest tooldef tool.json --json
{
  "algorithm": "tooldef/v1",
  "value": "sha256:2436ff3a7eff3889c2e071ff658d6db0ca957620ba565f0fae3c80b0052c2c5b",
  "status": "ok",
  "textFlags": []
}
```

(`tool.json` is the `tests/vectors/tooldef/annotated.json` vector; the value matches the vector's expected
digest, which is how other implementations prove digest agreement.) A definition JCS cannot represent is
reported, never approximated, and the command exits 1:

```text
$ symbiote digest tooldef bad-tool.json
tooldef/v1: UNDIGESTABLE (integer-out-of-range: $.inputSchema.maxItems: |9007199254740993| >= 2^53)
```

`digest file` agrees with `sha256sum` on the raw bytes and adds the facts the BOM records:

```text
$ symbiote digest file examples/triage-agent/CLAUDE.md --json
{
  "path": "examples/triage-agent/CLAUDE.md",
  "digest": "sha256:4f6df5170d3aab3751189370bfcfc78a34fc9f8a31793d6cf6879a83d394c7d5",
  "size": 150,
  "lineEndings": "lf",
  "triageDigest": "sha256:a635ec199c6525f77ace3cac484e47100be7bb6262d793aba4d02fba544af6d1"
}
```

```text
$ symbiote digest dir examples/triage-agent/.claude/skills/issue-triage
root sha256:3209f36ce21672ce759b24fee492baca53812f404f685f42b0e045ac10ec7c1b  (2 files; manifest sha256:7243b471…)
$ symbiote digest prompt examples/triage-agent/prompts/system.md --engine jinja2 --role system \
    --variables-schema examples/triage-agent/prompts/system.schema.json --json
{
  "algorithm": "prompt/v1",
  "value": "sha256:facd66d21e56011d9b8147da5552fa1ebcd874e63317086dfe3f04a40864241f",
  "status": "ok"
}
```

## `symbiote merkle verify`

```text
 Usage: symbiote merkle verify [OPTIONS] {companion}
 Recompute the Merkle root of a companion document (disclosed leaves + redacted leaf hashes) and compare.
```

```text
$ symbiote merkle verify /tmp/out/agentbom.json --json
{
  "file": "/tmp/out/agentbom.json",
  "root": "sha256:1672f9d2fa7b0364833f857df21f0930e73ce68f2e051c1c51af466a3146651f",
  "verified": true,
  "redactedLeaves": 0
}
```

Any change to any entity after sealing is a mismatch (exit 4):

```text
$ symbiote merkle verify tampered.json
MISMATCH sha256:1672f9d2fa7b0364833f857df21f0930e73ce68f2e051c1c51af466a3146651f
```

`merkle prove` (inclusion proofs) is specified but not implemented on this branch.

## `symbiote attest snapshot`

```text
 Usage: symbiote attest snapshot [OPTIONS] {companion}
 Sign an agentbom-snapshot/v1 statement over a finalised companion document (key-based DSSE or Sigstore keyless).

╭─ Options ────────────────────────────────────────────────────────────────────────────────╮
│ --key                     <path>  PEM private key (ECDSA P-256 or Ed25519) for key-based │
│                                   DSSE.                                                  │
│ --keyless                         Sign with Sigstore (OIDC identity); writes a Sigstore  │
│                                   bundle.                                                │
│ --staging                         Use the Sigstore staging instance.                     │
│ --identity-token          <str>   OIDC identity token for keyless signing.               │
│ --issuer-url              <str>   OIDC issuer to obtain a token from interactively.      │
│ --out             -o      <path>                                                         │
│ --json                            Machine-readable JSON on stdout.                       │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

```text
$ symbiote attest snapshot /tmp/out/agentbom.json --key key.pem -o snapshot.dsse.json --json
{
  "out": "snapshot.dsse.json",
  "predicateType": "https://aisecnomad.github.io/symbiote/attestation/agentbom-snapshot/v1",
  "subjects": [
    {"name": "snapshot:agent:triage-agent",
     "digest": {"sha256": "1672f9d2fa7b0364833f857df21f0930e73ce68f2e051c1c51af466a3146651f"}},
    {"name": "companion",
     "digest": {"sha256": "e2888aed689586c452328ea87daa921851a71e9bbb33e41da8056ea16038e3c0"}}
  ],
  "signatures": ["0f68c4d950fbd71f46eac05251fabc61ee19b4062cb7cd6beb3de6826b327375"],
  "mode": "key-based"
}
```

The default output file is `snapshot.dsse.json` (key-based) or `snapshot.sigstore.json` (keyless). Keyless signing
requires the `[sign]` extra and an OIDC identity (ambient CI credential, `--identity-token` or `--issuer-url`).
Passing neither `--key` nor `--keyless` is a usage error (exit 2). Details:
[attestation and enforcement](../guides/attestation-and-enforcement.md).

## `symbiote verify`

```text
 Usage: symbiote verify [OPTIONS] {envelope}
 Verify a DSSE envelope (key-based) or a Sigstore bundle (keyless) and its binding to a companion document.

╭─ Options ────────────────────────────────────────────────────────────────────────────────╮
│ --public-key                    <path>  Trusted PEM public key(s) for key-based DSSE     │
│                                         envelopes.                                       │
│ --policy                        <path>  YAML verification policy (identities, issuer,    │
│                                         staging) for Sigstore bundles.                   │
│ --companion                     <path>  Companion document the statement must bind to.   │
│ --insecure-unconstrained                Accept a Sigstore signature without identity     │
│                                         constraints (outcome:                            │
│                                         signature-valid-unconstrained).                  │
│ --store                         <path>  Chain store directory for anti-rollback checks   │
│                                         of the companion's snapshot.                     │
│ --json                                  Machine-readable JSON on stdout.                 │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

```text
$ symbiote verify snapshot.dsse.json --public-key key.pub --companion /tmp/out/agentbom.json --json
{
  "envelope": "snapshot.dsse.json",
  "outcome": "verified-constrained",
  "bindings": [
    {"subject": "snapshot", "ok": true},
    {"subject": "companion", "ok": true},
    {"subject": "merkle", "ok": true}
  ],
  "warnings": [],
  "acceptedKeyIds": ["0f68c4d950fbd71f46eac05251fabc61ee19b4062cb7cd6beb3de6826b327375"],
  "predicateType": "https://aisecnomad.github.io/symbiote/attestation/agentbom-snapshot/v1"
}
```

| Situation | Output | Exit |
|---|---|---|
| wrong public key | `signature failed: 0 trusted signature(s) verified, 1 required` | 4 |
| companion edited after signing | `digest mismatch https://…/agentbom-snapshot/v1` (`outcome: digest-mismatch`) | 4 |
| serial below the chain head (`--store`) | `verified-constrained … SERIAL REGRESSION` with `chainIssues: [SYM-SNAP-001 …]` | 7 |
| Sigstore bundle without identity constraints and without `--insecure-unconstrained` | `error: verification policy has no identity constraints…` | 4 |
| neither `--public-key` nor `--policy` | `pass --public-key (key-based) or --policy (Sigstore)` | 2 |

## `symbiote policy`

```text
 Usage: symbiote policy check [OPTIONS] {companion}
 Run the built-in SYM-* checks over a companion document (spec/checks.md).

╭─ Options ────────────────────────────────────────────────────────────────────────────────╮
│ --fail-on                      <str>   critical | high | medium | low | info [default:   │
│                                        high]                                             │
│ --select                       <str>   Check id glob(s) to run, e.g. SYM-MCP-*           │
│ --exclude                      <str>   Check id glob(s) to skip                          │
│ --baseline                     <path>  Approved/declared companion to compare against    │
│                                        (undeclared-component findings)                   │
│ --sarif                        <path>  Write SARIF 2.1.0 to this file                    │
│ --fail-on-indeterminate                Treat indeterminate findings as failures          │
│ --json                                 Machine-readable JSON on stdout.                  │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

```text
$ symbiote policy check /tmp/out/agentbom.json
13 finding(s) from 60 checks; flags: lethal-trifecta=unknown, rule-of-two-violation=unknown, unpinned-tool=true, …
critical indeterminate SYM-AUTHZ-001  agent:triage-agent
           Trifecta assessment incomplete: untrusted input=true, sensitive access=true, exfiltration=unknown, state change=unknown.
high     fail          SYM-COV-001    agent:triage-agent
           Not fully covered: code, data, identity, instructions, model-gateway, network, policy, registry, runtime, tools.
high     indeterminate SYM-MCP-001    server:cursor-github
           Server 'github' crosses a trust boundary; its authentication or tool capabilities are unknown.
high     fail          SYM-MCP-002    server:claude-code-filesystem
           Server 'filesystem' launches pkg:npm/%40modelcontextprotocol/server-filesystem without pinning (dist-tag:latest): every start may fetch new code.
…
medium   fail          SYM-MCP-006    agent:triage-agent
           Agent combines 2 ungated external server(s) with 4 internal/local server(s).
```

Exit 1 because findings at or above `high` are in state `fail`. `indeterminate` findings (an input the check
needs is `unknown`) never fail silently; they are listed and counted separately, and `--fail-on-indeterminate`
turns them into failures. `--select` / `--exclude` take check-id globs and may be repeated. `--baseline` compares
against an approved or earlier declared document and enables the undeclared-component checks (`SYM-TOOL-002`,
`SYM-SUB-001`). `--sarif FILE` writes SARIF 2.1.0 for GitHub code scanning. The guide:
[policy and conformance](../guides/policy-and-conformance.md).

```text
$ symbiote policy list
SYM-A2A-001    medium   Unsigned agent card
SYM-ATT-001    medium   Signature from an unconstrained signer
…
SYM-TRUST-002  critical Component from a revoked publisher
$ symbiote policy explain SYM-TOOL-001
{
  "id": "SYM-TOOL-001",
  "title": "Unpinned tool",
  "severity": "high",
  "description": "A tool has no usable digest, or exists only as a declared name with no served definition.",
  "remediation": "Observe the server live (`symbiote scan --live`), review the served tool definitions and approve the toolset digest; …",
  "inputs": ["tools[].digest", "tools[].source", "tool_servers[].toolset_digest"],
  "mappings": [{"framework": "owasp-asi-2025", "id": "ASI04"},
               {"framework": "mitre-atlas", "id": "AML.T0109"},
               {"framework": "mitre-atlas", "id": "AML.T0110"}],
  "extension": false,
  "rego": false
}
```

`policy list` prints 60 checks (`--json` for records). `policy explain` of an unknown id currently ends in a
Python traceback (`KeyError`) instead of a usage error; this is tracked as a CLI defect.

## `symbiote conformance`

```text
 Usage: symbiote conformance [OPTIONS] {companion}
 Evaluate AgentBOM conformance requirements (spec/conformance.md) up to the requested level.
  --level  <str>  minimal | standard | verified [default: minimal]
```

```text
$ symbiote conformance /tmp/out/agentbom.json --level minimal
requested minimal; attained none — NOT ATTAINED
Conformance describes the document's completeness and evidence, not the agent's safety.
pass    AB-MIN-01  Agent identity
pass    AB-MIN-02  Every model has an identity or explicit unknown
pass    AB-MIN-03  Every tool server has transport and package or endpoint
pass    AB-MIN-04  Every tool definition has a digest or an undigestable reason
pass    AB-MIN-05  Every instruction file and skill is digested
pass    AB-MIN-06  Coverage statement for all ten surfaces
unknown AB-MIN-07  Exported documents validate against the official schemas  — no CycloneDX validation result supplied (run `symbiote validate`)
pass    AB-MIN-08  No secret values anywhere
```

Exit 5: nothing failed, but one requirement is `unknown`, and a level is attained only with no `fail` and no
`unknown`. Exit 1 when any requirement fails (as with `--level standard` on the same document, where
`AB-STD-02`, `-04`, `-05` and `-10` fail). `--json` returns `{requested, attained, passed, note, requirements[]}`.

## `symbiote score`

```text
$ symbiote score /tmp/out/agentbom.json
completeness 63/100 — BOM completeness, not a trust or safety score.
assurance: declared=100%, observed=0%, verified=0%
tools          20/28 (weight 25)  missing: server:claude-code-filesystem: toolset digest, …
authorization  0/7 (weight 20)  missing: server:claude-code-filesystem: declared grant, …
models         0/0 (weight 15)
data           0/0 (weight 10)
identity       3/6 (weight 10)  missing: cred:claude-code-github-header-authorization: credential kind, …
instructions   0/0 (weight 10)
coverage       0/10 (weight 5)  missing: surface code queried, surface data queried, …
evidence       14/14 (weight 5)
```

Always exit 0; the score is information, never a gate. The assurance distribution is printed alongside so a
high score made of purely declared facts reads as what it is.

## `symbiote diff`

```text
 Usage: symbiote diff [OPTIONS] {before} {after}
 Typed delta between two companion documents of any snapshot kinds — the diff is the finding.
  --fail-on-change  <str>   Delta event type(s) that make the command exit 1, e.g. tool-definition-changed
  --out       -o    <path>  Write the Delta JSON here
```

Comparing the example scan with a second scan in which the `filesystem` server was pinned to an exact version
and a `jira` server over plain HTTP was added:

```text
$ symbiote diff v1/agentbom.json v2/agentbom.json
2 event(s): sha256:1672f9d2fa7b… (declared) -> sha256:e647954ae86a… (declared)
high     server-added                 server:claude-code-jira  crosses a trust boundary
critical server-identity-changed      server:claude-code-filesystem  server/v1 identity changed (kind, transport, endpoint, package, serverInfo or in…
$ symbiote diff v1/agentbom.json v2/agentbom.json --fail-on-change server-added; echo $?
…
1
```

Events are typed (`tool-registered`, `tool-definition-changed`, `server-added`, `server-identity-changed`,
`model-routed`, `sub-agent-spawned`, `memory-writer-added`, `grant-added`, …) and carry `before`/`after` identity
digests, so re-collection of unchanged facts produces zero events. `--fail-on-change` may be repeated; it exits 1
only when a listed event type occurs. `-o` writes the `Delta` JSON (`{id, fromSnapshot, toSnapshot, producedAt,
producer, events[]}`).

## `symbiote allowlist`

```text
 Usage: symbiote allowlist export [OPTIONS] {companion}
  --format       <str>  gab | opa-data | mcp-gateway-generic [default: gab]
  --out    -o    <path>
  --attestation  <str>  Attestation file names to reference from the bundle.

 Usage: symbiote allowlist check [OPTIONS] {gab} {server} {tools_json}
 Reference enforcement: decide allow/block/drop for served tools against a GAB.
```

```text
$ symbiote allowlist export approved.agentbom.json --format mcp-gateway-generic
[
  {"digest": "sha256:97ec8101875edeb2c8eef961b6c74c35cd2333bc6689003807f1b50d0a3fa0be",
   "gate": "required", "server": "server:github", "tool": "add_issue_comment"},
  {"digest": "sha256:2436ff3a7eff3889c2e071ff658d6db0ca957620ba565f0fae3c80b0052c2c5b",
   "gate": "required", "server": "server:github", "tool": "get_issue"}
]
$ symbiote allowlist check gab.json server:github served-tools.json
allow get_issue                      digest-matches-allowlist
allow add_issue_comment              digest-matches-allowlist
$ symbiote allowlist check gab.json server:github served-tools-rugpull.json
block get_issue                      rug-pull-signal: known name, new digest
drop  send_email                     unknown-tool-name
drop  add_issue_comment              approved-tool-missing
```

`check` exits 1 when any decision is not `allow`. `tools_json` is a raw `tools/list` result (an array of tool
objects, or an object with a `tools` array). The full bundle format and the rules a gateway applies are in the
[attestation and enforcement guide](../guides/attestation-and-enforcement.md#the-gateway-allowlist-bundle).

## `symbiote schema export`

```text
 Usage: symbiote schema export [OPTIONS] [which]
   which  <str>  companion | predicates | taxonomy [default: companion]
  --out  -o  <path>  Write to this file instead of stdout.
```

`companion` prints the generated JSON Schema of the companion document (identical to the committed
`src/symbiote/schemas/agentbom/agentbom-0.1.schema.json`; CI diffs the two). `predicates` prints the in-toto
predicate type URIs:

```json
{
  "agentbom-snapshot": "https://aisecnomad.github.io/symbiote/attestation/agentbom-snapshot/v1",
  "tool-definition-set": "https://aisecnomad.github.io/symbiote/attestation/tool-definition-set/v1",
  "coverage": "https://aisecnomad.github.io/symbiote/attestation/coverage/v1",
  "evaluation": "https://aisecnomad.github.io/symbiote/attestation/evaluation/v1",
  "registry-resolution": "https://aisecnomad.github.io/symbiote/attestation/registry-resolution/v1",
  "observed-delta": "https://aisecnomad.github.io/symbiote/attestation/observed-delta/v1",
  "trust-status": "https://aisecnomad.github.io/symbiote/attestation/trust-status/v1",
  "approval": "https://aisecnomad.github.io/symbiote/attestation/approval/v1"
}
```

`taxonomy` prints `spec/taxonomy.md`. An unknown name exits 2.

## Specified but not yet implemented

[`spec/cli.md`](../spec/cli.md) is the target surface for 0.1.0. On this branch the following are **not**
available yet, and documentation elsewhere that mentions them describes the specification, not the tool:

| Specified | Status |
|---|---|
| `scan --live`, `--registry`, `--profile`, `--sbom`, `--nonce` | the live, registry and OTel collectors exist as Python modules and run through the API (`symbiote.collect.run_collectors` with `CollectContext(options=…)`), not from the CLI; `scan` has no profile selection |
| `init`, `collect`, `observe`, `generate`, `import`, `convert`, `redact`, `registry resolve`, `model …`, `trust …`, `index …`, `query …` | not implemented |
| `attest toolset|coverage|evaluation|resolution|delta|trust-status|approval` | only `attest snapshot`; the predicate builders exist in `symbiote.attest.statements` |
| `merkle prove`, `validate --cross`, `policy export-rego`, `--jsf-sign`, `--cdx-version 1.6`, `--embed-records`, `--redact` | not implemented |
| global `--quiet`, `--config`, default store `./.symbiote/store` | not implemented; the store is opt-in via `--store` |
| GitHub Action (`action.yml`) and `.pre-commit-hooks.yaml` | available: the composite Action (`scan` → `validate` → `policy check --sarif` → optional `conformance`) and the `symbiote-scan` / `symbiote-policy` hooks; see the [CI guide](../guides/ci.md). Not yet available: the optional keyless `attest snapshot` step |
