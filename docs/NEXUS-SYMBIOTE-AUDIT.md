# Nexus SymBiote — Security, Correctness & Product Audit

**Target:** `github.com/aisecnomad/SymBiote` (package `nexus-symbiote`) @ `b5a52d7`
**Scope:** full codebase (~5,470 LoC src / ~4,300 LoC tests), schemas, examples, GitHub Action, CI, packaging.
**Method:** first‑hand static review of every module **plus empirical verification** — built the package in a clean venv (Python 3.13), ran the full suite (`pytest`/`ruff`/`mypy`/`pip-audit`), and reproduced each High‑severity finding with adversarial probes against the running tool. Findings marked **[reproduced]** were executed, not merely read.

> This is my primary verified analysis. A parallel 12‑dimension audit workflow (independent reviewers + adversarial verification + standards/competitive research) is finishing; its corroboration and citations will be reconciled in a follow‑up.

---

## 1. Executive summary

Nexus SymBiote pairs a **genuinely excellent security core** with a **control/CLI layer that is currently broken in ways that defeat the product's own purpose.** The domain modeling (`evidence.py`), the confined file readers (`confined.py`/`base.py`), and the canonical hashing (`hashing.py`) are top‑tier — careful, adversary‑aware, and honest about the difference between a *claim* and a *proof*. But the layer that turns that core into a usable gate is not wired up or is mis‑wired:

- The **"recommended primary workflow" (`import-shadowscan`) crashes on invocation** — a leftover pre‑rename import.
- The **risk gate can essentially never pass**, so the GitHub Action is effectively always‑red.
- The **drift gate (`diff`) exits 0** even on a critical rug‑pull, so it can't gate.
- The **real signature verification exists but has no caller** — the "verifier" never verifies.
- The **version‑pin signal is inverted** (digest‑pinned and `==`‑pinned deps are flagged "unpinned").
- The **tool's own output fails its own JSON Schema.**
- **All CI jobs are red on `main`** and the dependency tree ships **12 known CVEs**.

None of these are deep architectural flaws — they are fixable in days, and most are one‑liners or small refactors. The bones are strong enough that, once the control layer is repaired and the verification capability is wired through, this is a credible candidate for a best‑in‑class **agent‑native** BOM tool. The roadmap in §6 is what separates "works" from "top 0.1%."

### Severity tally

| Severity | Count | IDs |
|---|---|---|
| Critical | 2 | NS‑01, NS‑04 |
| High | 6 | NS‑02, NS‑03, NS‑05, NS‑06, NS‑07, NS‑18 |
| Medium | 8 | NS‑08, NS‑09, NS‑10, NS‑11, NS‑12, NS‑13, NS‑14, NS‑16 |
| Low | 3 | NS‑15, NS‑17, NS‑19 |
| Refuted (not reported) | 2 | union‑misclassification, registry pin parsing |

---

## 2. Empirical ground truth (CI/build state on `main`)

Built with `pip install -e ".[dev,all]"` in a clean Python 3.13 venv:

| Check | Result |
|---|---|
| `pytest` | **1 failed, 358 passed, 1 skipped** (`test_export_assurance.py::test_cyclonedx_strict_validator`) |
| `ruff check` | **2 errors** (unused imports in `scanners/shadowscan.py`) |
| `ruff format --check` | **fails** |
| `mypy src/nexus_symbiote/` | **4 errors** (stale `symbiote.*` imports in `cli.py`) |
| `pip-audit` | **12 known CVEs across 4 deps** (`cryptography`, `sigstore`, `tuf`, `pytest`) |
| Coverage | 92% overall, but `scanners/shadowscan.py` **25%**, `model.py` 84%, `rag.py` 85% |

**Every CI job defined in `.github/workflows/ci.yml` (lint, typecheck, test) is red on `main`.** A security tool shipping red CI is itself a trust signal problem.

---

## 3. Findings

Each finding: location → status → mechanism → impact → fix.

### NS‑01 — `import-shadowscan` (the "recommended primary workflow") is dead · **CRITICAL** · [reproduced]
**Where:** `src/nexus_symbiote/cli.py:202, 221, 225, 229`
The rename commit (`SymBiote → Nexus SymBiote`) missed four imports:
```python
from symbiote.scanners.shadowscan import ShadowScanImporter   # cli.py:202
from symbiote.generators.cyclonedx import CycloneDXGenerator   # :221
from symbiote.generators.spdx import SPDXGenerator             # :225
from symbiote.generators.sarif import SARIFGenerator           # :229
```
The package is now `nexus_symbiote` with no `symbiote` shim. Running `nexus-symbiote import-shadowscan report.json -o out.json` raises an **uncaught** `ModuleNotFoundError: No module named 'symbiote'`. This is also what fails `mypy` in CI. The README calls this command the *recommended primary workflow*, and its body (`cli.py:202–236`) is **0% covered** by tests.
**Impact:** The flagship ingestion path is 100% broken; CI is red; the primary documented workflow cannot run.
**Fix:** Replace `symbiote.` → `nexus_symbiote.`; move the imports to module top; add an end‑to‑end `import-shadowscan` test (native JSON + CycloneDX fixtures); make CI's typecheck job gate merges.

### NS‑04 — The "verification" tool never cryptographically verifies · **CRITICAL** · [grep‑confirmed]
**Where:** `src/nexus_symbiote/utils/crypto.py` (whole module); `scanners/model.py:153–160`
`crypto.py` contains a **correct, fail‑closed** Sigstore verifier (`verify_sigstore_digest`/`verify_sigstore_bundle` — requires an explicit identity+issuer policy, uses `Verifier.production(offline=True).verify_artifact(...)`). But it has **no caller anywhere** in the package (only a re‑export in `utils/__init__.py` and `test_crypto.py`). The model scanner only checks for the *presence* of a signature file and records `"signature-present-unverified"`; the integrity validator never calls `crypto`. Likewise the excellent `DeploymentProfile`/`AuthorityClaim`/`EvidenceRecord` model (which *correctly* requires digest+verifier+policy+time for a `VERIFIED` claim) is **never produced or consumed** by any scanner or validator.
**Impact:** The product's headline capability — *verification* of signatures/provenance — is not delivered through any command. `assurance_level=verified` is unreachable in practice. SECURITY.md is honest about "presence ≠ verification," so this is not deceptive — but the differentiator is unwired.
**Fix:** Wire `verify_sigstore_bundle` into the model/registry scanners and the integrity validator, with configurable expected identities/issuers (a trust policy); only then set `assurance_level=verified` and `signing_status="verified"`. Populate `DeploymentProfile` from ShadowScan/scanner evidence and have the risk/policy layer consume `AuthorityClaim`.

### NS‑02 — The risk gate is structurally unreachable (Action is always‑red) · **HIGH** · [reproduced]
**Where:** `validators/risk.py:84–160` (esp. `passes_gate`), `cli.py:120`
`passes_gate` requires `coverage_status == "reported"`:
```python
passed = (report.overall_score < self.fail_threshold
          and not report.severity_counts.get("critical", 0)
          and report.coverage_status == "reported")
```
But `score()` only sets `"reported"` when **every** scanner in `scanner_status` is `"complete"` with no exclusions, and `cli.py:120` seeds `scanner_status = dict.fromkeys(all_scanners, "unknown")` for **all 8 registered scanners** — then marks any scanner that found nothing as `"partial"` (via `surfaces_excluded`). On a real project, most scanners legitimately find nothing → `"partial"` → gate can never reach `"reported"`.
**Reproduced:** a clean project (overall_score **11** < 50, `risk_level=moderate`) returned `coverage_status=partial` and the gate **FAILED (exit 1)**. With a policy file (5 scanners) it was still `partial`.
**Impact:** The GitHub Action risk gate fails on *every* build regardless of actual risk. It is fail‑closed (safe) but useless — teams will set `risk-threshold: 0` to disable it, which is worse than a working gate.
**Fix:** Base coverage on the **selected/required** scanners, not all registered ones; treat "scanner ran, found nothing" as `complete`, not `partial`; and separate three distinct gate outcomes — *insufficient coverage*, *risk exceeded*, *policy violated* — with distinct exit codes and messages so CI can act on each.

### NS‑03 — `diff` cannot gate: exits 0 on a critical rug‑pull · **HIGH** · [reproduced]
**Where:** `cli.py:361–404`
The `diff` command prints a `CRITICAL` security alert ("Tool definition hash changed — possible rug‑pull attack") but has **no `sys.exit`** on findings; it returns 0.
**Reproduced:** both `diff old new` and `diff old new --json-output` exit **0** despite emitting a critical alert. The README's "Drift detection" CI example implies gating.
**Fix:** Add `--fail-on <severity>` (default `high`) and exit non‑zero when `security_alerts`/modified‑severity meets the threshold.

### NS‑05 — Version‑pin signal is inverted (pinned deps flagged "unpinned") · **HIGH** · [reproduced]
**Where:** `core/hashing.py:81–99` (`extract_version_pin`), reached from `scanners/mcp.py:108`
`extract_version_pin` returns `None` (→ "unpinned") for the two most important pin formats:
```
extract_version_pin("pkg==1.2.3")        -> None   # exact pip pin treated as UNPINNED
extract_version_pin("img@sha256:<64hex>") -> None   # digest pin (strongest) treated as UNPINNED
```
The `==` branch only fires when the string *starts* with `==` (bare `==1.2.3`), not the real `name==1.2.3` form; digests never match the version regex. This is reachable via MCP docker/`uvx`/`pipx` servers (`_extract_package_ref` → `extract_version_pin`), so a **digest‑pinned MCP server is reported as HIGH "unpinned — vulnerable to supply chain attacks."**
**Impact:** The scanner inverts its core signal — penalizing the strongest supply‑chain hygiene and eroding trust in every pinning finding.
**Fix:** Parse `name==ver`, `name@sha256:…`/`@<digest>`, OCI digests, and `==ver` as pinned; add a table‑driven test matrix (npm/pip/uv/docker/OCI). Consider reusing `packaging`/`pip`'s requirement parser rather than hand‑rolled regex.

### NS‑06 — Policy trust‑boundary inversion + silently‑dead policy fields · **HIGH** · [reproduced]
**Where:** `policy.py:58–71` (`load_policy` walks up 20 parents), `cli.py:98` (scan) and `cli.py:299` (risk)
`risk` loads `.nexus-symbiote.yaml` from the **AIBOM's own directory** and `scan` from the **scanned directory** — both untrusted in CI (public‑PR checkout / generated artifact workspace).
**Reproduced:** placing `.nexus-symbiote.yaml` with `fail_threshold: 100000.0` next to the BOM caused `risk` to apply `threshold=100000.0`. An attacker opening a PR can ship a permissive policy that gates their own change.
Compounding this, several policy fields are **parsed but never enforced** — a policy that *looks* protective but isn't:
- `risk.ignore_categories` and `risk.warn_threshold` — never used by `RiskScorer`.
- `ValidatePolicy` (`require_completeness`, `require_integrity`, `minimum_assurance_level`) — the `validate` command never loads policy at all.
- `scan.exclude_paths` — never passed to scanners.
**Fix:** Load gating policy only from a **trusted** location (CWD or explicit `--policy`), never from the scanned tree/artifact; or treat an in‑tree policy as untrusted metadata (report it, don't enforce it). Then either enforce every policy field or delete it and document the gap.

### NS‑07 — Tool output is invalid against the project's own JSON Schema · **HIGH** · [reproduced]
**Where:** `schemas/nexus-symbiote-aibom-1.0.schema.json` (`ComponentType` enum, lines 175–182) vs `core/enums.py:ComponentType`
The published schema's `ComponentType` enum lists only 11 types; it is **missing `mcp-client`, `a2a-client`, `a2a-server`, `ide-agent`, `verified-extension`** — all of which have Pydantic models and are emitted by scanners (`mcp.py` creates `mcp-client`; `a2a.py`/`ide_agents.py` the others).
**Reproduced:** a live `scan` of a project with `.mcp.json` emitted an `mcp-client` component and the output **failed the project's own schema** (`'mcp-client' is not one of [...]`). The shipped examples pass only because they avoid those types.
**Fix:** Generate the JSON Schema from the Pydantic models (single source of truth) in a build step, cover all component types + per‑type properties, and validate the shipped examples **and a sample `scan` output** against it in CI.

### NS‑08 — Rug‑pull detection evadable via attacker‑controlled `bom_ref` · **MEDIUM** · [reproduced]
**Where:** `diff/differ.py:97–151`
Component correlation is keyed solely on `bom_ref`, which the adversary controls in the BOM. Mutating a tool definition **and** renaming its `bom_ref` turns a rug‑pull into a benign remove(info)+add(medium).
**Reproduced:** ref `tool:srv/search` → `tool:srv/search__v2` with a changed `definition_hash` produced **no critical alert** — only `added: [medium], removed: [info]`.
**Fix:** When a ref disappears, attempt stable‑identity correlation (name + `source_path` + `mcp_server_ref`); flag "component identity churn with definition change" as suspicious; consider a content‑addressed component key.

### NS‑09 — SARIF drops findings and won't dedupe in GitHub · **MEDIUM** · [reproduced]
**Where:** `generators/sarif.py`
- Results with no `source_path` emit **no `locations`** → GitHub code scanning drops or mis‑attributes them. Imported/model risks frequently lack a path, so **critical findings can silently vanish from the Security tab.**
- **No `partialFingerprints`** → alerts don't correlate across runs (duplicate/flapping alerts).
- **No `security-severity`** property on rules → GitHub can't rank severity.
**Fix:** Always emit a location (fallback `artifactLocation.uri` of the component ref or the repo root with a region), add stable `partialFingerprints` (e.g. hash of ruleId+bom_ref), and add `properties["security-severity"]` (numeric) + `help`/`fullDescription` per rule.

### NS‑10 — Projection fidelity + SPDX 3.0 conformance unverified + non‑determinism · **MEDIUM** · [partially reproduced]
**Where:** `generators/cyclonedx.py:126–180`, `generators/spdx.py`
- CycloneDX output **does validate** against real CycloneDX 1.5/1.6/1.7 (verified with `cyclonedx-python-lib`'s strict validator) — good. **But** the conformance test can't run in CI because `[dev,all]` omits `cyclonedx-python-lib[json-validation]` (jsonschema), so the test only ever *errors*. Conformance is unguarded.
- Both generators **lack an `isinstance` branch for 5 component types** (MCP client, A2A client/server, IDE agent, verified extension) → their agent‑specific fields are **silently dropped** from the projections; those types fall back to `"library"`/`software_Package`.
- SPDX 3.0 output is **unvalidated**; structurally, component elements lack per‑element `creationInfo` and relationship type casing is unverified against the SPDX 3.0 model.
- `uuid.uuid4()` doc/relationship IDs + `datetime.now()` timestamps make output **non‑reproducible**.
**Fix:** Add `cyclonedx-python-lib[json-validation]` to dev deps and make the strict validator a CI gate; generate CycloneDX via the library's model objects; cover all component types; validate SPDX against an SPDX‑3 tool and add per‑element creationInfo; make IDs/timestamps deterministic (see NS‑13).

### NS‑11 — Model scanner false‑negative: unknown/renamed formats are invisible · **MEDIUM** · [by inspection]
**Where:** `scanners/model.py:70–77` (`MODEL_EXTENSIONS`), `core/enums.py:SERIALIZATION_FORMAT_SAFETY`
Discovery is purely extension‑based. A pickle shipped as `model.dat`/`weights.bin2`/no‑extension is **not discovered at all** → no component, no risk (absence‑as‑safety). The most dangerous case (a disguised pickle) evades the scanner.
**Fix:** Content‑sniff magic bytes (pickle opcodes, ZIP/PK for torch, GGUF magic) regardless of extension; emit an `unknown-format` component with `serialization_safety=unknown` **flagged** (fail‑closed) for unrecognized large binaries in model dirs; record as partial coverage.

### NS‑12 — Dependency tree ships 12 known CVEs; `sigstore<4` blocks the fix · **MEDIUM** · [reproduced]
**Where:** `pyproject.toml`, CI
`pip-audit` reports 12 CVEs: `cryptography 46.0.7` (cert‑chain DoS, wildcard‑SAN bypass, PKCS7 oracle, OpenSSL), `sigstore 3.6.7` (OAuth CSRF — **fixed in 4.2.0, but `pyproject` caps `sigstore<4`**), `tuf 6.0.0`, `pytest 8.4.2`. CI has **no dependency audit**. Deps are version ranges with **no lockfile**.
**Fix:** Raise the `sigstore` cap to pull the fix; add `pip-audit`/OSV‑Scanner + Dependabot/Renovate to CI (gating); add a lockfile/constraints for reproducible installs; publish an SBOM of the tool itself (dogfood).

### NS‑13 — Native BOM output is non‑reproducible · **MEDIUM** · [reproduced]
**Where:** `core/aibom.py:87–96` (`finalize`)
`to_dict()` → `finalize()` stamps a fresh `timestamp` (and `tool_version`) on **every** serialization; two `to_json()` calls on the same object differ.
**Impact:** Breaks content‑addressable/reproducible BOMs and clean baseline diffing; complicates attestation.
**Fix:** `finalize()` once at creation; support `SOURCE_DATE_EPOCH`/`--deterministic` to fix timestamps and derive the serial number from content.

### NS‑14 — `rglob` discovery follows symlinks (DoS) on Python < 3.13 · **MEDIUM** · [by inspection]
**Where:** `scanners/model.py:73`, `scanners/rag.py:46,209`, `validators/completeness.py:169`
`Path.rglob` follows directory symlinks on Python ≤ 3.12 (the CI matrix includes 3.11/3.12), so a symlink cycle in a scanned repo can hang discovery. (Reads are still blocked by the `O_NOFOLLOW` readers — good — but discovery itself loops.)
**Fix:** Use `os.walk(followlinks=False)` or `rglob(..., recurse_symlinks=False)` (3.13) with a visited‑inode guard and a traversal budget; record truncation as partial coverage.

### NS‑16 — Malformed/hostile BOM input produces uncaught tracebacks · **MEDIUM** · [reproduced]
**Where:** `core/aibom.py:104–107` (`load`), `cli.py` (`validate`/`risk`/`summary` don't guard `load`)
`AIBOM.load` does `json.loads(path.read_text())` with **no size/shape guard** and `validate`/`risk`/`summary` don't catch load errors.
**Reproduced:** `validate` on a scalar JSON dumped a raw `pydantic_core.ValidationError` traceback; malformed JSON dumped a raw `json.JSONDecodeError`. (Exit code is 1 — good — but the UX is a stack trace, and deeply nested JSON risks an uncaught `RecursionError`.)
**Fix:** Bound the read (max bytes), catch `JSONDecodeError`/`ValidationError`/`RecursionError` and emit a clean `ClickException`; mirror the `diff` command's guarded load across all commands.

### NS‑18 — All CI jobs red on `main`; no security CI · **HIGH (process)** · [reproduced]
**Where:** `.github/workflows/ci.yml`, `action.yml`
lint + format + typecheck + one test are red on `main` (NS‑01/NS‑10/ruff). There is no SAST/CodeQL, no secret scan, no dependency audit (NS‑12), no release signing/provenance, and the Action example pins `@main` (mutable).
**Fix:** Make CI green and **required**; add CodeQL, `pip-audit`/OSV, `gitleaks`, and a `cyclonedx`/SPDX strict‑validation job; sign releases (Sigstore) and publish SLSA provenance; document pinning the Action by commit SHA.

### NS‑15 — `diff` surfaces only `critical` as alerts · **LOW**
**Where:** `diff/differ.py:300–324` — trust‑tier downgrade, signing regression, pin removal, serialization‑safety change (all `high`) are relegated to the modified list, not `security_alerts`. **Fix:** promote `high` to alerts; tie to NS‑03 gating.

### NS‑17 — Rich markup/ANSI injection via untrusted names in CLI output · **LOW**
**Where:** `cli.py` (`diff`/`risk` print component names/details into Rich f‑strings). A component named `[red]…[/]` is interpreted as markup. **Fix:** `rich.markup.escape(...)` all untrusted strings; strip control chars.

### NS‑19 — Dead/mismatched config & docs · **LOW**
Covered by NS‑06 (dead policy fields). Also: `README` still points installs at `nexus-symbiote.git` while the repo is `SymBiote`; `pyproject` author (`Emmanuel Dahunsi`) vs org `aisecnomad` — confirm intended attribution. **Fix:** reconcile names/URLs; CI link‑check.

### Refuted (verified *not* to be issues — reported for confidence)
- **Pydantic untagged‑union misclassification** — I suspected `AIBOM.load` would mis‑resolve component types (no discriminator, `component_type` not a `Literal`). **Probe showed correct resolution** (`tool`→`ToolComponent`, `model`→`ModelComponent`). Not a bug. *(Recommendation: still add a discriminated union with `Literal` component_type to make this guarantee explicit and fast.)*
- **`registry.py` pin parsing** — uses its own correct regexes (not the broken `extract_version_pin`), so NS‑05 does **not** affect the registry scanner's pip/npm checks.

---

## 4. What is genuinely strong (keep and build on)

These are verified strengths, several at a top‑0.1% level:

- **`utils/confined.py` + `scanners/base.py` file readers** — descriptor‑relative `O_NOFOLLOW` opens per path component, `..` rejection, `S_ISREG`+size `fstat` guard, before/after `mtime/ctime/size` TOCTOU check, fail‑closed on platforms lacking the primitives, bounded chunked reads (4 MB config / 1 GB model). **Probes confirmed** it blocks symlink‑to‑`/etc/passwd`, symlink‑to‑outside, and `../` traversal. This is excellent.
- **`core/hashing.py`** — RFC 8785 JCS via `rfc8785`; **probe confirmed** key‑order independence and `NaN`/`Infinity` rejection (`FloatDomainError`). Deterministic tool‑definition fingerprinting with an explicit `definition_hash_version`.
- **`core/evidence.py`** — the `EvidenceRecord`/`AuthorityClaim` state machine (`VERIFIED` *requires* digest+verifier+policy+time; "unknown must carry no permission + a reason") is exactly the claim‑vs‑proof rigor this domain needs. Best code in the repo — now wire it in (NS‑04).
- **Secret hygiene** — MCP scanner redacts `args`, `env`, and endpoints (`sanitized_origin`); logs to stderr, data to stdout.
- **Honest naming** — `"signature-present-unverified"`, `coverage_status` distinctions, `SECURITY.md`'s candor about digests/signatures/absence. The project does not over‑claim in prose.
- **`crypto.py`'s Sigstore verifier** — correct, offline, identity‑policy‑bound, fail‑closed. It just needs a caller.
- **Model risk taxonomy** — pickle/`.pt`/`.pth` → critical RCE; GGUF → CVE‑2024‑34359 SSTI; `trust_remote_code` → critical, with references.

---

## 5. Standards conformance status

| Format | Status | Notes |
|---|---|---|
| **CycloneDX 1.7** | **Valid** (verified vs 1.5/1.6/1.7 strict schema) | Hand‑rolled; conformance test unguarded in CI (NS‑10); agent fields dropped for 5 types |
| **SPDX 3.0.1** | **Unverified** | Per‑element `creationInfo` missing; relationship/type values unvalidated against the SPDX‑3 model |
| **SARIF 2.1.0** | **Ingestion‑broken** | Missing locations/fingerprints/security‑severity (NS‑09) |
| **Native AIBOM schema** | **Self‑inconsistent** | Output fails the project's own schema (NS‑07) |

---

## 6. Roadmap to a top‑0.1% agent‑SBOM product

The grading criterion for "world‑class" in this category is no longer *"can you list components"* — it is **cryptographic provenance, exploitability‑aware risk, agent‑native depth (MCP/A2A/tool‑level), and continuous verification**, all gate‑able in CI and conformant to the standards you claim. Prioritized:

### P0 — Earn trust / be functional (ship first)
1. **Repair the control layer** (NS‑01/02/03/06/07) and make CI green + required. *Effort S–M. Without this nothing else matters.*
2. **Wire real verification** (NS‑04): Sigstore/cosign signature verification against a configurable trusted‑identity policy; adopt the **OpenSSF model‑signing** format for model weights; set `assurance=verified` only on cryptographic proof. *Effort M. This is the product's reason to exist.*
3. **Sign and attest the BOM itself:** cosign/Sigstore‑sign emitted AIBOMs, publish an **in‑toto attestation** + **SLSA provenance** for them, and record to a transparency log (Rekor). *Effort M. Table stakes for a supply‑chain tool in 2026.*

### P1 — Differentiate as *agent‑native*
4. **VEX / exploitability** — emit **OpenVEX** (and consume CSAF VEX) so findings carry exploitability status + justified suppressions; this is what turns a noisy scanner into a gate teams trust. *Effort M.*
5. **Policy‑as‑code** — a real engine (OPA/Rego or CEL), policy loaded from a trusted source (NS‑06), with separated, machine‑readable gate outcomes (coverage vs risk vs policy). *Effort M.*
6. **Deep MCP/A2A trust** — go beyond config parsing: fetch & hash **live** MCP tool lists to catch runtime tool‑poisoning / rug‑pulls, verify A2A agent cards and declared scopes, and **wire `DeploymentProfile`/`AuthorityClaim`** (NS‑04) into scanners + a capability/authority diff. This is the whitespace competitors (Protect AI, Endor, Manifest) don't own. *Effort L.*
7. **Model & data provenance** — HF model‑card ingestion, safetensors verification, a **dataset‑BOM**, and proper mapping to **CycloneDX ML‑BOM `modelCard`** and the **SPDX 3.0 AI/Dataset profiles**. *Effort L.*
8. **Ecosystem integration** — OSV/OSV‑Scanner for dependency components, **Dependency‑Track** export, **GUAC** ingestion, and GitHub code scanning done right (NS‑09). *Effort M.*

### P2 — Scale / enterprise / standards leadership
9. **Continuous (not one‑shot) AIBOM** — baseline approval workflow, drift monitoring, rug‑pull alerting as a service; reproducible BOMs (NS‑13) as the correlation key. *Effort L–XL.*
10. **Conformance as a gate** — pass official CycloneDX + SPDX‑3 validators in CI and publish the conformance matrix; this is a credibility moat. *Effort M.*
11. **Enterprise surface** — API + dashboard, RBAC/multi‑tenant, signing‑key management, framework policy packs (LangGraph/CrewAI/…), SIEM/ticketing integrations. *Effort XL.*
12. **Standards leadership** — contribute the agent‑native component taxonomy (MCP server/client, A2A, tool‑definition fingerprinting) to the **CycloneDX AI WG / SPDX AI** efforts and publish the AgentBOM spec. Owning the standard is how a tool becomes *the* tool. *Effort L.*

---

## 7. Suggested remediation order (fastest trust recovery)

1. **Day 1 (one‑liners, unblock CI):** NS‑01 (`symbiote.`→`nexus_symbiote.`), ruff fixes, `cyclonedx[json-validation]` dev dep, raise `sigstore` cap (NS‑12). → CI green.
2. **Week 1 (make gates real):** NS‑02 (coverage/gate semantics), NS‑03 (`diff --fail-on`), NS‑05 (pin parser + tests), NS‑07 (schema from models + validate in CI), NS‑06 (trusted policy source).
3. **Week 2 (close verification gap):** NS‑04 (wire Sigstore + evidence model), NS‑09 (SARIF), NS‑11 (content‑sniffing), NS‑16 (clean errors), NS‑13 (deterministic output).
4. **Then:** P0.3 → P1 roadmap.

*Prepared from a first‑hand review with empirical reproduction of all High‑severity findings. Reconciliation with the parallel audit workflow's independent verdicts and standards/competitive citations to follow.*
