# Phase-1 adversarial review — findings and status (session ihvm)

Reviewer: session `…ihvm` (final-review gatekeeper for the foundation→main reconciliation).
Baseline reviewed: `claude/symbiote-foundation` @ `3d636bb`; this report also notes which
findings foundation commits up to `71a167e` (#34/#36/#37/#42) have already superseded.
Method: 6-dimension finder workflow; the invariants and exporter dimensions **reproduced
every finding empirically** (probe scripts executing the installed package). The dedicated
verifier pass was rate-limited (account 5-hour window); findings below are marked
*finder-reproduced* (ran code demonstrating the failure) or *static* (code-read only).
Fix state reflects branch `claude/review-fixes-ihvm` (all gates green: pytest, mypy
--strict on touched files, ruff check+format).

## Severity-ranked findings

### CRITICAL

1. **Zero-nonce redaction break** — `scan.py` seals documents with a zero salt nonce;
   recomputing a withheld leaf's hash from guessable content recovers redacted bodies
   (reproduced: recomputed leaf hash matched the withheld leaf). *Finder-reproduced.*
   **Owner: lead.** Fix: fresh random nonce per snapshot, refuse zero nonce in commit path.
2. **k8s-aibom importer minted `assurance=verified` from attacker-controlled property
   strings** (I3 signature laundering; reproduced via direct import). *Finder-reproduced.*
   **FIXED upstream in #34** (verified → supplier declaration) — confirmed on `71a167e`;
   my branch adds colon-dialect and oversized-inline regressions on top.
3. **`_RegexIdentity` prefix-match on `^`-anchored patterns** — `sigstore_backend.py:76`:
   a `^`-prefixed identity pattern is not end-anchored, so SAN
   `build@example.com.evil.net` verifies against policy `re:^build@example\.com`
   (I3). *Finder-reproduced.* **Owner: lead/WP-attest.** Fix: `re.fullmatch` always.

### HIGH

4. **Pickle-in-zip risk bypass** — `models_identity/serialization.py:847`: keras-v3/npz
   sniff rules outrank the embedded-`.pkl` rule; a zip holding `archive/data.pkl`
   (os.system) classifies `risk=low/none`, pickles never scanned, SYM-MODEL-002 never
   fires. *Finder-reproduced.* **Owner: WP3.**
5. **Text-suffix skip** — `models_identity/hf.py:209`: files with `.txt/.json/.model`
   etc. suffixes are never magic-sniffed; a pickle stream in `vocab.txt` yields
   `risk_class=none`. *Finder-reproduced.* **Owner: WP3.**
6. **Hidden-unicode scan only covers description/title** — `digest/textflags.py:82`:
   bidi/tag code points in enum values, defaults, examples, property names produce no
   flag; SYM-TOOL-006 never fires. *Finder-reproduced.* **Owner: WP2.**
7. **Collector-crash coverage laundering** — `collect/base.py:400`: a crashed collector
   records NOT_ATTEMPTED, which `merge_surface` excludes, so a failed live query reads
   `queried` and `conformance --level verified` can still pass (I2).
   *Finder-reproduced (merge_surface executed).* **Owner: lead/WP1.** Note: #34 reworked
   parts of collect/base — re-verify against `71a167e` before closing.
8. **Declared-stub-wins merge** — `scan.py:201`: same-id entities merge
   first-collector-wins (alphabetical), so mcp-config's declared stubs beat mcp-live's
   served definitions; rug-pull detection (SYM-TOOL-002) silently disabled. *Static.*
   **Owner: lead.** #34 touched this area (declaration correlation) — re-verify.
9. **SYM-TOOL-002 silent passes** — `policy/checks/tools.py:93`: no baseline → no
   finding (never indeterminate); empty served set skips the missing-approved branch,
   so a total-removal rug pull reports nothing. *Static.* **Owner: WP11.**
10. **Deployment entities silently dropped by both exporters** — `export/cdx/emit.py:391`
    (+ spdx): no `agentbom:deployment:*` properties, no LossItem, `lossless=True` while
    workload identity is discarded. *Finder-reproduced (schema-validated exports).*
    **Owner: WP13.**

### MEDIUM

11. **Duplicate-key safetensors header** — `digest/tensormanifest.py:46`: plain
    `json.loads` (last-wins) instead of the duplicate-rejecting parser; manifest attests
    different bytes than a first-occurrence loader sees (I5). *Finder-reproduced.*
12. **Duplicate tool names digest order-dependently** — `digest/tooldef.py:56`:
    `toolset_digest` accepts same-name entries; digest depends on page arrival order
    (violates §3.3 pagination invariance); shadowing signal unflagged. *Finder-reproduced.*
13. **No `--strict` anywhere** — `cli/app.py:357`: exit codes 8 (security-relevant loss)
    and strict-mode 7 are unreachable. *Static.* **Owner: WP14.**
14. **SYM-MCP-003 plaintext+unknown-boundary silent pass** — `policy/checks/servers.py:114`
    (and the Rego export bakes in the same divergence, so parity can't catch it). *Static.*
15. **Producer record hard-codes `mode=DECLARED`** — `scan.py:224`: observed-mode
    collectors misrepresented as declared in provenance (I3 direction). *Static.*
16. **ShadowScan importer trusted `model_providers` shape / inverted autonomy interval**
    — `imp/shadowscan.py`. *Finder-reproduced.* **FIXED on `claude/review-fixes-ihvm`.**
17. **Taxonomy drift** — `export/cdx/emit.py:699`: emitted property names
    (`agentbom:skill:interpreter`, `:unknown-reason` suffixes, …) absent from
    taxonomy.md's closed vocabulary; the spec'd taxonomy check is unimplemented. *Static.*

### Fixed on `claude/review-fixes-ihvm` (this branch; each with a regression test)

- flock-based ChainStore locking (stale-steal fork eliminated); redacted-view re-seal
  refused; diff treats unknown trust boundary/tier as worst-case HIGH; otel timestamp
  clamp + per-file fault isolation; k8s-aibom inline-size bound (on top of #34);
  shadowscan importer input validation. (mcp_live bounds and registry exact-matching
  were superseded by #34's stronger versions — adopted theirs, kept my adversarial
  regression tests.)

### Invariants-dimension scope notes (unfixed, lower priority)

- Stripping a redaction record from a document still passes `verify_document`
  (silent-redaction detection gap).
- Redacted leaves disclose entity `id` strings (spec §3.8 says `{kind, leaf_hash}` only).
- `sorted()` in snapshot body misses derived flags/findings → I7 byte-determinism risk.
- Salt nonce reuse across serials enables cross-snapshot salt linkage.
- `build_policy` AnyOf vs attestation.md §3 AllOf divergence; `sign_keyless` signs
  non-JCS bytes when non-ASCII present (two signing paths, two byte streams).
- CDX/SPDX importers listed in companion.md §6 don't exist; `LossReport.retained_ratio`
  missing; formulation `taskTypes=['scan']` vs mapping's `['other']`.

## Merge gates (restated)

1. Phase-1 findings triaged: criticals fixed or explicitly waived by the owner.
2. Phase-2 delta review of the reconciliation PR comes back clean.
3. CI green on the PR head.
Merge mechanics: merge commit (not squash), per the standing instruction.
