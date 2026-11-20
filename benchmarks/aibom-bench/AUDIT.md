# Audit of AIBOM-Bench 1.0: second adversarial pass

This supersedes [CRITIQUE.md](CRITIQUE.md). The first critique found
problems and then fixed the arithmetic by hand, which is the same failure
mode it was criticizing. This pass does four things the first did not:

1. Puts every criterion score in `grades.json` and computes totals with
   `grade.py`, so the numbers can be re-derived by anyone.
2. Adds `--strict` matching to `score.py`: coverage and log keys
   (`surfaces_scanned`, `files_scanned`, `scan_failures`, `issues`, and so
   on) are stripped from JSON outputs before a component can be credited, so
   a tool is not rewarded for listing what it looked at.
3. Builds a second corpus (`build_corpus_b.py`, `ground_truth_b.json`) whose
   file shapes come from the standards and from the competitors' READMEs,
   not from the host tool's documentation, and reruns all seven runnable
   tools on it with no reviewer overrides.
4. Re-grades with D1 as the mean of the two corpora.

## Findings against the first two reports, by severity

**High. Hand arithmetic was wrong.** Recomputing from the recorded criterion
scores gives Nexus SymBiote 76.7 on corpus A, not 79.7 or 75.9; k8s-aibom
59.0, not 65.4 (the first report ignored the rule that documentation-only
criteria score at most 2); cdxgen 25.5, not 27.3 or 23.6. The grades did not
change, but three of ten totals were misreported twice.

**High. The ranking on corpus A was partly an artifact of corpus A.** On
corpus B, Nexus SymBiote's weighted recall falls from 0.555 to 0.357 and it
drops from second to third on coverage behind agent-bom (0.575) and Cisco's
Tier-1 scanners (0.445) (figures after the 18 November correction below;
the first edition printed 0.344, 0.548 and 0.435). The causes are concrete and all on the host tool:
no support for the Zed, Cline or Continue MCP configurations, none for
Kubernetes manifests, Dockerfiles, Terraform, notebooks, n8n workflows or
OpenAI Assistants exports, and the same zero on hosted model references.
Corpus A contained the client configurations its documentation lists; corpus
B did not. Section 1 of CRITIQUE.md predicted this and under-stated it.

**High. A new gate failure for Cisco.** On corpus B the Tier-1 scanner
copied the Supabase access token, which the corpus passes as a launch
argument (`--access-token <value>`), into its candidate output verbatim.
That is gate G1. The shipped CLI post-processes candidates through an LLM
and may redact; this benchmark could not run it. The provisional grade is
now capped at C and the total falls to 37.0 regardless.

**Medium. Strict matching changed nothing.** Stripping coverage keys did not
reduce any tool's recall on corpus A, which means the first report's
detections were not propped up by "files scanned" lists. Removing the five
reviewer overrides changed only ai-agentbom (+0.014) and Trusera (+0.041,
both incidental matches the overrides had rejected). The overrides were
small and in the direction of strictness.

**Medium. Two decoys were unfair and are downgraded.** `vendor/pkg/.cursor/
mcp.json` was planted as a hard decoy; five of seven tools reported it, and
`vendor/` is not a path any standard ignores, so it is now soft (0.25). The
zero-byte `.bin` decoy added in the first critique stays, because a
code-executing-format finding with critical severity needs evidence of a
pickle header, not a suffix.

**Medium. One ground-truth token punished a correct detection.** Nexus
SymBiote found the corpus B TypeScript MCP server but names it by the
variable `server`, not by the `name: "analytics-mcp"` field. The token now
also accepts the source location. Other tools' naming conventions were not
re-examined one by one; a third party should.

**Low. cdxgen emits the raw U+202E file name in its JSON.** Criterion 6.5
lowered from 3 to 2. The strace on corpus B also shows it probing `cargo` and
`rustc` for a project with no Rust in it.

**Low. Determinism held.** Nexus SymBiote, agent-bom and ai-agentbom were
byte-identical on corpus B as on A; Trusera, Cisco and cdxgen were not.

## Final grades (mechanical, both corpora)

| # | Tool | Total | Grade | D1 A | D1 B | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Nexus SymBiote | 73.0 | **B** | 1.75 | 0.75 | coverage halves on the independent corpus; safety, provenance, standards and determinism unchanged |
| 2 | k8s-aibom | 59.0 | C (provisional) | N | N | runtime observer, graded from source |
| 3 | agent-bom | 55.6 | C (capped, G3) | 1.5 | 1.5 | best coverage on both corpora; out-of-root hash and console escape stand |
| 4 | Cisco AI BOM (Tier-1) | 37.0 | F (provisional, G1) | 1.5 | 0.75 | token copied from a launch argument; nondeterministic |
| 5 | Trusera ai-bom | 29.1 | F | 1.0 | 0.0 | invalid CycloneDX, nondeterministic |
| 6 | ai-agentbom | 28.1 | F | 0.0 | 0.25 | one of six corpus B servers found after the correction below; 28.14 unrounded |
| 7 | ai-finder | 28.1 | F (G4) | 1.0 | 0.0 | telemetry by default; models never extracted; 28.05 unrounded |
| 8 | cdxgen | 23.3 | F | 0.5 | 0.0 | `-t mcp` found 3 of 7 servers on B; package-manager execution stands |
| 9 | OWASP Generator | 22.7 | F (provisional) | N | N | |
| 10 | Syft | 22.2 | F (not run) | 0.0 | 0.0 | |

`python grade.py` reproduces this table from `grades.json`.

## What the auditor still cannot vouch for

- The author of corpus B is the author of corpus A and of the host tool's
  benchmark harness. Corpus B avoided the host tool's docs; it did not avoid
  the author's priors. The next corpus should be written by someone else.
- Three tools were never run. Their D/A labels are capped at 2 by the
  grader, which is why k8s-aibom lost 6.4 points between the first report
  and this one; the cap is the rule, not a judgment about the tool.
- Cisco's grade is the least trustworthy number here in both directions:
  Tier-1 alone under-reports what the product does, and the LLM stage could
  either redact the leaked token or be steered by the injection text the
  corpora plant for it.
- The vendored-decoy downgrade and the server-name token fix were made by
  the same person who was wrong the first time. Both are recorded as
  separate commits so a reviewer can revert either.
- A benchmark with two synthetic corpora and one author is evidence, not
  a verdict. The spec, corpus generators, runner and grader are the
  deliverable; the ranking is what they currently say.

## Corrections after publication

**2026-11-19, scratch paths and e-mail addresses removed from the raw outputs.**
The files under `results/` are the tools' outputs as they were written, so 204 of
them held the run's working directory, a scratch path carrying the session id,
as the project root the tools were pointed at.
`results/alt/cdxgen-trace/network-python/bom.json` also carried the e-mail
addresses that npm package metadata publishes for package maintainers. On the
maintainer's decision (D9 on the merge ledger, issue 200) that file is removed,
which leaves 689 files. In the others, every form of the path is rewritten to
`/aibom-run`: whole, without its `/tmp/` prefix, folded into a dash-separated
serial number, wrapped across lines by a console, or cut short by a table. The
cisco-aibom command lines name the benchmark directory as
`benchmarks/aibom-bench/`. No other file in `results/` holds an e-mail address;
cdxgen's outputs still name credential variables from the corpus, which are
names only and whose values are fixtures.
The vendored `schemas/jsf-0.82.schema.json` also lost the e-mail address in its
`$comment`; the author credit and licence stay, and `SOURCES.json` records the
upstream digest beside the modified copy's.

The rewrite maps distinct paths to distinct paths, so the determinism and
network-against-airgap comparisons are unaffected. `scores.json` records each
output's size in bytes and the first schema errors cut at 200 characters, so
those were re-measured with `score.py` on the rewritten files: 68 sizes (30 on
corpus A, 33 on corpus B, 5 in `alt/`) and six error messages, which now fit
whole. Every other value in the three `scores.json` files is unchanged, and so
is `grades.json`. `score.py` was not used to rewrite the files wholesale,
because the published scores hold strace summaries from logs that were not
committed. A fresh run on corpus A now reproduces `results/scores.json` except
for those summaries. On corpus B, a fresh run drops the F08 finding hints that
`results/corpus-b/scores.json` still lists; F08's only location was the Cline
item removed on 2026-11-18. In `alt/`, a fresh run adds the zero-bin decoy that
the alternative runs were scored without, which lowers agent-bom-alt's and
nexus-alt's D1 score by 0.25 each. Neither difference reaches `grades.json`.

`results/scores-strict.json`, the `--strict` run of `score.py`, was
byte-identical to `scores.json` (strict mode drops stderr and coverage blocks
from the leak search, which found nothing either way) and is removed. The
CycloneDX, SARIF and SPDX schemas `score.py` validates against are vendored
under `schemas/` with their licences, and `SOURCES.json` records each copy's
source and digest, so scoring runs offline with the bytes the published scores
were validated with.

**2026-11-18, corpus B item `mcp.cline-time` removed.** The item's source file,
`.cline/mcp_settings.json`, was a file name the corpus author chose. Cline's
documentation places MCP servers only in its global
`cline_mcp_settings.json` (under the CLI data directory or the editor's global
storage) and describes the project-level `.cline/` directory as holding rules,
skills and hooks, so no client reads that file in a project. Nexus SymBiote
already reads `.cline/mcp.json` at the root and `cline_mcp_settings.json` at
any depth, which is why the item looked like a host-tool miss. No tool had
detected the item, so removing it raises every tool's `mcp-server` recall by
the same denominator change and the ranking is unchanged. The expected finding
F08, whose only location was that file, was removed with it, and the `.cline`
entries were dropped from F03 and F07. The corpus file stays in
`build_corpus_b.py` and is not scored. `ground_truth_b.json` records the
correction in its notes; `results/corpus-b/scores.json` holds the re-scored
D1 blocks (the other dimensions were not re-scored, since the strace logs they
need are not committed) and `grades.json` the resulting D1 B values.

| Tool | Weighted recall before | After | D1 B before | After |
| --- | --- | --- | --- | --- |
| Nexus SymBiote | 0.344 | 0.357 | 0.75 | 0.75 |
| agent-bom | 0.568 | 0.575 | 1.5 | 1.5 |
| Cisco AI BOM (Tier-1) | 0.435 | 0.445 | 0.75 | 0.75 |
| ai-agentbom | 0.247 | 0.254 | 0.0 | 0.25 |
| cdxgen (`-t mcp`) | 0.237 | 0.247 | 0.0 | 0.0 |
| Trusera ai-bom | 0.236 | 0.239 | 0.0 | 0.0 |
| ai-finder | 0.184 | 0.197 | 0.0 | 0.0 |

Only ai-agentbom's total moves, from 27.2 to 28.1 (D1 is the mean of the
two corpora). The sentence under "High. The ranking on corpus A was partly an
artifact of corpus A" now carries the corrected figures.

**2026-11-18, `decoy.zero-bin-as-model` pattern narrowed.** The soft decoy
asserts that a 32 MiB file of zeros is not reported as a code-executing model
format. Its pattern counted any `serializ` or `pickle` within 200 characters of
`embeddings.bin`, which an acceptance run of the open pull requests on the
ledger showed also matches a tool that reports the file's format or loader
safety as *not established*: Nexus SymBiote at #254 reports the high
`serialization_format_unknown` finding with the evidence `Named pickle-family
format; no pickle evidence in the inspected prefix`, and in strict mode the
`serialization_format` field name sits within the window as well. The pattern
now counts a code-execution, unsafe-loader or pickle claim or the
`serialization_format` finding category, and not the words pickle-family, "no
pickle evidence", the field name or `serialization_format_unknown`.
`score.py` re-run on the committed results with the old and the new pattern,
in normal and in `--strict` mode, gives byte-identical scores, so nothing
published moves; the same scorer on #254's native output on corpus A reports
the decoy with the old pattern (strict mode) and not with the new one.

**2026-11-19, the ranking of rows 6 and 7, and three credits by another record type.** The
table ordered ai-finder above ai-agentbom at 28.1 each; `grade.py`'s unrounded totals are 28.05
and 28.14, so ai-agentbom is sixth and ai-finder seventh, as `python grade.py` prints them. The
three-tree comparison on the ledger also noted that three of SymBiote's credits follow this
tree's own labels but come from a record of another type: `rag.qdrant` on corpus A from the
container image `qdrant/qdrant:v1.12.1` (the label lists `docker-compose.yml` as a source),
`rag.weaviate` on corpus B from the npm package `weaviate-client` (the label lists
`package.json`), and the soft item `prompt.relocated-claude-md` from the scan-failure line
that names the case variant. Nothing was scored against the labels, and the labels are not
changed here, since every tool was matched by the same rule; but by records of the item's own
type SymBiote's totals are 36 of 76 and 16 of 53 and its vector-store row is 2 of 3 and 0 of 2.
`ROADMAP.md` carries that qualifier on the vector-store row, and the `rag` collector's floor is
set from the own-type counts. A label that requires the item's own record type is a corpus
change for the next benchmark version, not a correction of this one.
