# Three benchmark trees named AIBOM-Bench: a comparison

Three branches of this repository each hold a benchmark called AIBOM-Bench at
`benchmarks/aibom-bench/`, written on 18 November 2026 by three authors who did not see each
other's work. This is a comparison of the three by a reviewing agent that wrote none of
them, asked to assume none is better. It was produced in the session that wrote tree B,
and it sits in tree B's directory only because that is the branch its session can push to.
A second agent then re-derived its numbers; what that changed is in the next section, and
the two statements it corrected are marked where they stand.

## Summary

All three trees sit at benchmarks/aibom-bench and every pair conflicts on README.md and SPEC.md (plus score.py for A+C and docs/README.md for B+C), so no second branch can land as it stands; each merges cleanly with main alone. All three graded Nexus SymBiote 0.2.0 at a13b622-equal source (73.0 B, 67.9 C, 65.3 C) and agree on its main gaps (model references in code, datasets, framework-defined agents, poisoned tool descriptions, literal credentials not raised) and on its safe behaviour; I reproduced its detections in all three from regenerated corpora, and the points where they disagree trace to matching rules or corpus layout, not to tool mode or commit. The counts the owner's draft attributes to 'AIBOM-Bench v1.1' cannot be derived from tree B (the tree named 1.1.0) either, the trees rank the other tools differently, and none of them is the pre-registered third-party round that main's roadmap row L4 asks for.

## Second check (19 November)

A second agent re-derived the numbers below from its own scans and counts, without the
first one's working files. Every count, score, rank and path statement it could run held,
apart from the two corrections in items 2 and 3. Item 1 was then checked a third time
against tree A's committed outputs and labels, which narrowed it: the credits follow tree
A's own rule.

1. **In tree A, three of SymBiote's credits come from a record of another type.** Tree A's
   labels allow it: `rag.qdrant` lists `docker-compose.yml` as a source and `rag.weaviate`
   lists `package.json`, each matched by the product name, and the relocated `claude.md` is
   credited for "detection or an explicit evasion finding". What SymBiote's output holds
   is the container image `qdrant/qdrant:v1.12.1` (credited again as `img.qdrant`), the npm
   package `weaviate-client`, and a scan-failure line that says the relocated file "is not
   inventoried". It holds no retrieval-store record for Qdrant or Weaviate and no prompt
   record for that file. Counted by records of the item's own type, SymBiote identifies 36
   of 76 and 16 of 53 components, and vector stores are 2 of 3 and 0 of 2, where T2 and T3
   row 16 give tree A's stored 3 of 3 and 1 of 2. This matters where a class count becomes
   a floor for one collector: the roadmap on tree A's branch assigns the vector-store row
   to SymBiote's `rag` collector.
2. **Correction to T4.** On tree A's corpus B, 0.247 is the `cdxgen -t mcp` entry. Plain
   cdxgen is 0.200, which is below Trusera's 0.239, not above it.
3. **Correction to T6.** A search over every grouping of tree B's 20 kinds finds 86 that
   give 9 items with 1 found, not one. Datasets with vector stores is the only one inside
   the data pillar. The conclusion stands: no grouping that includes models has 16 items,
   and no kind named agent gives 0 of 2.
4. **Ranks move with the weights inside one tree.** Tree B's own sensitivity table
   (results/2026-11-18/RESULTS.md:84-96) puts SymBiote first under equal weight per group
   and fourth on inventory alone. T4 gives one rank per tree.
5. **The causes in T3 rows 13 to 15 were tested directly.** With tree B's compose file,
   npm manifest and one prompt file copied to the places SymBiote reads, it recorded three
   images, both npm SDKs and the prompt: 68 components became 76.
6. **One more decoy.** On tree A's corpus B, SymBiote reports the vendored configuration
   `vendor/pkg/.cursor/mcp.json` as an MCP server. It does not report the `node_modules`
   decoys of tree A's corpus A or of tree B.
7. **The relocated layout was built.** With each tree under its own directory name there is
   one conflict (`docs/README.md`). Eight links from tree A's roadmap, plan and
   `benchmarks/README.md` then break and take 14 changed lines, tree B's test takes one,
   and the hygiene check, ruff and 52 tests pass. The cost was also measured: tracked paths
   go from 598 to 1,386 and the source distribution from 2.78 MB to 4.19 MB unless
   `pyproject.toml` excludes the benchmark directories. Of the 785 added benchmark files,
   691 are tree A's raw tool outputs.

**What this changes in the recommendation.** Point 5 called the rename the step that
"commits to nothing". It is not needed when one tree lands and the other two stay as
branches or tags cited by commit, and it is not free when all three land. The order is
therefore:

- Decide what the benchmark is for first (point 2).
- If it is regression evidence and a gap list, with no ranking before main's L4 round, land
  at most one harness and cite the other two by commit. Three siblings in `main` would put
  three rankings that contradict each other there and postpone the choice of one detection
  rule, which item 1 shows matters.
- Only if all three are wanted in `main`, use the relocated layout of item 7, with a
  source-distribution exclusion and no ranking table in the index.

Facts for choosing one, which is the maintainer's choice because this comparison comes from
the session that wrote tree B:

| Tree | For | Against |
|---|---|---|
| A | The only one a third party can rescore from committed raw outputs; its branch's roadmap cites it | A class count can rest on records of another type (item 1); it does not measure the pair |
| B | The only one wired into the test suite; measures ShadowScan and the pair | Ten of its 100 points are assessed, and raters judge its risk and drift verdicts; it commits no raw tool outputs |
| C | Every point is computed; seeded, with a positive control | No test in the suite; its branch carries 19 paths outside the benchmark |

The other points of the recommendation stand.

Conventions. Tree A = origin/claude/laughing-hawking-5f9x78 at 326cfc51; tree B = origin/claude/modest-gauss-ymoyc9 at 30abed25; tree C = origin/claude/nice-archimedes-368l54 at 071ed932. Paths without a prefix are relative to benchmarks/aibom-bench/ in the named tree. "(ran)" marks what I ran today; everything else is read from the tree unless marked "(inferred)".

## T1. The three trees side by side

| Aspect | Tree A | Tree B | Tree C |
|---|---|---|---|
| Calls itself | AIBOM-Bench 1.0 (SPEC.md:1); ground truths "1.0" and "1.0-b" | AIBOM-Bench 1.1.0 (SPEC.md:3), successor of its own 1.0 | AIBOM-Bench 1.0 / 1.0.0 (SPEC.md:1) |
| Size | 709 files, 12 MB; 691 under results/ | 63 files, 1.6 MB | 12 files, 0.8 MB |
| What else the branch changes | ROADMAP.md rewritten, docs/enhancement-plan-2026-11-18.md added, benchmarks/README.md, docs/README.md; no tests; source now equals main | docs/README.md (one row), tests/test_aibom_bench.py (9 tests); source equals a13b622; 32 commits behind main | 19 paths outside the benchmark, including 4 source files, action.yml and 5 test files; no test of the benchmark |
| How the corpus is built | Two fixed, hand-written projects held as Python dictionaries in build_corpus.py and build_corpus_b.py; generated on demand, not committed; no seed; SHA-256 manifests committed | One project generated by `bench.py build` from aibom_bench/corpus.py; not committed; no seed; deterministic for a fixed canary directory (/tmp/aibom-bench/canary); digest pinned in README.md:48 | Generated by generate.py from a seed (default 20261118); not committed; nearly every matched identifier is a random token from the seed; 15 scenarios, each scanned as its own root |
| Corpus size (ran) | Corpus A: 67 manifest files, one 32 MiB sparse file, 4 symlinks, a 40-level directory. Corpus B: 39 files, 3 symlinks | Base: 89 files plus 3 out-of-tree files; 13 variants (base, repeat, drift, 8 hostile overlays, 2 probes) | 86 files, 2 symlinks and an outside directory; 4.2 MB, including a 3 GiB decompression bomb stored in about 3 MB |
| Labelled components | Corpus A: 76 in 15 classes: mcp-server 10, tool 3, skill 2, prompt 14, model 13, model-file 6, dataset 6, training 2, vector-store 3, a2a 1, agent-config 3, ci-agent 1, container 4, package 6, guardrail 2 (13 marked soft). Corpus B: 53 in 13 classes: mcp-server 6, tool 3, prompt 7, model 12, model-file 5, dataset 4, training 2, vector-store 2, agent-config 2, ci-agent 1, container 3, package 5, guardrail 1 (13 soft) | 92 in 5 pillars: models 18, data 11, tools 18, agent components 37, infrastructure 8. By kind: model 18; dataset 7, knowledge_source 2, vector_store 2; framework 10, tool 8; mcp_server 14, agent 6, skill 4, instructions 4, prompt 3, subagent 1, command 1, hook 1, permission 1, plugin 1, guardrail 1; container 5, endpoint 2, ci_agent 1 | 126 scored items in 9 domains. 68 inventory components: models 17, skills 14, mcp 13, agents 8, tooldefs 6, data 5, packages 5; plus 13 safety sentinels (4 without points) |
| Other labels | Corpus A: 6 decoys, 9 secret sentinels, 4 digests, 5 pins, 15 expected findings. Corpus B: 4 decoys, 7 secrets, 4 pins, 7 expected findings | 197 facts, 7 relationships, 8 decoys, 20 planted risks (19 offline), 6 clean controls, 10 planted changes, 7 execution canaries, 9 leak tokens, 8 hostile cases | 18 finding items, 9 negative items, 2 drift items, 9 safety probes, 7 standards items |
| Tools and versions graded | 10 (REPORT.md:28-39). Run: Nexus SymBiote 0.2.0 (a13b622), agent-bom 0.115.4, Cisco AI BOM 1.10.1 (Tier-1 scanners only), Trusera ai-bom 3.6.0, scanoss ai-finder 0.5.0, ai-agentbom 0.8.0, cdxgen 12.9.2. Graded from source or documentation without a run: k8s-aibom 7be6465, Syft 1a72047, OWASP AIBOM Generator 1.0.2 | 11 graded, 1 not gradable (tools/*.json): ShadowScan + SymBiote, Nexus SymBiote 0.2.0 (this checkout), agent-bom 0.115.4, cdxgen 13.8.0, Cisco AI BOM 1.10.1 (floor), AIROM 0.4.7, Nexus ShadowScan 0.1.4 (2b80f19), Trusera ai-bom 3.6.0, Syft 1.57.2, AIsbom 1.7.0, Snyk Agent Scan 0.6.11 (floor); OWASP AIBOM Generator 45851cb not graded | 12 ranked rows, 1 not run (tools.json): SymBiote + ShadowScan, Nexus SymBiote 0.2.0 (a13b622), Nexus-ShadowScan 0.1.4 (2b80f19), agent-bom 0.115.4, Cisco AI BOM 1.10.1, AIROM 0.4.7, cdxgen 12.9.2, Trusera ai-bom 3.6.0, aibom-scanner 1.3.5, AIsbom 1.7.0, Syft 1.57.2, AIBoMGen CLI 0.3.0; OWASP AIBOM Generator not run; plus a positive control and four synthetic tools |
| How each tool is run | run_tools.sh: fresh corpus per tool and mode at one path; isolated HOME; SOURCE_DATE_EPOCH=1700000000; 900 s. Mode network: host network under strace (connect, execve, openat, readlink). Other modes: `unshare -rn`, no interfaces. airgap and repeat form the determinism pair. Runs as the invoking user. SymBiote: `scan CORPUS` in four formats, no policy flag. Competitors get extra best-of invocations (results/alt) | runner.py, as root: `unshare -n` with loopback up; empty environment; fresh empty HOME per variant; working directory outside the project; 300 s (180 s hostile). strace of connect on repeat and on the default-egress probe; the default-exec probe runs each tool's plain command on a four-file project with the host network. SymBiote: `scan --no-project-policy` in four formats plus `risk --json-output` | run.py, as root on a disposable machine: network, PID and mount namespaces, loopback only, private /tmp; strace of connect and execve; setpriv to an unprivileged user; env -i with fresh HOME and TMPDIR and CI=true; a fresh writable copy of the scenario per command; 300 s; peak RSS from wait4. The plain invocation also runs on every scenario. SymBiote: `scan --no-project-policy --report-only` in four formats |
| Dimensions and weights | 9 dimensions: coverage 30, identity and pinning 12, provenance and evidence 10, standards 12, risk and policy 10, security of the tool 12, determinism 6, runtime correspondence 4, operability 4. Criteria scored 0 to 4 against anchors, most by a reviewer. Grades A+ 90, A 80, B 70, C 55, D 40, F. Four hard gates cap the grade at C | 8 groups, 35 criteria: discovery 30, precision 4, record fidelity 14, standards 10, BOM integrity 10, risk analysis 12, change detection 8, scanner safety 12. 90 points measured (13 of them through raters), 10 assessed. Grades A 85, B 70, C 55, D 40, E 25, F | 9 domains: mcp 16, tooldefs 10, skills 12, agents 8, models 16, data 8, packages 4, standards 12, safety 14. All computed by score.py. Grades A 85, B 70, C 55, D 40, F. Gates cap at F (execution), D (credential in output), C (symlink escape). Also an in-scope score |
| Detection rule and partial credit | A component counts when a substring or regex occurs anywhere in the concatenated outputs of all modes (score.py:113-120, :352-353). Soft items weigh 0.5. Class recalls are weighted, mapped to an anchor (0.85, 0.65, 0.45, 0.25) and reduced by 0.5 per hard and 0.25 per soft decoy; the final coverage score is the mean of the two corpora. Five reviewer overrides on corpus A, none on B; --strict strips coverage and log keys first. A criterion known only from documentation or assumed scores at most 2; label N removes a dimension | One generic extractor. A component counts only when one record holds a key or weak key and the record's own type fits the kind (scoring.py:126-181); a mention earns nothing; catch-all types and listings are rejected. Exposure rule: decoys, controls, canaries, secrets, escapes and hostile cases count only if the tool found a real component in the same file; an unfaced check earns nothing. Partial credit: invalid schema 0.5; determinism 0.6 after dropping time and id fields; assessed criteria known only from documentation half | Generic readers, no per-tool adapters. A component counts when a record holds the seeded token in a short single-line value and states the kind in another field; a path never supplies the kind (SPEC.md:98-106). Points are the item weight plus attribute checks found in one record. Negative items subtract their weight. A safety item earns points only if a benign sentinel in the same scenario was inventoried |
| How risk findings are judged | 15 expected findings (7 on corpus B). score.py records which hint words occur; the reviewer awards full or half marks (REPORT.md:304-320); anchors at 11, 8, 5, 2 findings plus one bonus point for policy gate, drift gate and crosswalk | 19 offline planted risks and 6 clean controls, judged by two raters from packets with tool names masked; the author does not rate; a third rater decides disputes | 18 finding items worth 36 item points: the finding must hold the token, a case keyword at a word boundary in its own message, and a severity above informational; findings naming more than three components earn nothing; 5 negative findings penalise wrong claims |
| How drift is judged | No drift case is run; credit comes from criterion 2.2 (canonical identity hash, read in code) and the risk bonus | 10 planted changes: 7.1 compares records between base and drift; 7.2 runs the tool's own diff command and the raters judge its report | One scenario pair: the changed tool's record must differ (T07), the unchanged tool's record must stay identical or keep a per-tool fingerprint (T08), and the change should be flagged (T07F) |
| Controls against author bias and scorer error | Evidence label on every criterion; same-author critique and audit; a second corpus written from standards and competitor READMEs; weighting-sensitivity table; mechanical grader. No blind raters, no synthetic control tools, no test of the scorer | Validity tests in the repository test suite (nothing-reporter, file lister, oracle, string echo, every-file-a-model); two raters blind to scores; a reviewer who built an echo tool; default-command probes; five alternative weightings; changelog with before and after for every tool. No seeded identifiers, no positive-control tool | Seeded tokens with an invitation to rerun on a private seed; calibrate.py (oracle, cat, lister, empty); a positive control that executes every payload, with scoring refusing to publish if a probe stays silent; negative controls; critics, skeptics and a hand audit described in RESULTS.md:332-365. No blind raters; calibration is not wired into the repository's tests |
| What the audits changed | SymBiote 79.7 to 75.9 to 73.0; three of ten totals had hand-arithmetic errors; cdxgen's MCP result corrected; agent-bom and Cisco capped by gates; two decoys downgraded; one token widened for SymBiote's naming; one corpus B item and finding removed (AUDIT.md:19-67, :110-139) | 1.0 to 1.1 after scores were known: SymBiote 71.1 B to 67.9 C; agent-bom 60.5 to 65.4; cdxgen 56.0 to 51.1; AIROM 53.0 to 45.0; Syft 36.8 to 27.7; AIsbom 37.5 to 26.1; Snyk 28.9 to 18.1; OWASP generator 17.3 to not graded (CHANGELOG.md:135-146) | Scorer fixes applied to every tool and the full run repeated (commits 444b371 to 3d67c25); agent-bom rose from F to D; cdxgen moved to its README command in safe mode; Cisco given its documented extras (RESULTS.md:339-347) |
| Safety probes | strace evidence for egress, execve and openat; symlinks to /etc/passwd (absolute and relative) and a loop; an /etc/passwd marker and off-pattern secret sentinels searched in outputs and stderr; ANSI, bidi and zero-width characters; 32 MiB sparse file; 40-deep nesting; JSONC and malformed TOML; text telling an AI reviewer to report compliance; corpus delta and HOME writes. No execution canary: the pickle is inert | 7 marker-file canaries (MCP launch command, pickle calling os.system, hook, skill script, npm lifecycle script, setup.py, Python import); default-exec and default-egress probes; 3 out-of-tree escapes with leak tokens; 4 provider-shaped secrets derived from a hash; 8 hostile cases including 200,000-deep JSON, 2^62 header claims, named pipes, 30,000 files and a 1 GiB sparse model | Canary files for two pickles, an MCP launch command, setup.py, a PEP 517 backend and npm scripts; build commands detected from execve; two symlinks out of the scenario; OSC title and OSC 52 sequences; 3 GiB decompression bomb, 2^62 header and 200,000-deep JSON under time and 2 GiB RSS bounds; two literal credentials generated at run time; connect attempts in default mode; a positive control shows each probe fires |
| ShadowScan and the pair | Not measured; its roadmap says so (ROADMAP.md:191-192 on that branch) | Both, in the same harness: ShadowScan alone 44.4 D; pair 69.4 C on the combined outputs, with a note that SymBiote's merged inventory alone identifies the same 48 components as SymBiote alone (RESULTS.md:105). The rater packet for these two was not blind, one drift verdict stayed disputed, and two rater verdicts for the pair were overridden by the author with a stated reason. cross-check/ also runs SymBiote, ShadowScan and the pair on tree A's two corpora with tree A's matcher | Three rows: ShadowScan alone 53.8 D; pair 72.8 B, graded on both artifacts of the documented workflow; the merged BOM alone scores 63.3, below SymBiote alone (RESULTS.md:48, :249) |
| Reproduced offline today (ran) | Both builders: all 67 and 39 SHA-256 values equal the committed manifests. grade.py prints the AUDIT.md table. score.py on the committed raw outputs: coverage, digest, findings, leak and determinism blocks identical on corpus A, also with --strict; identical on corpus B except the findings block. SymBiote end to end (regenerate, scan, score): identical per-component detections | `bench.py build` twice: identical trees and the README digest. tests/test_aibom_bench.py: 9 passed in 3.13 s. report.render on the committed results.json reproduces RESULTS.md byte for byte. Rater files: 225 of 225 and 50 of 50 equal; ShadowScan packets 50 of 50 and 19 of 20. My SymBiote scan: key presence agrees with the published identification for 91 of 92 components | generate.py: 126 items and a catalog identical to CATALOG.md; the digest differs from the published one because it depends on the output directory, as the README says. calibrate.py: oracle 96.5, cat 8.5, lister 1.9, empty 0.0, as documented. The scorecard regenerates byte for byte from results.json. My SymBiote scan of the eight non-hostile scenarios: token presence agrees with the published detection for 68 of 68 components |
| Not reproducible from the tree | strace-derived fields (logs not committed); any tool run; scoring needs CycloneDX 1.5 and 1.6 and SARIF schemas that are not in the repository | Scoring of any real tool (per-tool runs and raw outputs not committed); needs an external schema directory | Scoring of any real tool (raw outputs not committed, 90 MB per RESULTS.md:367); the published digest only at /opt/aibom-bench/corpus2 |

## T2. Nexus SymBiote by class in each tree

Tree A. Found-of-planted is my count from the components blocks of the two score files; recall values are the stored ones (soft items weigh 0.5).

| Class | Corpus A | Stored recall, results/scores.json line | Corpus B | Stored recall, results/corpus-b/scores.json line |
|---|---|---|---|---|
| mcp-server | 7 of 10 | 0.778, :4256 | 4 of 6 | 0.667, :3789 |
| tool | 3 of 3 | 1.0, :4262 | 2 of 3 | 0.8, :3795 |
| skill | 2 of 2 | 1.0, :4261 | none planted | null, :3794 |
| prompt | 9 of 14 | 0.667, :4260 | 2 of 7 | 0.364, :3793 |
| model | 0 of 13 | 0.0, :4257 | 1 of 12 | 0.1, :3790 |
| model-file | 5 of 6 | 0.9, :4258 | 4 of 5 | 0.889, :3791 |
| dataset | 0 of 6 | 0.0, :4254 | 0 of 4 | 0.0, :3787 |
| training | 0 of 2 | 0.0, :4263 | 0 of 2 | 0.0, :3796 |
| vector-store | 3 of 3 | 1.0, :4264 | 1 of 2 | 0.667, :3797 |
| a2a | 1 of 1 | 1.0, :4250 | none planted | null, :3783 |
| agent-config | 1 of 3 | 0.4, :4251 | 0 of 2 | 0.0, :3784 |
| ci-agent | 0 of 1 | 0.0, :4252 | 0 of 1 | 0.0, :3785 |
| container | 2 of 4 | 0.5, :4253 | 0 of 3 | 0.0, :3786 |
| package | 5 of 6 | 0.833, :4259 | 3 of 5 | 0.6, :3792 |
| guardrail | 0 of 2 | 0.0, :4255 | 0 of 1 | 0.0, :3788 |
| All | 38 of 76 | weighted recall 0.555 (:4752), coverage score 1.75 (:4751; grades.json:16) | 17 of 53 | 0.357 (:4139), 0.75 (:4138; grades.json:168) |

Total 73.0, grade B (AUDIT.md:76; grade.py on grades.json:15-169): coverage 9.4 of 30, identity 9.0 of 12, provenance 9.5 of 10, standards 11.4 of 12, risk 10.0 of 10, tool safety 11.7 of 12, determinism 6.0 of 6, runtime 2.5 of 4, operability 3.5 of 4. Earlier totals in the same tree: 79.7 (REPORT.md:30, :57) and 75.9 (CRITIQUE.md:120).

Tree B (results/2026-11-18/).

| Pillar | Identified of planted | Points | RESULTS.md line | results.json lines |
|---|---|---|---|---|
| Models | 5 of 18 | 1.9 of 7 | :28 | points :1398, lists :752-775 |
| Data | 1 of 11 | 0.6 of 6 | :29 | :1399, :776-792 |
| Tools and frameworks | 15 of 18 | 4.2 of 5 | :30 | :1400, :793-816 |
| Agent components | 27 of 37 | 6.6 of 9 | :31 | :1401, :817-859 |
| Infrastructure | 0 of 8 | 0.0 of 3 | :32 | :1402, :860-872 |
| All | 48 of 92 (52 %) | discovery 13.2 of 30 | :12, :69 | recall :1434, total :1483 |

By kind (my grouping of those lists): model 5 of 18; dataset 0 of 7, knowledge_source 0 of 2, vector_store 1 of 2; framework 8 of 10, tool 7 of 8; mcp_server 14 of 14, skill 4 of 4, instructions 4 of 4, subagent 1 of 1, command 1 of 1, hook 1 of 1, permission 1 of 1, agent 1 of 6, prompt 0 of 3, plugin 0 of 1, guardrail 0 of 1; container 0 of 5, endpoint 0 of 2, ci_agent 0 of 1. Total 67.9, grade C (RESULTS.md:12): precision 1.5 of 4, record fidelity 11.3 of 14, standards 8.7 of 10, BOM integrity 10.0 of 10, risk analysis 7.0 of 12, change detection 6.2 of 8, scanner safety 9.9 of 12. RESULTS.md:69: risks 9 of 19, changes 7 of 10, decoys 1 reported of 4 faced, canaries 0 tripped of 6 faced, secrets 0 disclosed of 2 faced, hostile cases 8 of 8, egress attempts 0.

Tree C (results/results.json; scorecard row RESULTS.md:23).

| Domain | Earned of possible | Percent | Components detected | results.json lines |
|---|---|---|---|---|
| mcp | 32 of 39 | 82.1 | 12 of 13 | :58-62 |
| tooldefs | 7 of 15 | 46.7 | 4 of 6 | :64-68 |
| skills | 23 of 32 | 71.9 | 12 of 14 | :70-74 |
| agents | 7 of 18 | 38.9 | 2 of 8 | :76-80 |
| models | 32 of 58 | 55.2 | 8 of 17 | :82-86 |
| data | 0 of 12 | 0.0 | 0 of 5 | :88-92 |
| packages | 10 of 11 | 90.9 | 5 of 5 | :94-98 |
| standards | 9.29 of 12 | 77.4 | not applicable | :100-104 |
| safety | 36 of 36 | 100 | 9 of 9 probes passed | :106-110 |
| All | score 65.3, grade C, in-scope 65.3, risk findings 44.4 % (:51-54) | | 43 of 68 | items from :113 |

## T3. Where the three agree and disagree about SymBiote

Tool mode or commit explains none of the differences: all three graded 0.2.0 at a13b622-equal source, and the flags differ only by --no-project-policy (B, C) and --report-only (C).

| # | Kind of component or finding | Tree A (corpus A; corpus B) | Tree B | Tree C | Who reports a gap | Cause of any difference, and basis |
|---|---|---|---|---|---|---|
| 1 | Model references in code and configuration | 0 of 13; 1 of 12 (a cache path) | 0 of 13 outside weight files | 0 of 7 (R01-R07); Modelfile and model-card lineage missed | all three | none; my scans show no such component in any corpus (ran) |
| 2 | Datasets | 0 of 6; 0 of 4 | dataset 0 of 7; knowledge sources 0 of 2 | 0 of 3 (D01-D03) | all three | none |
| 3 | Agents defined in framework code or exports | corpus B 0 of 2 (n8n workflow, Assistants export); corpus A labels none | 0 of 5 (kind agent 1 of 6; the one is the A2A card) | 0 of 6 (A01-A03, A05-A07) | all three where planted | none |
| 4 | Finding: instructions hidden in a tool description | not detected (REPORT.md:105-109, :310) | false | T03F 0 of 3 | all three | none |
| 5 | Finding: literal credential in configuration | recorded by name, not raised (REPORT.md:308) | mcp-header and env-file false | C06F and C07F 0 | all three: redacted, not raised | none |
| 6 | Finding: unpinned model revision | not applicable, models not read (REPORT.md:317) | false | R02F 0 | all three | follows from row 1 |
| 7 | Finding: typosquat or non-existent dependency | live only (F13) | false | P06F 0 | all three, offline | A plants a non-existent package, B and C a typosquat |
| 8 | CI agent workflow | 0 of 1; 0 of 1 | 0 of 1 | not planted | A and B | C has no case |
| 9 | Guardrail or evaluation configuration | 0 of 2; 0 of 1 | 0 of 1 | not planted | A and B | C has no case |
| 10 | Training pipeline | 0 of 2; 0 of 2 | not labelled | not labelled | A only | only A has the class |
| 11 | Plugin manifest | not planted | 0 of 1 | K11 missed | B and C | A has no case |
| 12 | Finding: skill script that downloads and runs code | not planted | false | K02F 0 of 3 | B and C | A has no case |
| 13 | Prompt files outside agent-instruction locations; inline prompts | 5 of 14 missed; 5 of 7 missed | prompt 0 of 3 | K13 found | A and B, not C | corpus content: C's only prompt file is in .github/prompts/, which SymBiote reads; A and B use a prompts/ directory and inline strings (ran) |
| 14 | Container images | 2 of 4 (compose images found, Dockerfile bases missed); 0 of 3 | 0 of 5 | out of scope | A and B agree on Dockerfile and Kubernetes, differ on compose | corpus content: compose file at the scan root in A, under deploy/ in B (ran: two registry entries on A, none on B) |
| 15 | npm AI SDK dependencies | missed (manifests in sub-directories) | 2 missed (web/package-lock.json) | P04 and P05 found | A and B, not C | corpus content: C's package.json is at the scan root; the root package.json of A's corpus B is read too (ran) |
| 16 | Vector stores | 3 of 3; 1 of 2 | 1 of 2 (Chroma yes, pgvector memory no) | 0 of 2 (D04, D05) | C fully, B partly, A not | matching rule: A and B accept the product name, which SymBiote records as 'chroma (from imports)'; C requires the collection or index name, which it does not record (ran). pgvector is not detected at all |
| 17 | Hook | hook item missed | hook 1 of 1 | K10 missed; finding K10F earned | A and C, not B | matching rule: B's key is the event name, present in the output; A and C require the command's script name or destination, absent (ran) |
| 18 | MCP server implemented in the repository | missed; found after the token was widened to the source path | 2 of 2 | T01 and T05 missed; their tools found | A (first corpus) and C, not B | matching rule: SymBiote names these servers by variable ('mcp', 'server'); a tree that accepts the source path credits them, one that requires the declared name does not (ran) |
| 19 | MCP client dialects | all found on A except a malformed file and a 40-deep one; corpus B misses Zed and Continue | 14 of 14 | 12 of 13 (misses a server launched from SDK client code) | A and C, different cases | corpus content: only A's second corpus has Zed and Continue; only C has the SDK launch |
| 20 | Finding: permissive permissions | F14 not credited | true | not planted | A, not B | corpus content: A's allow-list is scoped, B's contains Bash(*) |
| 21 | A file with a model suffix that is not a model | zero-filled .bin reported as a model | text file named .gguf reported as a model | no penalty on its negatives | A and B | C plants no such file as a negative; both components appear in my scans (ran) |
| 22 | Drift granularity | not run | 7 of 10 changes visible and reported; the 3 missed are kinds it does not inventory | change visible (T07) but the unchanged sibling tool's record changes too (T08 0 of 1) | C only | rubric: only C checks that an unchanged tool stays stable |
| 23 | Scanner safety | 11.7 of 12 | 9.9 of 12 | 36 of 36 | none: no execution, egress, symlink read or secret in output in any tree | rubric: A deducts for JSON-escaped ESC; B's exposure rule withholds points for one canary, two secrets and the HTML case it did not face. My scans tripped no canary (ran) |
| 24 | Determinism | byte-identical | 4 of 4, with one differing scan in 46 during an earlier rerun (0.25 s limit on TypeScript parsing, RESULTS.md:106) | 2 of 2 | none; B adds a caveat | B ran more scans |
| 25 | Found in all three | weight files, MCP client configurations, skills, instruction files, A2A card, tools from decorators and registerTool, root Python manifests | same, plus subagent and slash command | same, plus subagent, slash command and the CLAUDE.md import | | |

## T3b. The pair in B and C

| | Tree B | Tree C |
|---|---|---|
| SymBiote alone | 67.9; 48 of 92 | 65.3; 43 of 68 |
| ShadowScan alone | 44.4; 33 of 92 | 53.8; 44 of 68 |
| Pair as graded | 69.4 on combined outputs; 55 of 92 | 72.8 on both artifacts; 54 of 68 |
| Merged SymBiote inventory alone | same 48 components as SymBiote alone (RESULTS.md:105) | 63.3, below SymBiote alone (RESULTS.md:48, :249) |
| Determinism of the pair | 0.7 of 4 | 0.5 of 2 |
| Data pillar or domain for the pair | 2 of 11 | 0 of 5 |

## T4. The other tools

Order in each tree (A: AUDIT.md:76-85; B: RESULTS.md:11-22; C: RESULTS.md:22-34).

| Rank | Tree A | Tree B | Tree C |
|---|---|---|---|
| 1 | Nexus SymBiote 73.0 B | ShadowScan + SymBiote 69.4 C | SymBiote + ShadowScan 72.8 B |
| 2 | k8s-aibom 59.0 C (not run) | Nexus SymBiote 67.9 C | Nexus SymBiote 65.3 C |
| 3 | agent-bom 55.6 C (capped) | agent-bom 65.4 C | Nexus-ShadowScan 53.8 D |
| 4 | Cisco AI BOM Tier-1 37.0 F | cdxgen 51.1 D | agent-bom 51.2 D |
| 5 | Trusera ai-bom 29.1 F | Cisco AI BOM 48.6 D | Cisco AI BOM 50.3, F after gates |
| 6 | ai-finder 28.1 F | AIROM 45.0 D | AIROM 39.4 F |
| 7 | ai-agentbom 28.1 F | Nexus ShadowScan 44.4 D | cdxgen 35.0 F |
| 8 | cdxgen 23.3 F | Trusera ai-bom 32.2 E | Trusera ai-bom 34.5 F |
| 9 | OWASP AIBOM Generator 22.7 F (not run) | Syft 27.7 E | aibom-scanner 29.8 F |
| 10 | Syft 22.2 F (not run) | AIsbom 26.1 E | AIsbom 27.7 F |
| 11 | | Snyk Agent Scan 18.1 F | Syft 25.1 F |
| 12 | | | AIBoMGen CLI 11.7 F |
| not graded | | OWASP AIBOM Generator | OWASP AIBOM Generator |

Where the orders differ, with what the trees record as different (causal link not verified).

| Tool | Difference | Recorded difference in how it was run |
|---|---|---|
| cdxgen | 8th of 10 in A, below Trusera; 4th in B, above Cisco; 7th in C, between AIROM and Trusera | 12.9.2 in A and C, 13.8.0 with four invocations in B. All three record that its default or package modes run install steps (A CRITIQUE.md:70-91; B canary setup-py tripped; C canary pep517-backend) |
| Cisco AI BOM 1.10.1 | A 37.0 F with a secret-leak gate; B 48.6 D without a gate; C 50.3 with two gates | A drives Tier-1 scanners through an internal API; B runs analyze with the agentic extra; C adds the analysis, security and llm-openai extras, and the security extra starts declared MCP servers |
| agent-bom 0.115.4 | third in A and B, fourth in C. By components it is ahead of SymBiote in A (weighted recall 0.615 vs 0.555; 0.575 vs 0.357) and in B (52 vs 48 of 92) and behind in C (39 vs 43 of 68); in C it finds none of the seven model references | different opt-in flags in each tree (see facts) |
| Nexus ShadowScan 0.1.4 | 7th of 11 in B (44.4), 3rd of 12 in C (53.8) | plain `code` in B; `--profile ci --no-incremental` with an identity key in C |
| Syft and AIsbom | Syft above AIsbom in B, below in C | same versions |
| OWASP AIBOM Generator | graded 22.7 from source in A; B and C decline to grade it | |
| Only in one tree | k8s-aibom, ai-finder, ai-agentbom (A); Snyk Agent Scan (B); aibom-scanner, AIBoMGen CLI (C) | |

Coverage-only orders. A corpus A: agent-bom 0.615, SymBiote 0.555, Cisco 0.504, Trusera 0.370, ai-finder 0.314, cdxgen 0.305, ai-agentbom 0.164. A corpus B: agent-bom 0.575, Cisco 0.445, SymBiote 0.357, ai-agentbom 0.254, cdxgen 0.247 (corrected: this is the `-t mcp` entry; plain cdxgen is 0.200, below Trusera), Trusera 0.239, ai-finder 0.197. B components of 92: pair 55, agent-bom 52, Cisco 51, SymBiote 48, cdxgen 45, Trusera 34, ShadowScan 33, AIROM 31, Syft 14, AIsbom 13, Snyk 7. C components of 68: pair 54, ShadowScan 44, SymBiote 43, Cisco 40, agent-bom 39, cdxgen 31, Trusera 23, AIROM 22, aibom-scanner 19, Syft 11, AIsbom 11, AIBoMGen 7.

## T5. Path collisions and trial merges (ran)

| Pair | Paths in both trees | Same content | Trial merge of the two branches |
|---|---|---|---|
| A and B | README.md, SPEC.md | no | conflicts: README.md, SPEC.md |
| A and C | README.md, SPEC.md, score.py | no | conflicts: README.md, SPEC.md, score.py |
| B and C | README.md, SPEC.md | no | conflicts: README.md, SPEC.md, and docs/README.md |
| all three | README.md, SPEC.md | no | |
| each branch with origin/main | | | clean |

Outside the directory, docs/README.md is the only path changed by more than one branch (all three); git merges it for A+B and A+C and not for B+C, where both add a row named AIBOM-Bench at the same place. There is no file-versus-directory clash and no case-insensitive duplicate. results/ is a directory in all three with no common file, but tree A's scorer treats each sub-directory of results/ as a tool (ran), so in a shared directory tree B's results/2026-11-18 would be listed as one (inferred).

## T6. The counts cited from "AIBOM-Bench v1.1" against tree B

| Owner's figure (pair target) | Tree B by its own pillar: SymBiote; ShadowScan; pair | Nearest sub-grouping in tree B | Derivable |
|---|---|---|---|
| models 0 of 16 (13 of 16) | Models: 5 of 18; 6 of 18; 5 of 18 | model references outside weight files: 0 of 13; 6 of 13; 0 of 13 | no; no grouping that includes models has 16 |
| agents 0 of 2 (2 of 2) | Agent components: 27 of 37; 18 of 37; 29 of 37 | kind agent: 1 of 6; 3 of 6; 3 of 6 | no |
| AI infrastructure 1 of 7 (7 of 7) | Infrastructure: 0 of 8; 3 of 8; 3 of 8 | containers and endpoints: 0 of 7; 2 of 7; 2 of 7 | no; 7 only by leaving out the CI agent, and then SymBiote finds 0 |
| data and retrieval 1 of 9 (7 of 9) | Data: 1 of 11; 2 of 11; 2 of 11 | datasets and vector stores: 1 of 9; 2 of 9; 2 of 9 | only as a coincidence that leaves out the two knowledge sources; the target 7 of 9 has no counterpart |

Tree B's earlier version 1.0 (168bfc55) had 91 components with the same 18 models, 11 data and 8 infrastructure items. Tree C has 17 model components (7 references), 8 agent items and 5 data items, so it does not supply these counts either. What tree B does hold for the pair on tree A's corpora (cross-check/README.md:41-77): model 0 to 6 of 13 and 1 to 10 of 12 with pull request 258, and no change on main.

## T7. Layout options, criteria, and what main says

| Option | What it is | What it keeps | What it costs |
|---|---|---|---|
| 0 | Land none; keep three branches; use only the shared findings | every stored result as checked today | branches drift; tree A's roadmap cites a tree main does not have; tree B's tests do not run in CI |
| 1 | One harness, the other corpora as additional corpora | four project designs as mutual checks (tree A's audit shows the value: recall 0.555 fell to 0.357 on its second corpus); one adapter set, one detection rule, one results format | every published number is superseded; the three rules differ in substance, so the choice changes results (T3 rows 16-18); tree A's reviewer-scored dimensions have no counterpart in B and C; a rerun of every tool on a disposable machine (about 1 h for B's ten adapters and 90 min for C's, per their READMEs); the roadmap's per-class table must be re-based |
| 2 | One canonical tree, two archived as dated records | one name and one set of numbers; least to maintain; no rerun | the cross-corpus check survives only if archived corpora stay runnable; if A is not canonical its roadmap targets (ROADMAP.md:200-216 on that branch) need re-pointing; if A is canonical the pair has no native measurement |
| 3 | Three sibling directories with distinct names and one index page | every stored result, audit trail and offline check; branches can land in any order; no choice among the trees is made | three harnesses, three adapter sets and three numbers for the same tool stay in the repository; the index must say which number is cited where |
| 4 | Option 3 now, option 1 later as a pre-registered rerun | nothing is lost now; convergence happens under the conditions L4 names | the cost of option 1 is deferred, not avoided |

Path fixes a move needs (read). Tree A: its roadmap says REPORT.md, AUDIT.md, SPEC.md and results/ pointers mean benchmarks/aibom-bench (ROADMAP.md:22-23) and names the path 4 times; the enhancement plan names it 15 times; benchmarks/README.md links it; the code is location-independent. Tree B: tests/test_aibom_bench.py:16 hardcodes the directory; aibom_bench/runner.py:117 takes the repository root as parents[3], which survives a rename at the same depth and breaks at another; the docs/README.md row. Tree C: the docs/README.md row only (README.md:16-17 says the directory is self-contained).

Criteria for choosing.
1. Purpose: a gap list for SymBiote and the pair, or a public ranking. For the first, the three agree on the main gaps (T3) and the question is whose class denominators the roadmap uses. For the second, main's roadmap already answers (below).
2. How much of the score is computed rather than judged: A scores most criteria by reviewer with evidence labels; B measures 90 points (13 through raters) and assesses 10; C computes everything, with findings by keyword.
3. Whether a third party can rescore from the tree alone: only A commits raw outputs; B and C commit verdicts.
4. Protection against a scorer that pays for echoes: B's validity tests and C's calibration exist and pass (ran); A has strict mode and overrides.
5. Strength of safety evidence: marker-file canaries (B, C), a positive control (C), default-command probes (B, C), openat-level symlink evidence and corpus delta (A).
6. Independence of the corpus from the host tool: A states its first corpus was written with SymBiote's file list in view and adds a second (CRITIQUE.md:12-19); B states the author had read the tool's documentation (SPEC.md:417-418); C draws names from a seed.
7. Pair and ShadowScan coverage, which the owner's split needs: native in B and C, absent in A.
8. Cost in the repository: 709 files and 12 MB, 63 and 1.6 MB, 12 and 0.8 MB; tests added to CI (B: 9 tests, 3 s); what else rides on each branch (A: roadmap rewrite and plan; C: product source changes).
9. Naming: three unrelated things are called AIBOM-Bench 1.0, 1.1.0 and 1.0.0.

What main says (origin/main:ROADMAP.md).
- :178, row L4 under "Later — stay best": "A pre-registered, third-party benchmark round on public repositories, with every tool run in its supported mode", depending on "other people".
- :191, acceptance test P2: "An independent evaluator reruns the published benchmark and reproduces its numbers" is open (L3, L4).
- :265, Corrections to the reviews: "Rankings (#1 on coverage; 3rd, 4th, 5th, 8th, 9th of 11 or 12) and head-to-head benchmark numbers" were "Dropped: they contradicted each other, were judgments rather than measurements, or compared tools run below their supported mode. L4 replaces them with a reproducible round."
- :266: "SymBiote itself has not been benchmarked" is answered with "Two self-authored regression corpora have run in CI since v0.1.0 ... what is missing is a comparative, third-party round."
Read against that text (inferred): each tree has one author working in the graded tool's repository; all corpora are synthetic; none was pre-registered, and A and B record changes to labels or rules after results were seen; several tools ran below their supported mode; and the three order the other tools differently (T4). Each tree says as much about itself (A AUDIT.md:91-93, :104-106; B SPEC.md:417-424; C RESULTS.md:383-385). None of them is L4, and whichever lands does so as a self-authored result.

## Defects found while comparing

| Severity | Where | What |
| --- | --- | --- |
| high | All three branches: origin/claude/laughing-hawking-5f9x78, origin/claude/modest-gauss-ymoyc9, origin/claude/nice-archimedes-368l54 | No two of the three AIBOM-Bench branches can be merged: add/add conflicts at benchmarks/aibom-bench |
| medium | Tree A branch, ROADMAP.md:192-198 and :731-732; the owner's draft itself is not in the repository | The counts attributed to 'AIBOM-Bench v1.1' have no source in any of the three trees, including tree B, the one named 1.1.0 |
| low | Tree A branch, ROADMAP.md:17-21 | Roadmap says the branch's src equals a13b622; at the branch tip it equals main and differs from a13b622 in six files |
| low | Tree A branch, ROADMAP.md:191-192, against tree B cross-check/ | Roadmap says ShadowScan has not run on either corpus; tree B's cross-check has run ShadowScan and the pair on both |
| low | Tree A, SPEC.md:82-83 and REPORT.md:11 | Documents say 5 decoys; ground_truth.json has 6 |
| low | Tree A, results/corpus-b/scores.json | Findings block is stale against ground_truth_b.json and the file was not written by score.py as committed |
| low | Tree A, results/ layout and score.py:543 | Scoring the committed results directory lists `alt` and `corpus-b` as tools |
| note | Tree A, AUDIT.md:81-82 | Final table ranks ai-finder above ai-agentbom at 28.1 each; grade.py computes 28.05 and 28.14 |
| low | Tree B, README.md:17-18 and :61 | README says nine tools graded and ten adapters; the results hold eleven graded entries and tools/ holds twelve adapters |
| note | Tree B, entry 'ShadowScan + SymBiote' (assessments/nexus-pair.json, results/2026-11-18/adjudication/) | The pair's risk recall of 11 of 19 includes two verdicts set by the author against the raters, from a packet that was not blind |
| low | Tree B, aibom_bench/corpus.py:23 and aibom_bench/runner.py:134-143 | The canary directory is one fixed host path that every run deletes and recreates, with no lock |
| note | Tree B, tools/cdxgen.json, against origin/main ROADMAP.md:261 | Tree B grades cdxgen 13.8.0; main's roadmap recorded 13.8.0 as an unreleased development branch on 12 November |
| medium | Tree C branch (origin/claude/nice-archimedes-368l54) | The benchmark branch also carries product source changes made after grading |
| note | Tree C, tools.json:129 and :206 | A 64-hex ShadowScan identity key is written literally in the tree |
| note | Tree A, build_corpus.py:41-50 and :202, build_corpus_b.py:26-33 and :114, both ground truths, results/corpus-b/cisco-aibom/*/tier1.json | Credential-shaped sentinel strings are written literally in the tree, and three committed tool outputs repeat one |
| medium | Nexus SymBiote 0.2.0 at a13b622-equal source, as seen through trees A and B | A file is reported as a model on its suffix alone |

## Recommendation

1. Maintainer: do not merge a second of these branches as it stands. Every pair conflicts (T5), and whichever lands first takes the path the other two also use. Decide the layout before the first one lands.

2. Maintainer and owner: decide what the benchmark is for. Main's roadmap (L4 at :178, corrections at :265-266) reserves rankings for a pre-registered third-party round. Under that text all three are self-authored measurements: their shared findings about SymBiote (T3 rows 1 to 7) hold in all three and were reproduced today, while their rankings of other tools differ (T4) and should not be cited from any of them.

3. Owner: name the source of the "v1.1" counts or drop them; they are not in tree B either (T6). Tree A's session: amend ROADMAP.md:191-198 and :731-732 on its branch to say so, to record that tree B's cross-check has run ShadowScan and the pair on both of its corpora, and to correct the statement that the branch's src equals a13b622.

4. All three sessions: give the three benchmarks distinct names. Today 1.0, 1.1.0 and 1.0.0 are unrelated things under one name, which is how the "v1.1" citation went wrong.

5. (Revised by the second check above: decide the purpose first; the rename is needed only if more than one tree lands.) The step that options 3 and 4 need is to move each tree to its own directory name and leave benchmarks/aibom-bench free for whatever becomes canonical. Who changes what:
   - Tree A's session: the path sentence at ROADMAP.md:22-23, 4 path mentions in the roadmap, 15 in the enhancement plan, the benchmarks/README.md section; also the decoy count at SPEC.md:82 and REPORT.md:11.
   - Tree B's session: tests/test_aibom_bench.py:16, its docs/README.md row, the counts at README.md:17-18 and :61; aibom_bench/runner.py:117 only if the directory depth changes.
   - Tree C's session: its docs/README.md row; and either split the 19 non-benchmark paths into their own pull request or state in the pull request that product changes are included.
   - One session, last: a single index in benchmarks/ and a single row in docs/README.md (B and C conflict there), stating that all three are single-author, synthetic and self-run, which number is cited where, and that L4 is open.

6. If one harness is wanted (option 1, or the later half of option 4), the maintainer chooses it by the criteria in T7 and it is new work: write down the detection rule first (the three rules give different answers for vector stores, hooks and first-party MCP servers), port the other corpora, rerun every tool on a disposable machine, and have the next corpus written by someone outside the project, as tree A's audit and main's L4 both ask. Until that run exists the three result sets are dated records, not a ranking.

7. Independent of layout: tree A's session re-scores or removes the stale findings block in results/corpus-b/scores.json; tree C's session generates the ShadowScan identity key at run time; whoever owns SymBiote's model collector looks at the suffix-only model detection that trees A and B both show and my scans reproduced.

## Not done

- I ran no third-party scanner, no tree's tool runner (run_tools.sh, `bench.py run`, run.py), not ShadowScan and not tree C's executor.py. No third-party tool result was re-measured, so the rank differences among the other tools are explained only from stored data and adapter files.
- Tree B's `bench.py score` and tree C's score.py could not be rerun on real tools: neither tree commits raw outputs. For those two trees my check of SymBiote is at key or token level (91 of 92 and 68 of 68), not a full rescore under their typed-record rules; I did not scan tree C's six hostile scenarios or any of tree B's twelve other variants.
- Tree A's strace-derived results (egress, execve, symlink opens) could not be recomputed: the logs are not committed. Its scorer needed CycloneDX 1.5 and 1.6 and SARIF schemas from the session scratchpad, not from the repository.
- gitleaks is not installed here, so I have no secret-scanner verdict for the literal sentinels in tree A or the literal key in tree C.
- Beyond the hygiene script, ruff on the three benchmark directories and tree B's one test file, I ran no repository gate (no mypy, no full suite, no `make quality`).
- I built no merged or relocated tree. The statements that distinct directory names leave only docs/README.md to merge, and the list of path fixes per tree, come from path lists and reading the code. (The second check built it; see item 7 there.)
- The owner's draft is not in the repository; its counts were checked only against the three trees. External facts (tool versions, whether cdxgen 13.8.0 was released) were not checked: nothing left this machine.
- The generated corpora were deleted from scratch after use because they hold live hostile payloads; the commands in the facts regenerate them. Copies of the tree B and tree C ground truths with the secret values removed are kept in out/.
