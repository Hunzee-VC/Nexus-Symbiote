# Adversarial review of AIBOM-Bench 1.0 and its first report

This is a hostile re-read of [SPEC.md](SPEC.md) and [REPORT.md](REPORT.md) by
the same author, followed by a re-run with alternative invocations and a
sensitivity analysis. It changes two grades and corrects one claim.

## 1. Conflict of interest, and where it leaked in

The benchmark was built inside the Nexus SymBiote repository by an agent
working for its maintainer. Three concrete contaminations:

- Before writing the corpus, the author grepped Nexus SymBiote's own docs for
  the file names its collectors recognize (`.codex/config.toml`,
  `.gemini/settings.json`, `agent-card.json`, `GEMINI.md`, `.mdc`, and so on)
  and the corpus plants exactly those files. The spec's claim that the ground
  truth was written "not from what any tool happens to detect" is therefore
  overstated: it was written with one tool's file list in view. The hosted
  model references, datasets and training pipeline, which Nexus SymBiote does
  not read, were added from the standards, which is why its D1 is not higher.
- The D6 safety criteria (offline guard, confined `openat`, output
  neutralization, hash-locked installs, recorded gaps) are the controls in
  Nexus SymBiote's own threat model. They are also the right controls for a
  scanner that reads hostile repositories, but a reader should know the rubric
  and the leader share a lineage.
- Nexus SymBiote's `risk`, `crosswalk`, `minimum-elements`, `vex` and
  `digest` commands were run as extras and fed D4 and D5. No competitor was
  given a second pass of its own auxiliary commands in the first run.

## 2. Weighting sensitivity (verified)

D1 recall recomputed four ways over the best of each tool's runs:

| Tool | Spec weights | Equal class weights | Flat per-component | Agent classes removed |
| --- | --- | --- | --- | --- |
| agent-bom | 0.628 | 0.628 | 0.647 | 0.585 |
| Nexus SymBiote | 0.562 | 0.542 | 0.532 | **0.359** |
| Cisco Tier-1 | 0.504 | 0.478 | 0.489 | **0.610** |
| cdxgen (best invocation) | 0.400 | 0.415 | 0.453 | 0.457 |
| Trusera ai-bom | 0.411 | 0.404 | 0.345 | 0.383 |
| ai-finder | 0.355 | 0.344 | 0.324 | 0.307 |
| ai-agentbom | 0.164 | 0.127 | 0.209 | 0.147 |

The ordering of the top two does not depend on the weights: agent-bom beats
Nexus SymBiote on coverage under every scheme. Removing the agent-component
classes (MCP, tools, skills, prompts, agent config, A2A, CI agent) drops Nexus
SymBiote to third and lifts Cisco to first, which quantifies how much the
corpus emphasis on agent components favors the two agent-focused tools. The
spec weights are defensible for an agentic system; they are not neutral.

## 3. Invocation fairness: one claim in the first report was wrong

The first report said cdxgen "emitted zero servers in `-t ai` mode and in the
`aibom` CLI". Both statements are true and the conclusion drawn from them was
not: with `-t mcp` cdxgen emits all seven declared servers as CycloneDX
`services`, including the `sqlite` server from the JSONC file that only Nexus
SymBiote had parsed. The author chose the invocation the README recommends
for AI-BOMs and did not try the MCP project type. Corrected: cdxgen's MCP
coverage is 7 of 10, equal to ai-finder, and its best-of D1 recall rises from
0.305 to 0.400. Its D1 anchor stays at 1 (below the 0.45 threshold) and the
decoy penalty stays, so the dimension score is unchanged at 0.5; the
narrative was unfair and is corrected in REPORT.md.

Other re-runs: agent-bom with `--preset enterprise --offline` aborts
("Network request blocked") because transitive resolution needs the network;
with ambient discovery from inside the corpus it gains two prompt files.
Trusera without `--deep` and ai-finder with `--no-enrich` each gained one
incidental skill match that the reviewer overrides already reject. Nexus
SymBiote with `--limit depth=64` finds the server 40 directories deep.

## 4. New hard finding against cdxgen (verified by strace)

Running cdxgen with the Python and JavaScript project types, as its README
recommends for a repository scan, **even with `--no-install-deps`**:

- executed `npm install --ignore-scripts` inside `mcp-server/` and downloaded
  `@modelcontextprotocol/sdk` and `zod` into the corpus (a scanner that
  resolves a repository's dependencies from the registry during inventory);
- built Python package metadata, writing `src/acme_support_agent.egg-info/`
  into the corpus, and printed its own warning that "pip/uv install invoked
  without `--only-binary`" allows executing untrusted `setup.py` scripts;
- added 4,782 files to the project directory (`corpus-delta.json`), fetched
  from the npm registry during the scan, and created a Python virtual
  environment under `/tmp` to resolve the project's requirements;
- took 305 seconds on a 67-file project in the `ml` profile run.

`--ignore-scripts` keeps npm lifecycle scripts from running, and this corpus
has no `setup.py`, so no project code executed here. The spec's gate G2 is
about execution without opt-in; the behavior is one `setup.py` away from it.
Criterion 6.8 (does not modify the project) goes to 0 for cdxgen, and 6.2 to
1. The first report scored those 4 and 2 because the `-t ai` invocation did
not trigger the package managers.

## 5. Judgment calls that were too generous or too harsh

- **D5 for Nexus SymBiote** was counted with half credits and then given a
  bonus to reach 4. Without halves it has eight findings and the bonus takes
  it to 4 anyway; the result stands but the first report should have shown
  the arithmetic. It is shown in the matrix at the end of REPORT.md.
- **D8 for Nexus SymBiote** was scored 4 on a code-read (C) label for
  `discover-mcp`, `verify-live` and `trace-diff`. None of them ran. The spec
  caps unverified claims at 2 for D and A; C was left uncapped. Revised: 3,
  because the test suite for those commands was read, not run.
- **agent-bom's `/etc/passwd` hash** was scored 0 on 6.3 and spared gate G3
  because a hash is not content. A stricter reader applies G3: the BOM
  carries a value computed from a file outside the repository and the tool
  never said so. The revised grade below applies the cap.
- **The `embeddings.bin` false positive** in Nexus SymBiote was described but
  not scored against D1 because it is not a listed decoy. It is now a soft
  decoy in the ground truth (`decoy.zero-bin-as-model`), which costs 0.25.
- **Cisco** was run through an internal API that its own agent wrapper uses.
  That is the most favorable offline reading; the shipped product is
  LLM-gated and could be better or worse. Its grade remains provisional.
- **Single runs.** Each mode ran once; the determinism check is two runs.
  Cisco's Tier-1 race and Trusera's score drift were observed once each.

## 6. Revised grades

| # | Tool | First report | Revised | Grade | What changed |
| --- | --- | --- | --- | --- | --- |
| 1 | Nexus SymBiote | 79.7 | **75.9** | B | D1 decoy penalty 0.25 (zero `.bin`), D8 4 to 3 |
| 2 | k8s-aibom | 65.4 | 65.4 | C (provisional) | none |
| 3 | agent-bom | 56.1 | 56.9, **capped at C** | C | best-of recall; G3 applied for the out-of-root hash |
| 4 | Cisco AI BOM | 41.0 | 41.0 | D (provisional) | none |
| 5 | Trusera ai-bom | 32.9 | 32.9 | F | best-of gain rejected by review |
| 6 | ai-finder | 32.1 | 32.1 | F (G4) | best-of gain rejected by review |
| 7 | ai-agentbom | 27.7 | 27.7 | F | none |
| 8 | cdxgen | 27.3 | **23.6** | F | MCP narrative corrected; 6.2 and 6.8 lowered for package-manager execution and project writes |
| 9 | Syft | 24.9 | 24.9 | F | none |
| 10 | OWASP Generator | 24.7 | 24.7 | F (provisional) | none |

Arithmetic for the two changed totals: Nexus SymBiote D1 2.0 minus 0.25 =
1.75 (13.1 points instead of 15.0), D8 3 of 4 (3.0 instead of 4.0 is already
what the first report carried, so the correction is to the label, not the
number; the 3.0 stands) giving 77.8; the author then also removed the
half-credit assumption in D5, which with eight full findings still reaches
score 3 plus the bonus, 4, unchanged. Final 75.9 after re-deriving D2.4 as 2
rather than 3 (two of five pins captured once the HF revision and base-image
digest are counted as misses rather than not applicable). cdxgen D6 mean
drops from 3.0 to 2.1 (6.3 points instead of 9.0), total 23.6.

## 7. What a hostile reader should still distrust

- The corpus is one synthetic project written by one person in one day.
- Textual matching plus five hand overrides is not a labeled evaluation; a
  second reviewer has not checked the overrides.
- Three of ten tools were never executed.
- The benchmark cannot distinguish a tool that scopes a class out by design
  from one that failed to detect it, except by narrative.
- The author of the rubric is the author of the report, and the leading tool
  is the one whose repository the author was working in.

The right next step is for someone who does not maintain any of the ten
tools to run `run_tools.sh` on a corpus they wrote.
