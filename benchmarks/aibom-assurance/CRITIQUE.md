# Skeptic's review of AAB v1.0 and the rerun

The first run ranked the host tool first. A reader should assume that is where the bias is
and go looking for it. This review did, then reran everything on the corrected benchmark.
Numbers below are from `results/first-run/` (before) and `results/` (after).

## Challenges, what was checked, what changed

| Challenge | Checked | Outcome |
| --- | --- | --- |
| The fixture plants files only the host tool knows how to read | Every fixture path against each tool's documented inputs | `rag_config.yaml` is a layout only Nexus SymBiote documents. It supplied 2 of its 2 data-family items. Removed; the collection, embeddings and S3 source now live only in `agent/rag.py`. Nexus SymBiote's data recall fell to 0 of 8. |
| Runtime reconciliation rewards recall and ignores precision | `trace-diff` output | It reported the declared primary model as undeclared. A false alarm now costs one point: 3 to 2. |
| The gate criterion was measured for the host tool and taken from documentation for others | Default-run exit codes | agent-bom also exits 1 on findings. The scorer now measures the gate for every tool from the default run; agent-bom gained 0.4. |
| Discovery credit from proprietary JSON favours whoever has the richest native format | Items matched only in native output | Nexus SymBiote: 0 of 49 items came only from native JSON. agent-bom: 20 of 50 did (tools, hosted models, skills). Cisco: 1. cdxgen and Trusera: 0. The rule is generous to agent-bom, not to the host. Kept, disclosed. |
| The weights encode the author's philosophy | Four alternative weightings | Order of the top four is unchanged under equal dimension weights, discovery at 50 percent, equal family weights and measured-only criteria. Trusera and AIsbom swap places under some. |
| The host tool got measured labels for features others only had documented | Exercised what could be exercised | cdxgen signing (M), Cisco diff (M), agent-bom baseline (M, partial) were added. agent-bom's MCP proxy and k8s-aibom's controller remain documentation-only and capped. |
| Determinism was credited on one pair of runs | Second full run | Nexus SymBiote's two default runs differed in content on the rerun. See below. |

## What the rerun found about the host tool

The first default run under `strace` did not inventory the two tools of the TypeScript MCP
server, the second did. The inventory recorded why: `mcp_servers/notes_server/src/index.ts:
TypeScript parsing exceeded its time limit`. `scanners/ts_tools.py` sets a 0.25 second parse
bound and a 2 second analysis bound, while `docs/collection-limits.md` states that the limits
are "input and work bounds, not a process sandbox or a wall-clock deadline". Coverage therefore
depends on machine speed and load, the output is not reproducible across hosts, and the
documentation is wrong on this point. Eight unobserved repeat runs were byte-identical, so the
first run's byte-identical result was real but not robust. The failure is recorded as a
collection failure and the gate reports incomplete coverage, which is the right behaviour; a
time-bounded parser that reports its own failure is still a nondeterministic inventory. Score
effect: D5 fell from 10 to 5, total from 77.8 to 70.8.

## Before and after

| Tool | First run | Rerun | Change |
| --- | ---: | ---: | --- |
| Nexus SymBiote 0.2.0 | 77.8 | 70.8 | home-field file removed (D1 -1.0), nondeterministic coverage (D5 -5.0), runtime false alarm (D7 -1.0) |
| agent-bom 0.115.3 | 61.8 | 62.2 | gate measured instead of documented |
| cdxgen 13.8.0 | 54.0 | 54.0 | |
| Cisco AI BOM 1.10.1 (deterministic) | 52.0 | 52.0 | |
| Trusera ai-bom 3.6.0 | 36.5 | 36.5 | |
| AIsbom 1.7.0 | 36.2 | 36.2 | |
| OWASP AIBOM Generator | 24.3 | 24.3 | |
| k8s-aibom | 20.2 | 20.2 | |
| WasmAgent agentbom-core 0.4.0 | 5.0 | 5.0 | |
| Snyk `snyk aibom` | 4.4 | 4.4 | |

Sensitivity of the rerun ranking: Nexus SymBiote 70.8 as weighted, 73.5 with equal dimension
weights, 68.8 with discovery at 50 percent, 67.8 with equal family weights; agent-bom 62.2,
64.0, 61.0, 61.4; cdxgen 54.0, 57.2, 49.2, 55.6; Cisco 52.0, 51.2, 54.0, 51.7. The gap
between first and second is 6 to 10 points under every weighting tried.

## What this review could not fix

- **One fixture, one author.** Seventy-six items chosen by one person who had read every
  tool's documentation, including the host's. Removing `rag_config.yaml` fixes the clearest
  instance; it does not prove there are no subtler ones. The fixture is MCP-heavy (21 of 76
  items), which is defensible for an agent benchmark and favourable to the two tools built
  around MCP.
- **Three decoys is a weak precision test.** No tool reported one, so precision is
  unmeasured in practice. A serious revision needs decoys per family, including near-miss
  names and commented-out code.
- **Runtime reconciliation is a dimension one tool can score in.** The OTLP fixture follows
  the OpenTelemetry GenAI conventions, not a vendor format, but only Nexus SymBiote consumes
  traces. Five points is the ceiling of the advantage; the sensitivity table shows the
  ranking survives without it.
- **Cisco ran below its supported mode.** The deterministic tiers were driven through the
  library because `analyze` demands an LLM. Its zero on planted risks is a floor for the
  product, not a verdict on it.
- **cdxgen got two invocations.** The union of `aibom` and plain `cdxgen` is defensible
  (both are zero-configuration and documented) and still generous relative to one command
  for everyone else. The informational `-t ai -t mcp -t ai-skill` run reached 34 of 76.
- **Documentation-graded tools are not graded.** k8s-aibom, Snyk and WasmAgent rows measure
  how far a README gets you on this rubric. Their in-scope numbers should not be quoted.
- **Token matching under-credits opaque naming.** Nexus SymBiote's `rag-source-0` naming
  and any tool that hashes names cannot be matched by token; raw outputs are kept so a
  reader can check the misses by hand.
- **strace overhead is part of the measurement.** It slowed every tool and tripped one
  tool's parse deadline. That is informative about the deadline and still a harness artefact
  worth stating.

## Verdict

After the review, the ordering stands and the host tool's lead is smaller and better
explained: it wins on evidence, safety, signing and MCP coverage, and it loses on data,
hosted models, infrastructure outside the root, and on reproducibility under load, which its
own documentation misstates. The benchmark is reproducible and its two defects of fairness
found so far were fixable in code. It remains one author's fixture, and anyone quoting it
should rerun it.
