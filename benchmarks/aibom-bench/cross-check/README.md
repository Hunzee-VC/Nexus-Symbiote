# Cross-check: the ShadowScan and SymBiote pair on another tree's corpora

Three branches of this repository each hold a benchmark called AIBOM-Bench, written
by three authors who did not see each other's work. This directory runs one
measurement from this tree on the two corpora of another:
`benchmarks/aibom-bench/` on `claude/laughing-hawking-5f9x78` at `2c627e8c`
(corpora A and B, built by its `build_corpus.py` and `build_corpus_b.py`), scored by
that tree's own match rules. Its roadmap sets per-class targets for the pair and
says ShadowScan had not been run on either corpus.

## What was run

On 18 November 2026, offline, in an unprivileged network namespace with an isolated
`HOME`:

- **SymBiote alone**: `nexus-symbiote scan CORPUS` on `main` at `7ca2235f`.
- **ShadowScan alone**: Nexus ShadowScan 0.1.4, `shadowscan code CORPUS`.
- **Pair on `main`**: ShadowScan writes `shadowscan.json` into the project, then
  `main` scans the project and reads it.
- **Pair with the change**: the same, with pull request 258 at `bdde1f94`, which names
  a model when the scan reads its identifier at the file and line the report cites.

```sh
BENCH=/path/to/that/tree/benchmarks/aibom-bench \
SHADOWSCAN=/venv/bin/shadowscan PYTHON=/venv/bin/python \
MAIN_SRC=/checkout-of-main/src PR_SRC=/checkout-of-the-change/src \
OUT=/tmp/pair ./run_pair.sh
python3 -I score_pair.py /path/to/that/tree/benchmarks/aibom-bench /tmp/pair
```

A component counts when that tree's `detect` matches it in the tool's outputs after
its `strip_coverage` (its strict mode). `results/hits.json` holds what matched for
every component.

## Results

Components identified, by that tree's classes.

Corpus A, 76 components:

| Class | Components | SymBiote alone | ShadowScan alone | Pair on `main` | Pair with the change |
| --- | ---: | ---: | ---: | ---: | ---: |
| mcp-server | 10 | 7 | 9 | 7 | 7 |
| tool | 3 | 3 | 2 | 3 | 3 |
| skill | 2 | 2 | 2 | 2 | 2 |
| prompt | 14 | 9 | 9 | 9 | 9 |
| model | 13 | 0 | 7 | 0 | 6 |
| model-file | 6 | 5 | 0 | 5 | 5 |
| dataset | 6 | 0 | 1 | 0 | 0 |
| training | 2 | 0 | 0 | 0 | 0 |
| vector-store | 3 | 3 | 3 | 3 | 3 |
| a2a | 1 | 1 | 1 | 1 | 1 |
| agent-config | 3 | 1 | 1 | 1 | 1 |
| ci-agent | 1 | 0 | 1 | 0 | 0 |
| container | 4 | 2 | 2 | 2 | 2 |
| package | 6 | 5 | 6 | 5 | 5 |
| guardrail | 2 | 0 | 0 | 0 | 0 |
| All | 76 | 38 | 44 | 38 | 44 |

Corpus B, 53 components:

| Class | Components | SymBiote alone | ShadowScan alone | Pair on `main` | Pair with the change |
| --- | ---: | ---: | ---: | ---: | ---: |
| mcp-server | 6 | 4 | 5 | 4 | 4 |
| tool | 3 | 2 | 2 | 2 | 2 |
| prompt | 7 | 2 | 4 | 2 | 2 |
| model | 12 | 1 | 9 | 1 | 10 |
| model-file | 5 | 4 | 0 | 4 | 4 |
| dataset | 4 | 0 | 0 | 0 | 0 |
| training | 2 | 0 | 0 | 0 | 0 |
| vector-store | 2 | 1 | 1 | 1 | 1 |
| agent-config | 2 | 0 | 1 | 0 | 0 |
| ci-agent | 1 | 0 | 1 | 0 | 0 |
| container | 3 | 0 | 2 | 0 | 0 |
| package | 5 | 3 | 5 | 3 | 3 |
| guardrail | 1 | 0 | 1 | 0 | 0 |
| All | 53 | 17 | 31 | 17 | 26 |

## How to read them

- **SymBiote alone reproduces that tree's own counts** in every class of both
  corpora, so the two harnesses agree on the baseline.
- **Today's import adds nothing a reader can identify.** The pair on `main` equals
  SymBiote alone in every class: imported components are named by a hash.
- **The change carries the models ShadowScan cites.** Models go from 0 to 6 of 13 on
  corpus A and from 1 to 10 of 12 on corpus B. Every one is a component named by the
  identifier. The pair reports no decoy that SymBiote alone does not.
- **Three matches on corpus B are not counted.** The matcher is textual, and
  `prompts/judge.yaml`, `openai/assistant.json` and `n8n/weekly-digest.json` appear
  as the cited location of a model, not as a prompt or an agent configuration. The
  raw count for that column is 29; `score_pair.py` lists the three.
- **The run found a defect in the change, since fixed.** ShadowScan 0.1.4 labels a
  Bedrock guardrail name in Terraform as model evidence, and the first version named
  it as a model. `bdde1f94` names a Bedrock resource only when its kind is a model's
  and counts the rest as unconfirmed.
- **What ShadowScan's report holds and the import still drops.** On A: two MCP
  servers, two inline prompts, one dataset, one CI agent, one package, and one model
  that appears only in a quoted source line (`llama3.2`). On B: one MCP server, one
  CI agent, two images and two packages, besides the three files and the guardrail
  above. Its findings are of kind `agent-config` (7 on A, 5 on B), `mcp-server` (6,
  4), `agent` (2, 1), `framework-usage` (1, 2), `infra` (1, 2), `secret` (1, 1) and
  `workflow` (0, 1); the import maps `agent` and `mcp-server` today.

## Limits

- One run on one machine. The corpora and the match rules belong to another author;
  nothing here was tuned to them, and nothing in them was changed.
- The ShadowScan-alone column is raw text matching on its report and was not
  reviewed for incidental matches. Read it as an upper bound.
- A merged `scan` writes no SARIF on either tree ("SARIF cannot preserve imported
  discovery coverage"), so the pair columns are scored on the native, CycloneDX and
  SPDX outputs.
- ShadowScan's repository surface is the only one of its surfaces these corpora
  exercise.
