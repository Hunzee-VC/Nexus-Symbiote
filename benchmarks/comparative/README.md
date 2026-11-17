# Comparative AI-BOM benchmark

Runs AI-BOM generators on the same generated projects and compares what each writes with what is there: models, data, tools and agent components such as MCP servers, skills and instruction files. It also checks how each tool handles a hostile repository, whether its output is reproducible, and whether the output changes when the project does.

- [Method](METHOD.md): what is measured, every scoring rule, and what the numbers do not show. Read it before quoting a score.
- [Deviations](DEVIATIONS.md): every change made after the method was registered.
- [Results](results/README.md): one directory per recorded round, with a report, notes and the full scorecard. The latest is the [round of 2026-11-17](results/2026-11-17/REPORT.md).

This is a first-party benchmark with a synthetic corpus. It supports comparisons on this corpus only, and no percentile or market ranking.

## Requirements

- Linux with `unshare` from util-linux, run as root or with `CAP_SYS_ADMIN`. Each tool runs in new network and mount namespaces.
- [uv](https://docs.astral.sh/uv/), Python 3.13, Node.js 22 with npm, and Go 1.24 or newer, to install the tools.
- This repository's development environment (`make install-locked`). The scorer validates documents with `cyclonedx-python-lib`, which that environment holds.

## Run a round

Install the pinned tools. This step needs the network; nothing later does.

```bash
benchmarks/comparative/tools/install.sh "$HOME/aibom-bench-tools"
```

Check the corpus against its labels. The command prints the corpus size and digest, and exits 1 on any inconsistency.

```bash
cd benchmarks/comparative && python -m bench check
```

```text
41 discovery cases, 128 expected components, 14 risk pairs, 15 hostile cases, 14 mutations
corpus digest 93cf36ee3a2fbc24f4502c124f0686a086a214e0cec6601ea62d6f42174694fb
```

Run every tool on every case. About 1,550 runs; allow twenty minutes on four cores. Runs with a package manager retry against the missing network and take longest.

```bash
python -m bench run --tools-root "$HOME/aibom-bench-tools" --work "$HOME/aibom-bench-work"
```

Score the runs and render the report. The scorer also scores the two calibration tools, which must print 100 and 0.

```bash
python -m bench score --work "$HOME/aibom-bench-work" --out results/local/scorecard.json
```

```bash
python -m bench report --results results/local/scorecard.json --out results/local/REPORT.md
```

`--tool ID` on `run` and `score` selects tools; repeat it for several. The identifiers are in `bench/tools.py`.

## Security considerations

- **The corpus is hostile on purpose.** It holds pickles that run a command when loaded, MCP servers and hooks whose commands write a canary, package manifests with install scripts, file names that are shell commands, and links that point outside the project. The benchmark never loads, renders or launches any of them, and each command only creates an empty file. `python -m bench materialize` writes the same files to a directory you choose; do not open that directory with a coding agent or run a package manager in it.
- **Run tools only through `python -m bench run`.** The sandbox gives a tool no network, an empty home directory and a cleared environment, so it cannot read your agent configuration or send anything out. Outside it, several of these tools send telemetry by default, and at least one does so on `--help`.
- **Tools run with your privileges inside the namespaces.** The sandbox isolates the network and the paths under `/mnt`; it is not a security boundary against a malicious tool. Install only the pinned versions, in a disposable environment.
- **Credential canaries are derived, not stored.** No token-shaped string is committed. A materialized corpus contains them; they are not valid credentials.
- **Results name real projects.** A result against another tool is a statement about a pinned version, run with its defaults, on one corpus. The hostile cases show how a tool behaves on a hostile repository; tell the project what you observed. Anything that looks exploitable beyond that is a vulnerability: report it to the project privately before you publish it.

## Layout

| Path | Content |
| --- | --- |
| `bench/cases_*.py` | The corpus: cases, labels, decoys, risk pairs, hostile cases |
| `bench/corpus.py` | Mutations, materialization, the digest and the self-check |
| `bench/tools.py` | One adapter per tool: pinned version, exact command, nothing else |
| `bench/runner.py` | The sandbox and what each run records |
| `bench/cdx.py`, `bench/score.py` | How documents are read and scored, identically for every tool |
| `bench/baselines.py` | The oracle and null calibration tools |
| `bench/report.py` | The report, rendered from the scorecard |
| `tools/` | The install script and lockfiles |
| `results/` | Recorded rounds |

The tests are in `tests/test_comparative_benchmark.py` and run with the project's suite; they start no third-party tool.

## Add a tool or dispute a result

Both are described under [changing the benchmark](METHOD.md#changing-the-benchmark).
