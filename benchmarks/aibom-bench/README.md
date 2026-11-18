# AIBOM-Bench

A cross-tool benchmark for AI bill-of-materials generators. It builds one synthetic agentic
application with 92 labelled components, runs each tool against it with no network, and
scores what the tool's output contains: models, data, tools and agent components (MCP
servers, skills, instruction files, prompts, hooks, permissions). It also plants risks,
changes and hostile input, and measures whether the scanner itself is safe to point at an
untrusted repository.

This directory is separate from the [security regression corpus](../README.md) and the
[inventory regression corpus](../inventory/README.md). Those test Nexus SymBiote against
its own contracts and support no ranking. This one compares tools.

- [SPEC.md](SPEC.md): what is measured, the weights, and the threats to validity.
- [CHANGELOG.md](CHANGELOG.md): what version 1.1 changed after an audit of 1.0, and the
  effect on every tool's score.
- [Results of 18 November 2026](results/2026-11-18/RESULTS.md): nine tools graded, one
  not gradable.

> [!IMPORTANT]
> The benchmark was written in the repository of one of the tools it grades. Read
> [Threats to validity](SPEC.md#threats-to-validity) before citing a ranking, and rerun it
> yourself.

## Prerequisites

- Linux, run as root: the harness uses `unshare -n` to remove the network and `strace` to
  record attempted connections.
- Python 3.11 or later with `jsonschema` (installed by `make install-locked`).
- The tools you want to grade, each installed under `TOOLS/<slug>/` as its adapter in
  `tools/<slug>.json` describes.
- The upstream schemas in one directory: `bom-1.4` to `bom-1.7.schema.json`,
  `spdx.schema.json`, `jsf-0.82.schema.json` and `cryptography-defs.schema.json` from the
  CycloneDX specification repository; `sarif-2.1.0.schema.json`; `spdx-2.3.schema.json`;
  and `spdx-3.0.1.schema.json`. A document whose schema is missing is reported invalid.
- A machine doing nothing else. One graded tool bounds parsing by wall-clock time, and its
  output changed under load.

## Run it

Build the corpus and read the ground truth:

```bash
python benchmarks/aibom-bench/bench.py build /tmp/aibom-corpus
```

The last line printed is the corpus digest. For corpus 1.1.0 with the default canary
directory it is `7d99ff052f0f0bec721d6af41caa793b0fbda5b5d719917a335a05b27e5ba9ca`.

Run every adapter against every variant, then score:

```bash
python benchmarks/aibom-bench/bench.py run --tools-root TOOLS --work WORK
```

```bash
python benchmarks/aibom-bench/bench.py score --work WORK --schemas SCHEMAS --out OUT
```

`--tool <slug>` limits either command to one tool. `OUT/results.json` holds every
per-component verdict; `OUT/RESULTS.md` is the summary. A full run of the ten adapters
takes about an hour, most of it fixed waits inside two tools and three 180-second
timeouts.

Check the scorer itself before trusting a result:

```bash
python -m pytest tests/test_aibom_bench.py
```

## Security considerations

- **The corpus is hostile on purpose.** It contains a PyTorch archive whose pickle calls
  `os.system`, an MCP entry whose launch command is a shell script, and hook, skill, npm
  and `setup.py` scripts. Each only creates a marker file under `/tmp/aibom-bench/canary`.
  Build it in a scratch directory and do not load, install or launch anything in it.
- **The tools are third-party code.** Scored scans get no network, no credentials and an
  empty environment. Install the tools the same way: in a throwaway machine, with no
  tokens in the environment.
- **One probe uses the network.** `probe:default-exec` runs each tool's plain command on a
  four-file project with the host's network, so that a tool which resolves dependencies by
  running install steps can do so. It fetches two pinned public packages at most. Do not
  point it at anything else.
- **Secrets in the corpus are synthetic.** They are derived from a hash and match provider
  formats so that redaction can be tested. They grant nothing.
- **Do not run the harness on a machine you care about.** A tool that fails a hostile case
  may write outside its output directory.

## Add a tool

Write `tools/<slug>.json`: the pinned install commands, the entry point, one `scans` entry
per output format with `{bin}`, `{target}` and `{out}` placeholders, and a `default` entry
holding the tool's plain command with no offline or safety flags. Add a `diff` entry if
the tool compares two of its own outputs. Write `assessments/<slug>.json` for the seven
assessed criteria, each with a level, an evidence tier and the evidence. Run the tool,
build the adjudication packet with `aibom_bench.adjudication.build_packet`, and have two
people who have not seen the scores rate it; see
[Adjudication of risk findings](SPEC.md#adjudication-of-risk-findings).
