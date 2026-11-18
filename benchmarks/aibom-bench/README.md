# AIBOM-Bench

A cross-tool benchmark for AI bill-of-materials generators. It builds one synthetic agentic
application with 91 labelled components, runs each tool against it offline, and scores
what the tool's output actually contains: models, data, tools and agent components (MCP
servers, skills, instruction files, prompts, hooks, permissions). It also plants risks,
changes and hostile input, and measures whether the scanner itself is safe to point at an
untrusted repository.

This directory is separate from the [security regression corpus](../README.md) and the
[inventory regression corpus](../inventory/README.md). Those test Nexus SymBiote against
its own contracts and support no ranking. This one compares tools.

- [SPEC.md](SPEC.md): what is measured, the weights, and the threats to validity.
- [Results of 18 November 2026](results/2026-11-18/RESULTS.md): ten tools, graded.

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

## Run it

Build the corpus and read the ground truth:

```bash
python benchmarks/aibom-bench/bench.py build /tmp/aibom-corpus
```

The last line printed is the corpus digest. For corpus 1.0.0 with the default canary
directory it is `6221015927c286967f2b50193d900c76c1bd79dafceea74ee61cd7a02ff39ef2`.

Run every adapter against every variant, then score:

```bash
python benchmarks/aibom-bench/bench.py run --tools-root TOOLS --work WORK
```

```bash
python benchmarks/aibom-bench/bench.py score --work WORK --schemas SCHEMAS --out OUT
```

`--tool <slug>` limits either command to one tool. `OUT/results.json` holds every
per-component verdict; `OUT/RESULTS.md` is the summary table.

## Security considerations

- **The corpus is hostile on purpose.** It contains a PyTorch archive whose pickle calls
  `os.system`, an MCP entry whose launch command is a shell script, and hook, skill, npm
  and `setup.py` scripts. Each only creates a marker file under `/tmp/aibom-bench/canary`.
  Build it in a scratch directory and do not load, install or launch anything in it.
- **The tools are third-party code.** The harness gives them no network, no credentials
  and an empty environment. Install them the same way: in a throwaway machine, with no
  tokens in the environment.
- **Secrets in the corpus are synthetic.** They are derived from a hash and match provider
  formats so that redaction can be tested. They grant nothing.
- **Do not run the harness on a machine you care about.** A tool that fails a hostile case
  may write outside its output directory.

## Add a tool

Write `tools/<slug>.json`: the pinned install commands, the entry point, and one `scans`
entry per output format with `{bin}`, `{target}` and `{out}` placeholders. Add a `diff`
entry if the tool compares two of its own outputs. Write `assessments/<slug>.json` for the
seven assessed criteria, each with a level, an evidence tier and the evidence. Run the
tool, review every risk verdict in `results.json`, and record corrections with a reason
under `adjudication`.
