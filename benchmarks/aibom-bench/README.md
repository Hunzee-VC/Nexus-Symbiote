# AIBOM-Bench

A tool-neutral, executable benchmark for AI bill-of-materials generators. It scores
how completely a tool inventories the AI supply chain of a repository (data, models,
MCP servers and tool definitions, skills, instruction files, hooks, plugins, agents)
and how safely it behaves when that repository is hostile.

- [`SPEC.md`](SPEC.md): what is measured, why, how it is scored, and the threats to validity.
- [`CATALOG.md`](CATALOG.md): every case, with its weight and attribute checks.

This directory is self-contained. It imports nothing from `nexus_symbiote`; Nexus
SymBiote is graded as one tool among the others.

## Run it

Prerequisites: Linux, root on a **disposable** machine or VM (the runner uses
`unshare -n` and `setpriv`), `strace`, Python 3.11+, and each tool you want to grade.
The corpus contains live hostile payloads, so do not generate it on a workstation.

1. Create the unprivileged sandbox user. Tools run as this user, so they cannot write
   the corpus or the results of other tools:

   ```bash
   useradd --system --create-home --home-dir /opt/aibom-bench/home --shell /usr/sbin/nologin bench
   ```

2. Install the tools under one root, for example `/opt/aibom-bench/tools`, following
   the `install` field of each entry in [`tools.json`](tools.json). Install PyPI tools
   from wheels only (`--only-binary=:all:`) and npm tools with `--ignore-scripts`, so
   that no package code runs at install time.

3. Generate the corpus. The default seed reproduces the published results. Use your own
   seed for an independent holdout run:

   ```bash
   python3 generate.py --out /opt/aibom-bench/corpus --seed 20261118
   ```

   Expected: `corpus /opt/aibom-bench/corpus seed=20261118 items=115 digest=...`

4. Run every tool over every scenario in the sandbox (about 45 minutes for all ten):

   ```bash
   python3 run.py --corpus /opt/aibom-bench/corpus --tools tools.json --tools-root /opt/aibom-bench/tools --runs /opt/aibom-bench/runs
   ```

   Each line shows the tool, the scenario, the exit codes of its commands, the elapsed
   time, and any canary files a payload wrote. A non-empty `canaries=[...]` means the
   tool executed attacker-controlled code.

5. Score:

   ```bash
   python3 score.py --corpus /opt/aibom-bench/corpus --runs /opt/aibom-bench/runs --tools tools.json --out results
   ```

   `results/results.json` holds per-item evidence for every tool; `results/scorecard.md`
   is the summary table. CycloneDX schema validation needs `cyclonedx-python-lib[validation]`
   importable by the Python that runs `score.py`.

## Add a tool

Add an entry to `tools.json` with its documented, most complete repository-scan
command(s), a `default_commands` entry with the plain invocation (used only to observe
network attempts), its install command, and the domains its own documentation claims
(`declared_scope`). Do not add a per-tool parser: if the tool's output is valid
CycloneDX, SPDX, SARIF or JSON and is read incorrectly, fix the generic reader in
`score.py` and re-score every tool.

## Security considerations

- The corpus includes a pickle and a PyTorch checkpoint that write files when loaded, an
  MCP config and project build scripts that do the same when executed, a 3 GiB
  decompression bomb, and symbolic links out of the scenario. Generate and scan it only
  inside a disposable sandbox.
- The literal credentials in the corpus are random strings in real token formats. They
  are generated at run time and never committed. Do not paste them anywhere: secret
  scanners will flag them.
- The runner removes network access with a network namespace instead of trusting a
  tool's `--offline` flag, and records every `connect()` attempt.
