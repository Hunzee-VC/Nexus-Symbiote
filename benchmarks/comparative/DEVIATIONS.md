# Deviations from the registered method

The corpus, the scoring rules, the weights and the grade bands of version 1.0.0 were registered in commit `65859db`, before any tool was run on the corpus. This page lists every change made after that commit: what changed, why, and what it did to each tool's score.

A deviation is recorded even when it changes no score. A change to a case or a label also changes the corpus digest pinned in `bench/__init__.py`.

## Before registration

These choices were made while the adapters were developed against a smoke project that is not part of the corpus. They are listed so that the registered state can be understood, not because they changed a result.

| Choice | Reason |
| --- | --- |
| The binary control file is a PNG image, not a `.bin` file | Two tools treated a `.bin` file of random bytes as model weights. `.bin` is a real model-weight extension, so it could not serve as a file with no AI content |
| agent-bom runs with `--offline --no-scan` | Offline, it reports a scan without its vulnerability database as incomplete and lists fewer components; vulnerability matching is outside this round for every tool |
| Output files are named `bom.cdx.json`, `findings.sarif` and `native.json` | agent-bom refuses to write SARIF to a file without a `.sarif` extension |

## After registration: round of 2026-11-17

Five changes were made after the first pass over the corpus, each because the first results showed the benchmark measuring something other than what its method says. None was made to move a particular tool, and each is applied to every tool. The table gives every composite score at each step, so the effect of each change can be checked.

| Configuration | As registered | After 1 | After 2 | After 3 | After 4 and 5 (final) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Nexus SymBiote a13b622 (unreleased) | 54.37 | 54.16 | 54.16 | 54.16 | 54.16 |
| cdxgen (repository command) 13.8.0 | not run | not run | not run | not run | 38.61 |
| agent-bom 0.115.3 | 37.42 | 37.42 | 37.42 | 37.42 | 37.42 |
| Nexus SymBiote 0.1.0 | 36.51 | 36.51 | 36.51 | 36.51 | 36.51 |
| Trusera ai-bom 3.6.0 | 30.25 | 30.25 | 30.25 | 30.25 | 30.25 |
| AIsbom 1.7.0 | 14.16 | 14.16 | 16.22 | 19.82 | 19.82 |
| Syft 1.57.2 | 14.30 | 14.30 | 14.30 | 18.30 | 18.30 |
| cdxgen (aibom command) 13.8.0 | 13.72 | 13.72 | 13.72 | 17.72 | 17.72 |
| xbom 0.0.3 | 0.25 | 0.25 | 0.25 | 0.25 | 0.25 |

### 1. Attributes and relationships are read from a component's own record

**Registered rule.** Any element that named a label counted for its attributes, and two components were related when one element named both.

**Problem.** One tool emits an element for the agent that refers to every tool, model and instruction file it uses. That element names every label of the case, so it satisfied the relationship rule for any pair, and it could lend one component's facts to another.

**Change.** A label's own record is the found element that names the fewest labels of the case. Attributes, the standard-type check and relationships are read from own records. Two components are related when the own record of one names the other, by nesting, by `dependencies`, or by a `bom-ref` reference.

**Effect.** Nexus SymBiote a13b622: 54.37 to 54.16. No other score changed.

### 2. The digest of a component's file identifies it

**Registered rule.** A label was named only by its tokens.

**Problem.** Some labels are identified by a directory name, such as `sentiment-distil-v2` for `models/sentiment-distil-v2/model.safetensors`. A tool that records the file as `model.safetensors` with its SHA-256 has identified the artifact exactly and was not credited.

**Change.** An element also names a label when it carries the SHA-256 digest of the label's file. The generic-signature rule still applies, so listing every file with its digest earns nothing.

**Effect.** AIsbom: 14.16 to 16.22. No other score changed.

### 3. Hostile cases that target model files gained a model-file survivor

**Registered corpus.** Every hostile case had one survivor, an MCP server.

**Problem.** Five hostile cases attack model parsing or model paths. A tool that reads model files and not MCP configuration parsed the hostile files, and was recorded as not engaged because it could not find the only survivor.

**Change.** Cases `h04-symlink-escape`, `h06-malformed-inputs`, `h07-parser-bombs`, `h10-filename-injection` and `h13-special-files` each hold a valid SafeTensors file with its own label. The corpus digest changed from `935f70a418d8cfa114e6b805a1915e678b89b8386f1386a3bd083c5a16408f8c` to `93cf36ee3a2fbc24f4502c124f0686a086a214e0cec6601ea62d6f42174694fb`. The five cases were run again for every tool.

**Effect.** AIsbom: 16.22 to 19.82. Syft: 14.30 to 18.30. cdxgen (aibom command): 13.72 to 17.72. No other score changed.

### 4. cdxgen is also run with its documented repository command

**Registered adapter.** `aibom -o <file> .`, which the cdxgen README names for AI-BOMs.

**Problem.** `aibom` selects the `ai` project type only. In the first pass it reported no MCP server from `.mcp.json` and no package from any manifest. The same README gives a second command for the same task, "Generate and audit an AI-BOM from the current repository": `cdxgen -r --include-formulation -o <file> --bom-audit --bom-audit-categories ai-bom .`, which detects every project type.

**Change.** Both commands are run and reported as two configurations. The method now says that every documented command for the task is run.

**Effect.** A new row. The registered row is unchanged.

### 5. The limit per run is 300 seconds, not 120

**Registered rule.** A run was stopped after 120 seconds.

**Problem.** Four runs hit the limit. One was cdxgen's repository command on `t04-typescript-mcp-server`: without a network, its `npm install` retries for about two minutes before it continues. The other three were Trusera ai-bom on `h13-special-files`.

**Change.** The limit is 300 seconds for every run. The four runs were repeated. No other run came near either limit; the slowest took 84 seconds.

**Effect.** cdxgen (repository command) finished in 144 seconds and gained two labels: 37.30 to 38.61. Trusera ai-bom hit the new limit in all three formats; its score did not change.

### 6. Reporting changes with no effect on any score

- The discovery listing shows a component's own record instead of the first element that names it.
- The report counts elements that mention a control file.
- `environment.json` lists every run session, so re-runs are visible.

## Results that the changes did not touch

For transparency about what was looked at and left alone:

- **Nexus SymBiote 0.1.0 scores 0 on reproducibility and change sensitivity.** Two scans of the same project differ in an embedded digest and an embedded document, which the lenient comparison cannot remove without also removing content digests. The rule was not loosened.
- **cdxgen labels the Markdown and JSON control files as prompt configuration files**, so instruction and prompt files that it renders the same way are not counted as found. The generic-signature rule was not loosened.
- **Nexus SymBiote raises the same statement for a data-only pickle and an executing one**, so it earns nothing on the three deserialization pairs. The pair rule was not loosened.
