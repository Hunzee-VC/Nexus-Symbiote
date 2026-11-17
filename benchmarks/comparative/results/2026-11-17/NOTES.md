# Round of 2026-11-17: notes on the results

The [report](REPORT.md) gives the numbers. This page explains the outcomes that a number does not explain, and says what stands behind each statement. Every observation here was checked against the recorded run: the exit code, the console streams, the output file, the canary directory and the project tree. It applies to the pinned version, run with the command in the report, on this corpus.

Read the [limits](../../METHOD.md#what-the-results-do-not-show) first. This is a first-party benchmark on a synthetic corpus.

## How to read the ranking

- **No tool covers the surface.** The best configurations find about half of the 128 labelled components. Every released tool grades F on the registered bands; the bands were fixed before the first run and were not adjusted.
- **Three released configurations are level.** cdxgen's repository command (38.6), agent-bom (37.4) and Nexus SymBiote 0.1.0 (36.5) are within about two points, and their order changes with the weights. Treat them as tied.
- **The first row is not a release.** Nexus SymBiote a13b622 is this repository's development tree. It leads on the composite and is second on inventory alone, where cdxgen's repository command finds 63 components to its 61.
- **Three tools have no score** because they cannot run in this round: Cisco AI BOM needs an LLM provider, the OWASP AIBOM Generator takes a Hugging Face model identifier, and k8s-aibom takes a running cluster.

## Observations by tool

### Nexus SymBiote (0.1.0 and the development tree)

| Observation | Evidence |
| --- | --- |
| It finds nothing on surfaces it has no collector for: models and datasets referenced in code, notebooks, Modelfiles and Kubernetes manifests; function tools declared as JSON; agents defined in framework code; prompt directories; guardrail and memory configuration; n8n workflows; CI agent actions; Go, Java, Rust and Ruby packages; cloud AI resources; endpoint and gateway configuration | Discovery items in `scorecard.json`: 67 of 128 labels missed by the development tree, 86 by 0.1.0 |
| It makes the same statements about a data-only pickle and one that runs a command, and about a Keras file with and without a Lambda layer | `r01`, `r02`, `r03`: identical SARIF results for both twins |
| It raises nothing for credentials written into an MCP server's environment, although it keeps them out of its output | `r07`: identical SARIF results for both twins; no canary credential in any output |
| It raises nothing for a tool description that carries a directive, a skill script that pipes a download to a shell, a model loaded with remote code enabled, or an instruction file that tells the agent to post the environment file | `r08`, `r10`, `r12`, `r13`: the development tree writes no SARIF result for either twin; 0.1.0 shows no difference |
| It passes every hostile check. These are the classes its own audits target, so this is expected and is weaker evidence than a suite written by someone else | Hostile matrix |
| Release 0.1.0 writes a different document on each scan of an unchanged project, so a change cannot be told from noise; the development tree writes identical documents | Repeat of `a01` on 0.1.0: an embedded `sha256:` value and an embedded document differ |

### cdxgen 13.8.0

| Observation | Evidence |
| --- | --- |
| The `aibom` command reports no MCP server from `.mcp.json` and no package from a manifest; the repository command reports both | Discovery by domain: 7 against 23 agent components, 0 against 22 packages |
| The repository command ran code from the scanned project while resolving Python dependencies. cdxgen prints a notice that this can happen and to scan only trusted directories; `npm install` was run with `--ignore-scripts` | `h02`: canary `h02-build-backend` created, and `__pycache__/backend.cpython-313.pyc` written into the project |
| The repository command wrote no document for a project with an empty `package.json`, and none where its own schema validation failed | `h06`: exit 1, `SyntaxError: Unexpected end of JSON input`; `h07`: exit 1, `schema validation failed` |
| Both commands label a Markdown note and a JSON settings file as prompt configuration files, the same way they label `AGENTS.md` and prompt files | 22 control-file elements with `cdx:file:kind=prompt-config-file` |
| The repository command writes analysis files into the scanned project and records a random temporary path in the document | `.chen/*.frag` created in `t03`; `/tmp/cdxgen-venv-*` differs between two scans of `p01` |
| Without a network its dependency installation retries for a long time | `t04`: 144 seconds; `p01`: 25 seconds |

### agent-bom 0.115.3

| Observation | Evidence |
| --- | --- |
| Its CycloneDX export leaves out much of what its own JSON report holds, including skills and instruction files | Mean domain recall 28% in CycloneDX, 51% in its JSON |
| One deeply nested JSON file ends the scan with no document | `h06`, `h07`: exit 1, `maximum recursion depth exceeded while decoding a JSON array` |
| It signals more of the risk pairs than any other tool, including both executing pickles | Risk matrix: 8 of 14 |

### Trusera ai-bom 3.6.0

| Observation | Evidence |
| --- | --- |
| It follows a symbolic link out of the project and inventories the MCP configuration it points to | `h04`: the outside server's name is in its CycloneDX, SARIF and JSON output |
| It does not finish on a project that holds a named pipe and links to device files | `h13`: stopped at the 120-second and again at the 300-second limit, in all three formats |
| Half of its package URLs are not valid package URLs, and a quarter of its documents fail the CycloneDX schema | Conformance: 50% valid package URLs, 16 of 21 documents valid |

### AIsbom 1.7.0

| Observation | Evidence |
| --- | --- |
| It is the only tool that signals all four model-file risk pairs: both executing pickles, the Keras Lambda layer and the template escape | Risk matrix: `r01` to `r04` |
| It follows a symbolic link out of the project and records the digest and header of the file it points to | `h04`: the outside file's SHA-256 is in its document |
| It reads model files and `requirements.txt` only | Discovery by domain: 0 of 70 data, tool and agent labels |

### Syft 1.57.2

| Observation | Evidence |
| --- | --- |
| As a general SBOM generator it finds packages, three of the weight files and one agent component, a CI action | Discovery by domain |
| Every document is schema-valid, with valid package URLs, and identical across repeats and locations | Conformance and reproducibility tables |

### xbom 0.0.3

| Observation | Evidence |
| --- | --- |
| It found one of the 128 labels | Discovery by domain |
| It tries to post usage telemetry on every invocation, including `--help`. The sandbox has no network; outside it, the attempt was refused by this environment's proxy | Console stream of every run: `posthog ... us.i.posthog.com` |

## What a maintainer of a graded tool can do with this

Every case can be written to a directory with `python -m bench materialize`, and each case identifier in the report names the fixture that produced a result. A wrong label or an unfair command is a defect in the benchmark; the [method](../../METHOD.md#changing-the-benchmark) says how to report one.
