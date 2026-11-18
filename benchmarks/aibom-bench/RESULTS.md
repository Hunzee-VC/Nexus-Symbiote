# AIBOM-Bench 1.0 results

Run on 2026-11-18. Seed `20261118`, corpus digest `e771ea4d7f519c31`, 126 scored items in 15
scenarios. Every tool ran its documented safe configuration for untrusted repositories,
offline, and its plain documented invocation on every scenario. Both ran in the same
sandbox: network, PID and mount namespaces, an unprivileged user, and a fresh writable
checkout. A positive control that executes every payload ran in that sandbox too. It
tripped all seven safety probes, so every safety verdict below comes from a probe that
was shown to work. Method and scoring: [`SPEC.md`](SPEC.md). Every case: [`CATALOG.md`](CATALOG.md).
Per-item evidence: [`results/results.json`](results/results.json).

## Scorecard

Ranked by grade after gates, then by score. Score is coverage of the whole AI supply
chain (0–100). In-scope restricts it to the domains each tool's own documentation
claims. Risk findings is the share of finding points earned. Domain columns are
percentages.

| # | Tool | Version | Grade | Score | In-scope | Risk findings | MCP | Tool defs | Skills | Agents | Models | Data | Pkgs | Standards | Safety | Gates |
|--:|---|---|:-:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|---|
| 1 | Nexus SymBiote | 0.2.0 | **C** | 65.3 | 65.3 | 44 | 82 | 47 | 72 | 39 | 55 | 0 | 91 | 77 | 100 | – |
| 2 | agent-bom | 0.115.4 | **D** | 51.2 | 51.2 | 36 | 72 | 0 | 66 | 22 | 55 | 0 | 91 | 69 | 67 | – |
| 3 | Cisco AI BOM ¹ | 1.10.1 | **F** (D before gates) | 50.3 | 47.7 | 0 | 59 | 40 | 28 | 28 | 43 | 25 | 91 | 78 | 67 | executes MCP launch commands → F; reads through escaping symlinks → C |
| 4 | AIROM | 0.4.7 | **F** | 39.4 | 60.8 | 19 | 0 | 13 | 3 | 11 | 66 | 58 | 91 | 89 | 53 | – |
| 5 | OWASP cdxgen ² | 12.9.2 | **F** | 35.0 | 38.0 | 14 | 49 | 13 | 31 | 11 | 41 | 0 | 91 | 72 | 17 | default mode builds the scanned project → F |
| 6 | Trusera ai-bom | 3.6.0 | **F** | 34.5 | 33.9 | 0 | 41 | 27 | 0 | 0 | 29 | 0 | 36 | 52 | 92 | reads through escaping symlinks → C |
| 7 | aibom-scanner | 1.3.5 | **F** | 29.8 | 38.5 | 14 | 77 | 0 | 0 | 6 | 3 | 0 | 91 | 17 | 78 | – |
| 8 | AIsbom | 1.7.0 | **F** | 27.7 | 60.1 | 22 | 0 | 0 | 0 | 0 | 59 | 0 | 54 | 73 | 53 | – |
| 9 | Anchore Syft | 1.57.2 | **F** | 25.1 | 52.9 | 0 | 0 | 0 | 0 | 0 | 36 | 0 | 91 | 63 | 58 | – |
| 10 | AIBoMGen CLI ³ | 0.3.0 | **F** | 11.7 | 29.3 | 0 | 0 | 0 | 9 | 0 | 17 | 0 | 0 | 65 | 0 | – |
| – | OWASP AIBOM Generator ⁴ | main, 2026-10-17 | N/R | – | – | – | – | – | – | – | – | – | – | – | – | – |

¹ v1.10.1 refuses to run without an LLM. The endpoint pointed at an unreachable port, so
these are its deterministic detections, each marked `pending_agent_review`, with no LLM
enrichment. Treat the grade as provisional. It was installed with the documented
`agentic`, `analysis`, `security` and `llm-openai` extras.
² Its README AI-BOM command. The benchmark run adds the documented `--no-install-deps`; the
plain run does not.
³ Reads model metadata from the Hugging Face Hub, which the sandbox cannot reach.
⁴ Accepts only a Hugging Face model ID and needs the live Hub API. It cannot scan a
repository, so it is reported as not run, not as failed.

Synthetic calibration tools, not ranked:

| Tool | Score |
|---|---:|
| Oracle | 96.5 |
| File-dumping "cat" | 8.5 |
| Path lister | 1.9 |
| Empty | 0.0 |
| Positive control | F, with all seven safety probes and every gate tripped |

## What matters, in order

1. **Two tools run attacker-controlled code when pointed at a repository.**
   - **cdxgen's** documented AI-BOM command (`cdxgen -r --include-formulation --bom-audit
     --bom-audit-categories ai-bom`) installs the project's dependencies by default. In
     the sandbox it ran `python -m pip install <checkout>`. pip built the project and
     imported its in-tree PEP 517 backend, which wrote the canary with no network at
     all. It also ran `pip install -r <checkout>/requirements.txt`.
   - **Cisco AI BOM**, with its documented `security` extra, passes every discovered MCP
     config to `cisco-ai-mcp-scanner`. That component starts each declared stdio server
     to list its tools. It ran the planted `sh -c "touch …/canary/mcp"`, and `npx -y …`
     and `docker run …` from the MCP fixture.
   - In a CI job scanning a pull request, either behaviour is remote code execution.
   - **Mitigation:** cdxgen has a one-flag fix (`--no-install-deps`, with which the
     benchmark run stayed clean). For Cisco, install it without the `security` extra.
     An earlier run of this benchmark without it started no servers.

2. **Two tools disclose files outside the checkout.** Cisco AI BOM and Trusera ai-bom
   followed `.cursor/mcp.json`, a symlink to a file outside the scanned directory, and
   inventoried the server defined there. A repository can make them read and publish
   files from the CI host.

3. **Nobody reads the attack.** No tool flagged any of:
   - the tool description containing the instruction to read `~/.ssh/id_rsa` (T03F)
   - the skill whose script pipes `~/.aws/credentials` to curl and `curl | sh` (K02F)
   - the typosquat `langchian` (P06F)
   - the unpinned Hugging Face revision (R02F)

   The best risk-finding share is 44% (Nexus SymBiote). Inventory is ahead of detection
   across the field.

4. **Data and agents are the blind spots.**
   - Seven of ten tools score 0% on data, and no tool names the Chroma collection or
     Pinecone index (D04, D05). Only AIROM records the pinned Hugging Face dataset (D01).
   - No tool found the OpenAI Agents SDK agent (A01), and each other agent framework is
     covered by at most two tools.
   - No tool inventoried the Claude Code plugin manifest (K11) or the hook command's
     destination (K10).

5. **Specialists are good in their lane.** Their in-scope scores are 53–60:
   - **AIsbom** is the only tool that names the Keras Lambda layer.
   - **AIROM** is the only one with the pinned dataset, and has the best standards output.
   - **Syft** has strong package and model-file coverage.

   None of them covers MCP, skills or agents, so none can be the only AI-BOM in an
   agentic codebase.

6. **Hygiene:**
   - Six tools try the network in their plain invocation: agent-bom, Cisco AI BOM, cdxgen,
     AIsbom, AIROM and AIBoMGen (DNS to the configured resolvers).
   - agent-bom and Cisco AI BOM echo planted terminal escape sequences (window title,
     OSC 52) raw to stderr.
   - No tool leaked the planted literal credentials into any output.
   - agent-bom aborts its whole scan on a 200 000-deep JSON config ("maximum recursion depth
     exceeded") and writes no inventory for that scenario.

## Tool notes

**Nexus SymBiote (C, 65.3).**
- *Strengths:*
  - Widest coverage of MCP client config dialects: Claude Code, Cursor, VS Code, Codex
    TOML, Gemini and Kiro, with pins, digests, remote endpoints and launcher packages.
  - Targeted findings for unpinned `npx` launches, `:latest` images, shell-wrapped launches,
    GGUF template payloads, invisible Unicode in rules, and hooks that contact the network.
  - The only tool to record the CLAUDE.md `@import`, the subagent, slash commands and
    prompt files together.
  - Perfect safety: no execution, symlinks refused, credentials redacted, escapes
    neutralised, no egress, byte-identical reruns.
- *Gaps:*
  - No datasets or RAG stores.
  - No model references in code.
  - Tool descriptions not checked for poisoning.
  - Literal credentials redacted but never flagged.
  - Drift visible only at file level (no per-tool fingerprint).
  - No agent SDK definitions.

**agent-bom (D, 51.2).**
- *Strengths:*
  - Strong MCP and skills inventory.
  - Flags literal MCP secrets, invisible-Unicode instructions and malicious pickle payloads.
  - With its documented `--model-files`, `--model-provenance` and `--dataset-cards`
    discovery, a solid model inventory that sees through the disguised pickle.
- *Gaps:*
  - No in-repo MCP tool definitions (tool defs 0%).
  - No datasets.
  - The exfiltrating skill gets only low-severity "no capability declaration" notes.
- *Operations:*
  - Crashes on deeply nested JSON.
  - Echoes raw escape sequences.
  - Attempts DNS by default.

**Cisco AI BOM (F, D before gates, 50.3).**
- *Strengths:*
  - Broad deterministic discovery: FastMCP servers and tools, an A2A card and client,
    hosted fine-tune IDs, data files.
  - Valid CycloneDX and SPDX 3 with ML-BOM types.
- *Gaps:* no scored risk findings. Its SARIF holds `level: note` inventory entries;
  the only risk flag is one low "unpinned model" note on a hosted model ID.
- *Safety:*
  - Gated for starting declared MCP servers (`security` extra).
  - Gated for following escaping symlinks.
  - Echoes escape sequences.
  - Its default mode tries to reach an LLM provider, which sends repository content
    off-host by design.

**AIROM (F, 39.4; in-scope 60.8).**
- *Strengths:*
  - Best standards output.
  - The only tool with the pinned Hugging Face dataset.
  - Names the malicious pickle callable and the GGUF template gadget.
- *Gaps:* no MCP, skills or agent coverage.

**OWASP cdxgen (F, 35.0).**
- *Strengths:*
  - Mature CycloneDX and SPDX production with formulation.
  - Its bom-audit flags literal MCP credentials.
  - Finds the Ollama Modelfile, Bedrock ARN and CrewAI YAML agent.
- *Gaps:*
  - Records a dataset card as a model.
  - Calls an environment-referenced credential "inline" (a false positive).
  - Reports a UI data-model JSON as an AI prompt config (a false positive).
- *Safety:* gated for building the scanned project in default mode.

**Trusera ai-bom (F, 34.5).**
- *Strengths:*
  - MCP servers.
  - In-repo tool definitions, typed under the wrong framework (CrewAI).
  - Clean output hygiene.
- *Gaps:* no findings, skills, agents or data.
- *Safety:* gated for following escaping symlinks.

**aibom-scanner (F, 29.8).**
- *Strengths:* good MCP inventory, with a specific "launched without a pinned version"
  finding for exactly the unpinned and `:latest` servers.
- *Gaps:*
  - Other risks are repository-level governance statements that name every server.
  - No standards output beyond SARIF (standards 17%).
  - No models, data or skills.

**AIsbom (F, 27.7; in-scope 60.1).**
- *Strengths:* precise model-file security: names `os.system` and `builtins.open` in
  pickles, the Keras Lambda layer, and the GGUF sandbox escape.
- *Gaps:*
  - Nothing outside model files and manifests.
  - Default mode attempts network.

**Anchore Syft (F, 25.1; in-scope 52.9).**
- *Strengths:*
  - Excellent package inventory.
  - GGUF and SafeTensors model files with digests.
- *Gaps:* no AI-specific risk analysis or agentic surface. That's expected for a general
  SBOM tool.

**AIBoMGen CLI (F, 11.7).**
- Built around Hugging Face Hub lookups, which this offline sandbox cannot serve.
- It also reads skill script paths as Hugging Face model IDs (`pkg:huggingface/scripts/...`).

## Nexus SymBiote: what to fix first

Ranked by how much a silent miss hurts a deployment. Item IDs refer to [`CATALOG.md`](CATALOG.md).

1. **Flag instruction-like text in MCP tool descriptions and docstrings (T03F, T07F).** The
   tools are already enumerated by AST. The poisoned description itself is the attack, and
   no tool in the field catches it, so this would be a clear lead.
2. **Raise a finding for literal credentials it already redacts (C06F, C07F),** and keep the
   variable names of referenced credentials (C05 `credential_ref`).
3. **Analyse bundled skill scripts (K02F).** Look for credential-file reads, `curl | sh`,
   and posts to external hosts.
4. **Datasets and retrieval stores (D01–D05).**
   - `load_dataset` with its revision, `data_files`, dataset cards, and vector-store
     collection and index names in code.
   - `scanners/rag.py` only recognises fixed configuration file names
     (`RAG_CONFIG_PATTERNS`), so `rag/config.yaml` is never read.
5. **Model references in code and config (R01–R07), and model-card lineage (M02).**
   - `from_pretrained` and its `revision`, `SentenceTransformer`, hosted and fine-tuned
     IDs, Bedrock ARNs.
   - An unpinned-revision finding (R02F).
   - `pkg:huggingface` package URLs.
6. **A per-tool definition digest (T08),** so drift alerts name the tool that changed
   rather than the source file.
7. **Agent definitions from SDK code and config (A01–A03, A05–A07).**
8. **Smaller items:**
   - Declared FastMCP and `McpServer` names (T01, T05).
   - Plugin manifests below the repository root (K11).
   - Hook command destinations (K10).
   - The Ollama Modelfile (M10).
   - Keras Lambda layers (M08F).
   - Naming the dangerous callable in pickles (M06G, X01F).

## How these grades were checked

- **Design review.**
  - Five independent critics reviewed threat coverage, scoring validity, standards rigor,
    sandbox validity and tool fairness.
  - Every finding that would change a grade went to two skeptics who tried to refute it.
  - A final synthesis checked the survivors against this run.
  - Every upheld defect was fixed generically, and the full run repeated: commits
    `444b371` to `3d67c25`.
- **Fairness corrections that changed grades.** agent-bom's working directory now lets its
  model scan run (it rose from F to D). cdxgen uses its README command in safe mode. Cisco
  AI BOM got its documented extras.
- **Verdict audit.**
  - For every missed item, each tool's raw output was searched for the item's token, and
    every hit was judged by hand.
  - The text behind every earned finding was read.
  - Generic fixes that came out of this, applied to every tool and recalibrated:
    - A name-like value may state its own kind.
    - Findings on generically named files are attributed by the file's digest.
    - A severity-less annotation is informational.
    - An annotation's severity must be labelled as one.
    - A risk property whose value is `none` is not a finding.
    - Paths never type a record.
    - Attribute checks are read per record.
- **Calibration and positive control.** The four synthetic tools stay where they should.
  The positive control trips every safety probe, and `score.py` refuses to publish if any
  probe stays silent.

Raw outputs are not committed: 90 MB, including live escape sequences and strace logs.
`run.py` regenerates them from this tree.

## Limits

These grades describe the listed versions on a synthetic corpus, offline, in one run. The
main threats to validity are in [`SPEC.md`](SPEC.md#threats-to-validity):

- synthetic fixtures
- kind evidence based on a word list
- keyword-based finding classes
- weights that are judgement
- per-process memory accounting
- degraded modes for LLM- and Hub-dependent tools
- the benchmark was written inside the Nexus SymBiote repository

That last point is a conflict of interest. Nexus SymBiote ranks first here, which is
exactly the result that conflict would produce. Run with a private seed
(`generate.py --seed <yours>`) before relying on the ranking.
