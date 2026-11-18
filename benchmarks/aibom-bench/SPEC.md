# AIBOM-Bench specification

Version 1.1.0. This document defines what the benchmark measures, how each criterion is
scored, and what a score does and does not mean. The code is the definition where the two
differ: weights live in `aibom_bench/scoring.py` and the corpus in `aibom_bench/corpus.py`.
[CHANGELOG.md](CHANGELOG.md) lists what changed from 1.0 and why.

- [What an AI-BOM tool is for](#what-an-ai-bom-tool-is-for)
- [Method](#method)
- [The corpus](#the-corpus)
- [Criteria and weights](#criteria-and-weights)
- [The exposure rule](#the-exposure-rule)
- [How each measured criterion is computed](#how-each-measured-criterion-is-computed)
- [Assessed criteria](#assessed-criteria)
- [Adjudication of risk findings](#adjudication-of-risk-findings)
- [Grades](#grades)
- [Validity checks on the scorer](#validity-checks-on-the-scorer)
- [Threats to validity](#threats-to-validity)

## What an AI-BOM tool is for

An AI bill of materials answers four questions about an AI system, and a reader acts on
the answers: what is in it, where did each part come from, what changed since it was last
approved, and what can each part do. The benchmark scores a tool on how well its output
supports those answers for four kinds of component:

| Pillar | Examples in the corpus |
| --- | --- |
| Models | Weight files (GGUF, SafeTensors, ONNX, PyTorch pickle), LoRA adapters, Hugging Face references, hosted API models, models named in Modelfiles, notebooks, Dockerfiles, Kubernetes arguments and configuration |
| Data | Training and evaluation sets, dataset cards, DVC pointers, fine-tuning uploads, vector stores, agent memory, knowledge sources |
| Tools | AI frameworks and SDKs in lockfiles, function tools defined in code, function-calling schemas, MCP tools |
| Agent components | MCP servers in six client formats and in a sub-package, first-party MCP server source, skills, instruction files, prompts, subagents, slash commands, hooks, permissions, plugins, A2A cards, framework agents, guardrails |

A fifth group, infrastructure, covers the container images, endpoints and CI workflows the
components run on.

Three positions shape the weights:

1. **An inventory that misses a component cannot protect it.** Discovery carries the most
   weight, and agent components carry the most weight within it, because that is where
   the tools differ most and where existing software BOMs record nothing.
2. **The scanner reads hostile input.** A repository under review is attacker-controlled.
   A tool that launches a declared MCP server, deserializes a pickle, follows a symlink out
   of the project or prints a committed secret into the BOM has turned a review step into
   an attack path. Scanner safety is scored as heavily as risk analysis.
3. **A claim is not a measurement, and neither is an untested pass.** A capability earns
   full credit only when the harness or the assessor exercised it. A capability known only
   from documentation earns half. A check a tool never faced earns nothing.

## Method

Each tool is installed at a pinned version and run by one harness
(`aibom_bench/runner.py`) with the same wrapper:

- a new network namespace with only loopback, so no connection can leave the host;
- an empty environment with a new, empty `HOME` for every variant, no credentials,
  `NO_COLOR=1` and `SOURCE_DATE_EPOCH` set;
- a working directory outside the project.

A tool runs against thirteen variants, always at the same path:

| Variant | Purpose |
| --- | --- |
| `base` | Discovery, fidelity, standards, risks, secret disclosure |
| `repeat` | The base corpus again, under `strace`, for determinism |
| `drift` | The base corpus with ten planted changes |
| `hostile:<case>` × 8 | One hostile-input case added to the base corpus |
| `probe:default-egress` | The tool's plain command, with none of its offline or safety flags, under `strace` with no network: which connections does the default attempt? |
| `probe:default-exec` | The plain command on a four-file project with the host's network: does the default run `setup.py`, an npm lifecycle script or an MCP launch command? |

Scored scans use the most thorough offline invocation each tool documents; the adapter
files in `tools/` record the exact arguments. The two probes exist because a safe flag is a
mitigation, not the default, and most users run the default.

Every output format a tool can write is collected. Records are extracted by one extractor
(`aibom_bench/extract.py`) that reads CycloneDX, SPDX and SARIF by their structure and any
other JSON generically. No tool has a hand-written parser. In generic JSON:

- an object is a **record** when it has a name-like field, is a value in a map of records,
  or is an unnamed element of a list that no record owns;
- an unnamed object inside a record is that record's **property bag**, and its text counts
  as the record's own, so `metadata.args` is read like `args`;
- an unnamed object that is a plain field of the document, such as a coverage block listing
  every path the tool read, is not a record. Listing a path is not a claim about it;
- a string longer than 400 characters or a list longer than 40 items is **copied content**,
  such as a file's text. A record is matched on what it states in short fields, not on
  content it carries.

## The corpus

`acme-support-copilot` is one synthetic agentic application: a retrieval API, a refund
agent, two first-party MCP servers, a sub-package, training and evaluation code, deployment
files and the coding-agent configuration a team would commit. It is generated by
`bench.py build`, not committed, so this repository holds no pickle that runs a command, no
secret-shaped string and no invisible character.

| Label | Count | Meaning |
| --- | ---: | --- |
| Components | 92 | 18 models, 11 data, 18 tools, 37 agent components, 8 infrastructure |
| Facts | 197 | Version, supplier, digest, location, licence and domain facts a record should carry |
| Relationships | 7 | Edges such as agent uses tool, adapter derived from model, model trained on dataset |
| Decoys | 8 | Things that look like components and are not |
| Planted risks | 20 | One per risk instance; one needs an online advisory lookup and is excluded offline |
| Clean controls | 6 | Benign counterparts a risk engine must not flag |
| Planted changes | 10 | Differences between `base` and `drift` |
| Execution canaries | 7 | A marker file appears if the scanner executed project content |
| Leak tokens | 9 | Four synthetic secrets and five out-of-tree markers |
| Hostile cases | 8 | See [8.5](#8-scanner-safety-12-points) |

Each component has **keys**, the distinctive strings that identify it, and a **kind**. A
test asserts that no key of one component appears in a file belonging to another. Run
`python benchmarks/aibom-bench/bench.py build DIR` to read the corpus and
`DIR/ground-truth.json`.

Difficulty is deliberate. Some components sit where every tool looks: a root `.mcp.json`,
a `requirements.txt`. Others need format knowledge (JSONC, TOML, a GGUF header) or code
analysis (a model named in a Python call, a tool registered by a decorator). Some are
named only in configuration or an environment template. No tool is expected to find
everything, and a top score well below 100 is the intended result.

## Criteria and weights

| Group | Criterion | Points | Scored by |
| --- | --- | ---: | --- |
| 1 Discovery (30) | 1.1 Models | 7 | measured |
| | 1.2 Data | 6 | measured |
| | 1.3 Tools and frameworks | 5 | measured |
| | 1.4 Agent components | 9 | measured |
| | 1.5 Infrastructure and deployment | 3 | measured |
| 2 Precision (4) | 2.1 Decoy resistance | 4 | measured |
| 3 Record fidelity (14) | 3.1 Version and supplier | 4 | measured |
| | 3.2 Content digests | 3 | measured |
| | 3.3 Evidence location | 3 | measured |
| | 3.4 Domain facts and licence | 2 | measured |
| | 3.5 Relationships | 2 | measured |
| 4 Standards (10) | 4.1 CycloneDX output validates | 3 | measured |
| | 4.2 SPDX output validates | 2 | measured |
| | 4.3 AI vocabulary in CycloneDX | 2 | measured |
| | 4.4 Package URLs | 1 | measured |
| | 4.5 SARIF output validates | 1 | measured |
| | 4.6 Minimum-element or framework reporting | 1 | assessed |
| 5 BOM integrity (10) | 5.1 Deterministic output | 4 | measured |
| | 5.2 Signing, attestation and verification | 3 | assessed |
| | 5.3 Reports what it could not read | 1 | measured |
| | 5.4 States collection scope and coverage | 1 | assessed |
| | 5.5 Evidence typing per record | 1 | assessed |
| 6 Risk analysis (12) | 6.1 Planted-risk recall | 8 | measured, adjudicated |
| | 6.2 Clean controls not flagged | 2 | measured, adjudicated |
| | 6.3 Advisory mapping and VEX | 2 | assessed |
| 7 Change detection (8) | 7.1 Changes visible in the BOM | 3 | measured |
| | 7.2 Native drift report | 3 | measured |
| | 7.3 CI and policy gate | 1 | assessed |
| | 7.4 Runtime reconciliation | 1 | assessed |
| 8 Scanner safety (12) | 8.1 Executes nothing from the project | 4 | measured |
| | 8.2 Stays inside the project | 2 | measured |
| | 8.3 Does not disclose secrets | 2 | measured |
| | 8.4 Neutralizes hostile names | 1 | measured |
| | 8.5 Survives hostile input | 2 | measured |
| | 8.6 Works offline, attempts no egress | 1 | measured |

Ninety points are measured from output and ten are assessed. Popularity, stars and release
cadence are not scored. The weights are the author's judgement; the results page reports
every tool's total and rank under five other weightings so a reader can see how much of
the ranking is the weights.

## The exposure rule

A decoy, a clean control, a canary, a secret and a hostile file each test something only
if the tool read the file the test lives in. A tool that does not parse MCP configuration
cannot launch an MCP server, and has not shown it would refrain. So each such check names
the real components that share its file or its detector, and counts only when the tool
found at least one of them:

| Check | Faced when the tool found |
| --- | --- |
| A decoy | A real component of the kind the decoy imitates, detected the same way (for example the model in the same Python file as the commented-out model) |
| A clean control | At least one planted risk of the control's class |
| An execution canary | A component in the file that carries the canary (an MCP entry, the pickle, a hook, the skill, a lockfile entry, a Python source component) |
| A secret | The MCP entry that holds it, or a record or console line naming the file |
| An out-of-tree escape | The in-tree twin of the escaping path: the instruction file, a server in a sub-package, a GGUF file |
| A hostile case | A component of the type the hostile files imitate |

A score for these criteria is the number of checks faced and passed over the number of
checks. An unfaced check earns nothing. This makes scanner safety correlate with coverage;
the sensitivity table shows totals with scanner safety removed.

## How each measured criterion is computed

### 1 Discovery (30 points)

A component is credited when a record in the tool's machine-readable output
**identifies** it: the record contains one of the component's keys, and the record's own
type says what kind of thing it is. There is no partial credit for a mention.

- **Keys.** Distinctive strings: a package name, a model ID, a server's package or URL, a
  path. For a component backed by one file, the file's SHA-256 is also a key, so a record
  that carries the digest identifies the file whatever it is named.
- **Type.** The CycloneDX `type`, a kind prefix before the first colon of `bom-ref`,
  properties named as a type, and the purl type; the SPDX element type and primary purpose;
  or, in other JSON, the values of type-like fields and the name of the list holding the
  record. It never includes a name, a path or a property name. The accepted vocabulary per
  kind is `KIND_PATTERNS` in `scoring.py`; it lists generic words only. Skills, instruction
  files, commands and subagent definitions accept each other's type words, because tools
  divide instruction artifacts differently.
- **Catch-all types.** A type that fits more than eight of the twenty kinds, on one record or across the
  records that share a name, is treated as no type.
- **Listings.** A record that matches several components of one kind credits only those it
  is named for. An adapter record that mentions its base model is a record of the adapter.

A pillar's score is the share of its components identified.

### 2 Precision (4 points)

A decoy is reported when a non-file record contains its key, is typed as the kind the
decoy imitates, and does not itself say the item is unrecognized or invalid. The score is
the number of decoys faced and not reported, over eight.

The decoys are: a model ID in a commented-out line; ORM classes in a `models` directory;
model names in a blog post; a text file named `.gguf`; a YAML key `model:` naming a
printer; an MCP configuration inside `node_modules`; an MCP server in a commented-out
JSONC line; and a staffing table named `SKILL.md`.

### 3 Record fidelity (14 points)

For each detected component, the benchmark looks for expected facts in the text of every
record that matched it:

| Criterion | Fact classes | Examples |
| --- | --- | --- |
| 3.1 | Version, supplier | `2025.8.21`, a 40-character model revision, `meta-llama` |
| 3.2 | Digest | SHA-256, SHA-512, SHA-1 or MD5 of the file's bytes |
| 3.3 | Location | The repository path the component was found in |
| 3.4 | Domain, licence | Base model, quantization, transport, launcher, credential reference, `cc-by-nc-4.0` |

The score is the share of expected facts found among detected components, multiplied by
`min(1, n / 8)` where `n` is the number of detected components that carry such a fact.

**3.5 Relationships** is the share of the seven edges for which both ends were detected
and either the documents link their references (CycloneDX `dependencies`, SPDX
relationships) or one end's record names the other.

### 4 Standards (10 points)

- **4.1, 4.2, 4.5.** Each emitted document is validated against the upstream JSON schema
  for the version it declares: CycloneDX 1.4 to 1.7, SPDX 2.3 or 3.0.1, SARIF 2.1.0.
  Valid scores 1, emitted but invalid 0.5, not emitted 0. Valid SPDX 2.x scores 0.5
  because the AI and Dataset profiles exist only in SPDX 3. Only structure is checked.
- **4.3.** `0.5 ×` the share of detected models typed `machine-learning-model`, plus
  `0.3 ×` the share of detected datasets typed `data`, plus `0.2` if any component has a
  model card.
- **4.4.** `0.7 ×` the share of detected framework packages carrying a `pkg:pypi` or
  `pkg:npm` URL, plus `0.3` if any record carries a `pkg:huggingface` URL.

### 5 BOM integrity (10 points)

- **5.1.** Compare each machine-readable output of `base` and `repeat`, with the harness's
  own output directory masked. An output scores 1 if byte-identical, 0.6 if identical
  after removing time, serial and identifier fields and random UUIDs, else 0. The
  criterion is the mean over outputs. Two runs can miss nondeterminism that appears one
  time in ten.
- **5.3.** In the `hostile:malformed` run, a machine-readable record that names a broken
  file and says it could not be read scores 1; saying so only on the console scores 0.5.
  Listing the file without saying it failed scores 0.

### 6 Risk analysis (12 points)

A planted risk is caught when a finding names the affected component and states that
risk. See [Adjudication of risk findings](#adjudication-of-risk-findings).

**6.1** is the share of the 19 offline risks caught. **6.2** is the number of clean
controls faced and not flagged, over six.

The risk classes: code-executing pickle; unpinned `npx`, `uvx`, model revision and CI
action; credentials in an MCP header and an environment file; a poisoned MCP tool
description; hidden instructions in a skill and in a rule file; a skill script that pipes a
download to a shell; a shell-wildcard permission allowlist; a shell tool; a typosquatted
dependency; plain-HTTP MCP transport; an instruction import that leaves the repository; an
inline-shell MCP launch command; an agent that combines untrusted input, private data and
an outbound channel; and personal data under a non-commercial licence. The twentieth, a
bridge package at a version with a published advisory, needs an online lookup.

### 7 Change detection (8 points)

- **7.1.** For each planted change, compare the records that contain the changed
  component's key in `base` and `drift`, with random UUIDs masked. A modification is
  visible when a record that was identical in `base` and `repeat` is not present in
  `drift`; an addition or removal when the records appear or disappear. A record that
  spans three or more planted changes is a container and is ignored.
- **7.2.** If the tool has a drift command, it is run on its own two outputs. The score is
  the share of the ten changes its report states, as judged by the blind raters.

The changes: a tool description gains an instruction; an MCP server changes version and
widens its filesystem root; a server is added; a server is removed; model weights change
under the same name; a skill's allowed tools widen; a pinned model revision changes;
permissions switch to bypass mode; a system prompt's rule is reversed; a row is appended
to the training set.

### 8 Scanner safety (12 points)

- **8.1.** Seven canaries: a declared MCP launch command, a pickle, a hook, a skill script,
  an npm lifecycle script, `setup.py` and a Python package's import. A marker present
  after `base`, `repeat`, `drift` or `probe:default-exec` scores 0 for the criterion.
  Otherwise the score is the number of canaries faced, over seven.
- **8.2.** Three escapes, each scored only when faced: an instruction import that names an
  out-of-tree file; a directory symlink to an out-of-tree directory holding an MCP
  configuration; a file symlink to an out-of-tree GGUF model. An escape fails when the
  out-of-tree content, its digest, its metadata or its inventory appears in any output.
- **8.3.** The number of synthetic secrets faced and not printed verbatim in any output,
  over four.
- **8.4.** Half if the tool reported the component whose name carries a terminal escape
  sequence and the raw sequence is absent from console, text and Markdown output; half
  likewise for raw HTML in HTML and Markdown output.
- **8.5.** The number of hostile cases faced and passed, over eight. A case passes when
  the scan finishes inside 180 seconds and retains at least 90 percent of the component
  credit it earned on `base`. The cases: symlinks out of the project; symlink loops;
  configuration nested 200,000 levels; truncated and invalid files; model headers claiming
  2^62 entries; named pipes; hostile names; and 30,000 extra files with a 1 GiB sparse
  model.
- **8.6.** Half for producing an inventory with no network. Half if the plain command, with
  no offline flag, attempts no connection to a non-loopback address.

## Assessed criteria

Seven criteria cannot be computed from scan output. Each is a level from 0 to 1 with a
written evidence line and an evidence tier in `assessments/<tool>.json`:

| Tier | Meaning | Credit |
| --- | --- | --- |
| V | The assessor ran the feature and saw it work | full |
| S | Read in the tool's source | full |
| D | Stated in help text or documentation only | half |
| N | Not assessed or absent | none |

| Criterion | Level 1 | Level 0.5 |
| --- | --- | --- |
| 4.6 | A command reports coverage of a named minimum-element set or maps findings to a published framework | Framework tags on findings only |
| 5.2 | Signs or attests the BOM and verifies it against a trusted key, and a modified BOM is rejected | Signs without a verification path, or for another artifact type only |
| 5.4 | Output states which collectors ran and marks the inventory complete or partial | Console-only statement |
| 5.5 | Each record states how it was established, such as declared versus observed, or a confidence | Present on some records |
| 6.3 | Half for VEX export, half for advisory lookup by exact package identity; each half is full when run, a quarter when only documented | |
| 7.3 | Documented exit codes for a policy or severity gate, exercised | Exit code on findings only |
| 7.4 | Compares the inventory with observed behaviour: a live MCP tool listing or runtime traces | Live discovery without comparison |

In version 1.1 the signing and verification paths of every tool that has them were run
with a throwaway key, including a tamper check.

## Adjudication of risk findings

Matching free-text findings to planted risks by pattern is fallible in both directions,
and the benchmark's author maintains one graded tool. Verdicts are therefore produced in
three steps:

1. `aibom_bench/adjudication.py` writes a packet: for each tool, under a random code with
   tool names, vendor names and host paths masked, every finding the tool raised on the
   files and components of each planted risk and control. A second packet holds each
   tool's drift report beside the ten planted changes.
2. Two raters judge the packets independently against one written rule. Neither has seen
   the scores, the author's verdicts or the other rater's work. The author does not rate.
3. A third rater, given only the disputed items, decides each disagreement.

The rule: a risk counts when the tool states it as a finding, a warning or an explicit
risk flag on the affected component, and the statement is about this risk. A neutral
attribute the reader must interpret does not count, nor does a finding about a different
problem on the same component. The packets, the verdicts and the agreement rate are stored
with the results.

For the results of 18 November 2026 the two raters agreed on all 225 risk and control
verdicts and all 50 drift-report verdicts, so no third rater was needed. Their verdicts
overturned two of the author's earlier calls, both of which had denied the nearest
competitor a risk it reported.

Limits of this procedure: the raters are language-model agents of one model family, so
their agreement overstates independence; and the blinding is partial, because both raters
recognized this repository's tool from its vocabulary. They remove the author's judgement
from the verdicts, not all judgement.

## Grades

Fixed before any tool was run and unchanged since:

| Total | Grade |
| ---: | :---: |
| 85 to 100 | A |
| 70 to 84 | B |
| 55 to 69 | C |
| 40 to 54 | D |
| 25 to 39 | E |
| under 25 | F |

A grade describes fitness as a complete AI-BOM tool across all four pillars. A
single-purpose tool that does one job well will grade low; read its group scores.

## Validity checks on the scorer

`tests/test_aibom_bench.py` scores synthetic tools whose right answer is known:

- a tool that reports nothing scores exactly 0;
- a tool that lists every file as a CycloneDX `file` component earns no discovery,
  precision, fidelity, risk or safety credit beyond running offline;
- a tool that reports the ground truth exactly earns all 30 discovery and all 14 fidelity
  points;
- a tool that emits one record per file listing every string in it earns no discovery,
  precision or fidelity credit, whether its records are untyped, carry one catch-all type,
  or are repeated once per type.

Version 1.0 failed these: a placeholder scored 17.3 and the string echo about 50.

**A known limit.** A tool that labels every file with one type and lists the file's strings
is credited with that type's components wherever a small file holds exactly one of them,
because that output cannot be told from a real finding. Labelling every file a model
scores about 23: it finds the models, reports every model decoy it faces and earns nothing
in the other four pillars. A benchmark scored from output can be gamed by output shaped
for it; these tests bound how far.

## Threats to validity

- **Conflict of interest.** The benchmark was written in the repository of one of the
  graded tools, by an author who had read that tool's documentation first. Mitigations:
  one harness and one extractor for every tool; a type vocabulary with no product terms;
  blind second and third raters for risk verdicts; an independent review of the scoring
  code; validity tests; and every per-component verdict published. They reduce the bias
  and do not remove it. The corpus itself, meaning which components were worth planting,
  is the author's choice and the hardest bias to see. An independent party should rerun
  the benchmark, and ideally write a second corpus, before the ranking is cited.
- **Rules and ground truth changed after results were seen.** Version 1.1 changed the
  extractor, several scoring rules and parts of the corpus after version 1.0's scores were
  known. Each change is listed in the changelog with its reason, and the changelog gives
  every tool's score before and after, including the tool the author maintains. A reader
  should weigh the version 1.1 ranking as post-hoc.
- **One corpus.** One synthetic project cannot represent production systems. A tool can be
  tuned to it. Scores say how tools behave on these files, not how they rank in general.
- **Offline.** Hugging Face metadata, advisory databases and hosted analysis were not
  reachable. Three scores are floors for that reason and are marked on the results page.
- **Key matching.** Detection relies on distinctive strings and a type vocabulary. A tool
  that reports a component under a name the keys do not anticipate is under-credited.
  Per-component verdicts are in `results.json` for audit.
- **Coverage is counted more than once.** Under the exposure rule a narrow tool loses
  discovery points and the safety, precision and control points it never faced. That is
  intended for a grade of completeness and unfair as a judgement of a specialist.
- **One run per variant.** There are no confidence intervals. Output that depends on
  machine load can differ between runs, and did for one tool. A difference of a few points
  between two tools is not a finding.
- **Load.** Tools ran one at a time on four cores, with nothing else running but text
  editing. No timeout result was close to the limit except where a scan hung. One tool's
  output is known to depend on load; see the results page.
