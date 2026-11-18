# AIBOM-Bench changelog

## Entries added on 18 November 2026

Nexus ShadowScan 0.1.4 and the documented ShadowScan-into-SymBiote workflow were run on the
same corpus and harness and added to the results as two entries. ShadowScan's repository
surface is the only one of its nine that the corpus exercises. The raters' packet for these
two entries did not mask the name ShadowScan, so they were not blind to it, and its 60-line
cap hid two of SymBiote's findings; that correction and one unresolved disagreement are
recorded in the assessment files.

## 1.1.0, 18 November 2026

Version 1.0 was audited by its author acting as a hostile reviewer, by an independent
reviewer given the code and the raw outputs and told to assume bias, and by two blind
raters for the risk verdicts. The audit found defects in both directions. Every rule below
changed **after** version 1.0's scores were known, which is itself a threat to validity;
the last section gives each tool's score before and after so the effect of the changes on
the author's own tool is visible.

### Defects that paid points nothing had earned

- **A tool that reported nothing useful scored 17.3.** The OWASP AIBOM Generator wrote a
  placeholder and collected safety, precision and control points for checks it never
  faced. Now a check counts only when the tool found a real component in the same file or
  through the same detector ([the exposure rule](SPEC.md#the-exposure-rule)), and that
  tool is reported as not gradable.
- **Echoing strings scored about 50.** The independent reviewer built a fake tool that
  emits one record per file listing every string in it; it scored 49.8, and 60.8 with a
  constant type. Version 1.0 paid half credit for any record containing a component's key
  and read facts from anywhere in that record. Now: no credit without a matching type; a
  type that fits more than eight kinds is no type; a record matching several components of
  one kind credits only the ones it is named for; long strings and long lists inside a
  record are copied content, not description. The same fake tool now scores 5.0, all of
  it for being deterministic and offline.
- **A coverage list was read as an inventory.** One tool's native output lists every path
  it scanned. Version 1.0 treated that block as a record typed with every collector name.
  Only objects that name a component are records now.
- **CycloneDX `bom-ref` values and property names were read as types.** A path containing
  `mcp` could make a file a server. Type evidence is now the `type`, a kind prefix before
  the first colon of `bom-ref`, and properties named as a type.
- **Naming a broken file counted as reporting that it could not be read.** Criterion 5.3
  now requires the record to say so.
- **A decoy or a clean control was a free point for a tool with no detector for it.**
  Covered by the exposure rule.

### Defects that favoured the author's tool

- **One LoRA adapter record credited Nexus SymBiote with a model it never found.** The
  base-model property of the adapter matched the key of the Hugging Face model loaded in
  Python, which Nexus SymBiote does not detect. That credit also marked two decoys as
  faced and passed and satisfied a relationship. Fixed by the listing rule.
- **A 220 KB SPDX document element made unrelated changes look visible.** Criterion 7.1
  now ignores records that span three or more planted changes.
- **The author's risk adjudication under-credited the nearest competitor.** Two blind
  raters, unanimous on all 225 verdicts, reported two risks for agent-bom that the author
  had ruled out. The author's verdicts are no longer used.
- **Signing was verified by hand for Nexus SymBiote only.** agent-bom's `attest sign` and
  `attest verify` and cdxgen's `cdx-sign` and `cdx-verify` were then run with a throwaway
  key, including a tamper check. Both now earn full credit on 5.2.
- **agent-bom ran without analyses it documents as opt-in** (`--model-provenance`,
  `--scan-pii`, `--dataset-cards`, `--training-pipelines`, `--context-graph`), while other
  tools ran with theirs. ai-bom likewise ran without `--deep`. Both adapters now pass them.
- **The type vocabulary contained a term from Nexus SymBiote's collector names.** Removed;
  the vocabulary is generic words only.

### Defects that penalised other tools

- **Details nested one level down were not credited.** Trusera ai-bom and Cisco AI BOM put
  launch arguments under `metadata`; AIROM puts evidence under `evidence.occurrences`.
  Version 1.0 gave them half credit for MCP servers they listed correctly. An unnamed
  object inside a record is now that record's property bag.
- **Model files reported by file name were not matched.** AIsbom and agent-bom name a
  weight file `model.safetensors`; the keys were directory names. A record that carries
  the file's SHA-256, or is named by its unique file name, now identifies it.
- **Coarser categories were scored as wrong.** Cisco AI BOM files `AGENTS.md` under
  "skill" and agent-bom files a subagent definition under "skill file". Skills, instruction
  files, commands and subagent definitions are all instruction artifacts and tools divide
  them differently, so any of those types is now accepted for any of them.
- **Determinism charged tools for the harness's own paths.** Each run wrote to a different
  directory, and a tool that records its report path (cdxgen's SARIF) or its `HOME`
  (Syft) looked non-deterministic. `HOME` now keeps one path, the output directory is
  masked before comparison, `discovered_at` and `last_seen` count as time fields, and the
  criterion averages over outputs instead of failing on the first difference.
- **The drift-report criterion matched configuration strings, not reported changes.** It
  missed changes that Nexus SymBiote's and AIsbom's reports state in their own words. The
  reports are now judged by the blind raters.

### Defects in the ground truth

- Four keys named a different component: the skill script `issue_refund.py` and the MCP
  tool `issue_refund`; the server `acme-kb` and the bucket `acme-kb-prod`; and two skills
  mentioned by name in other files. Renamed. A test now fails if any key appears in a
  file belonging to another component.
- The two first-party MCP servers were keyed differently. Both are now keyed by declared
  name, package or framework, and source path. To keep the Python server's source path out
  of the client configuration that launches it, that configuration now runs it as a module.
- The clean control for a pinned model was not clean: the LoRA adapter named the same
  model with no revision. The adapter now pins it.
- One component was added: an MCP server declared in a sub-package. It is a real monorepo
  case and it is the control that shows a tool reads nested configuration.
- These edits were made after outputs existed. None was made to change a particular tool's
  verdict, but two of them did: the source-path key gives Nexus SymBiote the TypeScript MCP
  server it reports under a variable name, and removing a path key that also appeared in a
  client configuration takes credit from tools that only read that configuration.

### New measurements

- **Default-command probes.** Scored scans use each tool's safest documented flags.
  `probe:default-egress` and `probe:default-exec` run the plain command instead. The
  second found that cdxgen's default command executes the project's `setup.py`; it had
  scored 4 of 4 on "executes nothing" in version 1.0 because the scored scans pass
  `--no-install-deps`.
- **Out-of-tree file symlink.** A symlinked GGUF file outside the project is now part of
  the symlink case.
- **Weight sensitivity.** The results report every total and rank under five other
  weightings.
- **Validity tests.** Synthetic tools with a known right score are scored in CI.

### Found in a graded tool by the rerun

- Nexus SymBiote bounds TypeScript parsing by a 0.25-second wall-clock limit. In one of 46
  scans during the first rerun the limit fired, the TypeScript MCP server and its tool were
  dropped, and two scans of identical input differed. Version 1.0's two runs happened not
  to hit it and reported full determinism. It did not recur in twelve follow-up scans or in
  the final scored run, so the published determinism score is again full; read it as an
  upper bound.

### Scores before and after

Version 1.0 as published, against version 1.1 from one clean rerun of all ten tools on
the final corpus and harness. Version 1.1 is not comparable point for point: the corpus,
two adapters and most scoring rules changed.

| Tool | 1.0 total | 1.0 grade | 1.1 total | 1.1 grade | Change | Main reasons |
| --- | ---: | :---: | ---: | :---: | ---: | --- |
| Nexus SymBiote | 71.1 | B | 67.9 | C | -3.2 | Lost unfaced safety, decoy and secret points and the adapter-as-base-model credit; gained drift-report credit from the raters |
| agent-bom | 60.5 | C | 65.4 | C | +4.9 | Signing verified, opt-in analyses enabled, model files matched by name and digest, two risks restored by the raters; lost unfaced points and an out-of-tree symlink check |
| OWASP cdxgen | 56.0 | C | 51.1 | D | -4.9 | Default command ran `setup.py` (0 of 4 on 8.1); lost unfaced points; gained signing and determinism credit |
| Cisco AI BOM | 49.5 | D | 48.6 | D | -0.9 | Nested details and coarser categories credited; lost unfaced points |
| AIROM | 53.0 | D | 45.0 | D | -8.0 | Lost unfaced safety, decoy and control points |
| Trusera ai-bom | 36.9 | E | 32.2 | E | -4.7 | Nested details credited and `--deep` enabled; lost unfaced points and control credit |
| Anchore Syft | 36.8 | E | 27.7 | E | -9.1 | Lost unfaced safety, decoy and control points |
| AIsbom | 37.5 | E | 26.1 | E | -11.4 | Lost unfaced points and followed an out-of-tree symlink; gained model files matched by name and digest |
| Snyk Agent Scan | 28.9 | E | 18.1 | F | -10.8 | Lost unfaced safety, decoy and control points |
| OWASP AIBOM Generator | 17.3 | F | not graded | n/a | n/a | Takes a model ID, not a project; its 1.0 score was unearned |

Nexus SymBiote led agent-bom by 10.6 points in version 1.0 and leads by 2.5 in version 1.1. With one run per variant and
weights chosen by the author, that difference is not a finding. Counting inventory alone
(discovery, precision and fidelity), agent-bom and Cisco AI BOM both score above it.
