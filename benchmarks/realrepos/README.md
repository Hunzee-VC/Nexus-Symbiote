# Real-repository precision harness

This harness scans 24 public repositories, each pinned to a commit, and reports what Nexus SymBiote finds in them, so a change to a collector or a finding can be compared against a stored baseline. It is false-positive calibration on real code, not a field efficacy estimate: the repositories are a hand-picked sample (agent frameworks, MCP servers and SDKs, skills, RAG and training code, two non-AI libraries), the labels are a reviewer's judgement, and a clean result says nothing about repositories unlike these. It complements #268's `make precision`, which checks labelled cases written for the purpose, by measuring the findings that real code produces.

Nothing here runs in CI or in pytest: fetching uses the network and scanning takes a few minutes. `tests/test_realrepos_harness.py` exercises the manifest checks, the report, the labels and the budgets offline on small fixtures, and checks that the committed baseline is consistent.

## Files

| Path | Contents |
| --- | --- |
| `manifest.json` | The repositories (schema 1): `id`, `url`, `ref`, `commit`, `tree`, `group`, `license`, `rationale`. `commit` is authoritative; `ref` only records the branch it was resolved from. |
| `harness.py` | `fetch`, `scan`, `report` and `label-template`; standard library only |
| `budgets.json` | False-positive budgets per finding category, the component precision floor, the allowed exit codes, the negative repositories and the cost ratios |
| `labels/<id>.json` | True- and false-positive labels per repository |
| `results/baseline/` | `summary.json`, `observations.json` and `RESULTS.md` of the current tree |

## Run it

From a checkout with the locked environment installed (`make install-locked`):

```bash
python benchmarks/realrepos/harness.py fetch --dest ../realrepos/trees
python benchmarks/realrepos/harness.py scan --trees ../realrepos/trees --out ../realrepos/scan
python benchmarks/realrepos/harness.py report --out ../realrepos/scan --results ../realrepos/results \
    --baseline benchmarks/realrepos/results/baseline
```

`--only ID` limits `fetch` or `scan` to one repository and may be repeated. Relative paths are resolved against the current directory before anything runs. `scan` exits 1 when a tree is missing or at another commit, or when a scan exits non-zero or times out. `report --enforce-budgets` exits 1 when a budget fails; without it the report only lists the failures. `report --baseline-private FILE` names the baseline scan's `private/credential-observations.json`, so that a credential observation already in the baseline is not counted as new; without it every credential observation on a negative repository counts as new. To refresh the committed baseline, write the report to `benchmarks/realrepos/results/baseline` without `--baseline`.

The committed baseline was produced this way from trees fetched by the harness's precursor, which cloned each default branch and recorded the commit the manifest now pins; `scan` reads `.git/HEAD` and refuses a tree at any other commit.

## Safety

The repositories are third-party code and are treated as hostile input.

- **Fetch** runs `git init`, then `git fetch --depth 1 --no-tags --no-recurse-submodules <url> <commit>` and `git checkout --detach FETCH_HEAD`, with `core.hooksPath=/dev/null`, `protocol.allow=never` except HTTPS, `transfer.fsckObjects=true`, `core.fsmonitor=false`, `GIT_LFS_SKIP_SMUDGE=1`, `GIT_TERMINAL_PROMPT=0`, no system or global Git configuration, and a 900 s timeout per command. It then checks that `HEAD` is the pinned commit and that the tree hash matches the manifest. A target directory that already exists is accepted only when its `HEAD` is the pinned commit and its tree hash, read with the same hardened `git rev-parse`, matches the manifest.
- **Scan** runs `python -I -m nexus_symbiote scan <tree> --no-project-policy --report-only -f json -o <out>/<id>.json` for each tree, then `risk --json-output` on that inventory for the score. A fetched repository's `.nexus-symbiote.yaml` is never read. Each repository gets a fresh `HOME`, `SOURCE_DATE_EPOCH=0` and no `NEXUS_SYMBIOTE_*`, `PYTHON*` or `XDG_*` variables, so the scan is offline by default. The harness records the exit code, wall time and peak resident set (`os.wait4`), and kills a scan after 1,800 s. `--sarif` also writes SARIF. Nothing from a tree is executed or imported, and the harness resolves a tree's `HEAD` by reading files, not by running Git in it.

## What the report contains

Each observation has a stable identifier, the first 16 hexadecimal digits of a SHA-256 over canonical JSON:

| Kind | Identifier over |
| --- | --- |
| `finding` | `{repo, bom_ref, category, detail}` |
| `component` | `{repo, bom_ref, component_type}` |
| `gap` | `{repo, gap}`, where a gap is a collection failure, an excluded surface or a collector that did not complete |

`summary.json` holds, for each repository, the exit code, the scan gate verdict and its main reasons, the score, the components by type, the findings by category and severity, the gap count, whether coverage was complete, the wall time and the peak resident set; then the totals, the label metrics per finding category and per component type, the budget results and, with `--baseline`, the delta. `RESULTS.md` is rendered from `summary.json` alone, and the tests check that the committed pair agrees. `observations.json` lists every observation that may be published.

The delta lists new and removed observations by kind and category, gate flips with their reasons, and per repository the score delta and the time and resident-set ratios. The identifiers of the new and removed observations, and of the new credential observations, are written to `<out>/private/delta-ids.json`, beside the scan output.

### Credential categories: counts only

A finding whose category names a credential or a secret (`credential_exposure`, `credential_exfiltration`, `credential_helper` and any later one) is published as a count by category and severity only, across all repositories: no repository, component, path or detail, and no per-repository count. Its observations are written to `<out>/private/credential-observations.json`, which is never committed. Label them in a directory outside the repository (`label-template --private` refuses a directory inside it, and without `--private` refuses credential observations) and pass it as `report --private-labels DIR`. `report` refuses an entry in a `--labels` directory that names a credential observation or carries a credential category in its context, whether or not it has a verdict. A true positive in a third-party repository is reported to its maintainers privately by the project owner.

## Labels

`labels/<id>.json` (schema 1):

```json
{
  "schema_version": 1,
  "repository": "crewAIInc_crewAI-examples",
  "commit": "da94a91e691e1cf5b3151416bb15b5b62729bea8",
  "labels": [
    {
      "observation": "15ded84f0535ddb3",
      "verdict": "false-positive",
      "status": "proposed",
      "reviewer": "implementing session (B04)",
      "date": "2026-11-19",
      "note": "Chroma hnswlib persistence file (binary index), not a model or a pickle.",
      "context": {"category": "serialization_format", "severity": "critical"}
    }
  ]
}
```

`commit` must be the manifest commit of `repository`; `report` refuses a label file for another commit. `verdict` is `true-positive`, `false-positive`, `out-of-scope` or `null` (not yet labelled). `status` is `proposed` until the maintainer reviews the entry and sets `confirmed`; a session that writes labels writes them as `proposed`. `context` is optional and only helps the reviewer. An observation may be labelled once across all label directories.

`label-template --observations FILE --labels DIR` adds an unlabelled entry, with its context, for every observation in FILE that DIR does not yet label, and keeps the existing entries.

The committed labels are proposed, not confirmed. They cover the 35 critical and high findings of the baseline: the 16 findings on Chroma's `hnswlib` index files in `crewAIInc/crewAI-examples` (`serialization_format` and `signing_status` on `header.bin`, `data_level0.bin`, `length.bin` and `link_lists.bin`) are false positives; the `serialization_format` findings on pickle files and the `version_pinning` findings on `uvx <package>@latest` in `awslabs/mcp` client configurations are true positives; `signing_status` on data pickles is out of scope.

For each category, the report gives the observations, how many are labelled, true positives, false positives, out of scope, unlabelled, the false-positive rate FP / (TP + FP), false positives per scanned repository, and how many labels are confirmed; for each component type, the precision TP / (TP + FP).

## Budgets

`budgets.json` sets the acceptance budgets that later detector changes are checked against:

| Budget | Limit |
| --- | --- |
| `tool_description_instructions` false positives | 0 critical, 0 high, at most 2 medium |
| `credential_exposure`, `credential_exfiltration` false positives | 0 |
| `script_download_execution` false positives | at most 2 |
| Component precision, per type with any labels | at least 95% |
| Scan exit codes | 0 for every repository under `--report-only` |
| Negative repositories (`pallets/flask`, `psf/requests`) | 0 new observations, credential observations included, against the baseline, or 0 findings without one; only the total is published |
| Coverage | 0 new gaps on repositories whose baseline coverage was complete |
| Cost | no repository slower than 2× its baseline wall time (when above 5 s) or above 2× its baseline peak resident set |

A false-positive budget counts labelled false positives only, so an unlabelled finding never fails it; the report's unlabelled column shows what is still to be judged. The coverage and cost budgets need `--baseline`.

The categories budgeted here that the current tree does not yet produce are placeholders for the detectors that will add them. Per the maintainer's decision of 19 November, Nexus SymBiote does not add native discovery of datasets, model references in code or configuration, SDK agents, stores named only in code, A2A clients in code or typosquats, so the harness has no budget for them.

## Limits

- 24 repositories, chosen by hand; infrastructure MCP servers whose tool descriptions name their own configuration files (Kubernetes, SSH, Docker, BigQuery) are not in the manifest, so that class is unmeasured.
- The labels are proposed by one reviewer and cover 35 of the 172 baseline findings.
- Wall time and resident set depend on the machine; compare ratios against a baseline taken on the same machine.
- A pinned commit stays reachable only while its repository keeps it; a fetch that fails is reported, not replaced.
