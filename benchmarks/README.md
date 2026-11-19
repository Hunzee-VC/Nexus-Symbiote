# Synthetic security regression corpus

This small, committed corpus checks named security conditions and control contracts. It is not a representative sample of production agents, does not estimate population efficacy, and supports no competitive ranking or percentile claim.

Each case has an inspectable label, rationale, task, and SHA-256 manifest of exact inputs. The harness calls the Nexus SymBiote scanners and validators it imports (the checkout's `src` with the command below). Detection outcomes are computed from their outputs, not from the label. Labels are used only after evaluation for confusion counts. No fixture launches a tool, loads a model, or contacts a service. The SafeTensors fixture is a valid single zero-valued F32 tensor, not a trained model; pickle fixtures contain only inert serialized data and are never deserialized.

Run from a reviewed checkout with its dependencies installed:

```bash
PYTHONPATH=src python scripts/benchmark_security.py --out benchmark-results.json
```

The default corpus is `benchmarks/manifest.json`. `--manifest` selects another manifest under the same schema. A file hash mismatch, symlink, undeclared input file, invalid case, or duplicate case ID fails the run instead of quietly modifying the denominator. The output records corpus and runner digests, imported source digests, tool version, source Git revision and dirty state, platform, elapsed time, and Python traced peak allocation. Traced allocation is not whole-process resident memory.

Detection metrics include TP, FP, TN, FN, precision, recall, F1, specificity, and their denominators. A missing prerequisite or incomplete collection yields `unknown`; unknown predictions are excluded explicitly, and the report records their known labels separately so recall cannot conceal abstentions. Metrics are additionally separated by condition kind. Different kinds test different policies and their aggregate is only a regression summary.

Credential disclosure and collection-failure coverage are control contracts, reported separately from detection metrics. Their outcomes must not inflate TP/TN. The plaintext fixture secret is a public synthetic sentinel; tests check that this literal is absent from actual native, CycloneDX, SPDX, and SARIF exports.

## Hostile corpus suite

`tests/test_hostile_corpus.py` builds the seeded hostile corpus from [`seeded-corpus/generate.py`](seeded-corpus/generate.py) (seeds 20261118 and 4242) in a temporary directory, adds the `s10-new-surfaces` scenario it writes itself, and runs every built-in collector over each scenario through the CLI, in all four inventory formats and in VEX and `risk` text, in its own process, in an isolated interpreter capped at 300 s of CPU and 2.5 GB of address space, and called directly. Its pickles, MCP launch commands and build hooks only create empty files under `<tmp>/canary` if something executes them; nothing in the suite executes them, and the suite fails if any file appears there. It also fails on any network attempt, process start or pickle global the interpreter reports (swallowed refusals of the offline guard included), any open of a file outside the scan root through a symbolic link, a planted credential in any output or stream (raw, hexadecimal, base64, URL-encoded or `\u`-escaped), a raw terminal control character, more than 1 GiB of memory or 120 s of CPU on the 3 GiB decompression bomb and the deeply nested JSON, memory that grows with a bomb's inflated size, and two checkouts that do not scan to identical bytes. Teardown deletes both corpora. It runs in every pytest job; run it alone with `make hostile-regressions`.

The corpus is intentionally finite. Blind spots include real signed provider bundles, undocumented hosted-model revisions, deployed endpoint authentication, runtime revocation races, multi-tenant retrieval ACLs, framework diversity, and adversarial obfuscation beyond these fixtures. Expanding the corpus requires reviewed labels, independent fixture hashes, negative controls, and a documented sampling rationale. A perfect result on this corpus is not a safety or completeness certificate.
