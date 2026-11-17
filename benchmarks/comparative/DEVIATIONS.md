# Deviations from the registered method

The corpus, the scoring rules, the weights and the grade bands of version 1.0.0 were registered in the commit that added this file, before any tool was run on the corpus. This page lists every change made after that commit: what changed, why, and what it did to each tool's score.

A deviation is recorded even when it changes no score. A change to a case or a label also changes the corpus digest pinned in `bench/__init__.py`.

## Before registration

These choices were made while the adapters were developed against a smoke project that is not part of the corpus. They are listed so that the registered state can be understood, not because they changed a result.

| Choice | Reason |
| --- | --- |
| The binary control file is a PNG image, not a `.bin` file | Two tools treated a `.bin` file of random bytes as model weights. `.bin` is a real model-weight extension, so it could not serve as a file with no AI content |
| agent-bom runs with `--offline --no-scan` | Offline, it reports a scan without its vulnerability database as incomplete and lists fewer components; vulnerability matching is outside this round for every tool |
| Output files are named `bom.cdx.json`, `findings.sarif` and `native.json` | agent-bom refuses to write SARIF to a file without a `.sarif` extension |

## After registration

None yet.
