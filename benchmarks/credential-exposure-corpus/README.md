# Labelled corpus for the credential finding of an MCP launch

A side branch for review use; it is not meant to merge. It holds the corpus behind the
independent review of pull request 255 (`credential_exposure`), which used pull request
259 (`literal_credential`) as a second implementation to compare with.

- `corpus.py` builds 1,437 projects, each with one MCP client file and one planted value
  in one position, a label (476 `credential`, 961 `benign`) and a shape tag. Every
  credential-shaped value is put together when the script runs, from a seeded generator,
  so two builds are byte-identical and no token is committed here.
- `run_tree.py` runs one source tree over the corpus and records, per case, whether a
  credential finding is raised and whether the planted value reaches any output.
- `compare.py` prints the totals for several trees, by shape with `--by-shape`, and with
  `--lost BASE NEW` the credentials NEW no longer reports and the benign values it newly
  reports.
- `report.py`, `doc_map.py`, `fp_summary.py`, `merge_rows.py`, `leak_triage.py` wrote the
  review's tables.

```sh
sh run_all.sh .venv/bin/python /tmp/cred main=/checkouts/main fix=/checkouts/fix
```

## What is recorded here

- `RESULTS-summary.md`: the tables of 18 November 2026 for `main` `7ca2235f`, pull request
  255 at `6738b8ee` and pull request 259 at `be778342`, without the per-case listings.
- `cases-verdicts.tsv`: one row per case with its origin, label, shape, position, client
  file and the three verdicts. Names and values are left out on purpose: rebuild the
  corpus to see them (`python3 -I corpus.py build DIR` writes `DIR/manifest.json`).
- `prototype/stage1.patch`, `stage2.patch`, `stage3.patch`: an untested sketch on top of
  `6738b8ee`, cumulative. Stage 1 withholds a name that repeats a value, reads an inline
  script word by word, reads `--env=NAME=VALUE` and narrows the scheme and header-line
  rules. Stage 2 adds value rules (references in other syntaxes, placeholders, paths).
  Stage 3 adds positions (private key blocks, endpoint URL query, the command field).
  They have no tests and no documentation.

## Reading the numbers

The benign set is hostile by construction: lists written to break pull request 259, and
cases aimed at pull request 255's name rule. Read it by shape and origin, not as a rate
in the field. Six shapes have labels that can be argued (weak or documented passwords,
random values under a name without a credential word, a literal followed by a reference,
a documented example passphrase, repetitive synthetic values, an upper-case sentinel).

Gitleaks' generic rules flag three lines of `corpus.py` (an image tag that contains the
word "token", a `?token=${TOKEN}` reference and a `curl` header built from a placeholder).
None is a credential.
