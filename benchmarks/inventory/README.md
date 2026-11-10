# Inventory regression corpus

From a Nexus SymBiote development install run `python benchmarks/inventory/run_inventory.py`. The command prints per-case predictions, missed and unexpected tool names, control outcomes and counts. It returns nonzero on any mismatch. Run offline. Cases extract declared tools without executing repository code.

The source fixtures in `fixtures/upstream` are unmodified and accompanied by their licenses. Corpus v3 samples three public implementations. The manifest pins the upstream revisions and blobs, and the runner checks each source file's SHA-256 before collection.

| Upstream source | Expected tools | Explicit decoys | Label evidence |
| --- | ---: | ---: | --- |
| MCP TypeScript filesystem server | 14 | 0 | Upstream test enumerates the tool names. |
| MCP Python SDK quickstart | 1 | 2 | Manual review of the tool, resource and prompt decorators. |
| Microsoft MarkItDown MCP server | 1 | 3 | The upstream README names its sole tool, `convert_to_markdown`. The source defines three undecorated module-level functions that serve as decoys. [Upstream README](https://github.com/microsoft/markitdown/blob/7482c092d9c0074a89803c9fdb63a969e7fe17fc/packages/markitdown-mcp/README.md) |

The MarkItDown fixture exercises a separately maintained application beyond the two reference projects. The remaining seven cases are hand-labeled regressions. One case checks equivalent TypeScript bracket registrations and ensures that prompt and resource registrations remain outside the tool inventory. These are convenience samples of static source. Fourteen of the sixteen upstream tool labels come from the filesystem server. They cannot establish held-out accuracy, deployment behavior or a production error rate.

Tool confusion counts include only explicit expected tools and explicit decoys. A predicted name outside both label sets is reported separately as `unexpected_unlabeled` and fails the case pending review; it is not silently added to the false-positive denominator. The report totals these names under `unlabeled_predictions`. Labels must be unique and disjoint. No assertion that an unlabeled name is a true negative or a false positive is implied. Collection failures or relevant MCP exclusions make unobserved positive and negative labels unknown and exclude them from scored denominators. Per-collector status and relevant exclusions remain visible.

Source-scoped cases explicitly assess source declarations; the routine absence of an MCP config is outside that scope. Other exclusions make collection incomplete. The registration-decoys case intentionally contains two ambiguous registrations; the manifest records those exact expected exclusions and their rationale. The case can pass as a control when those omissions are reported exactly, but its missing labels remain unknown. An additional unexpected exclusion fails the case. A passing regression control therefore does not mean all labels were scored or that collection was complete.

Each case and the aggregate report include `tool_counts` and/or `label_bounds`.
The recall interval treats every unobserved positive label first as missed, then
as detected; the specificity interval treats every unobserved negative first as
incorrectly detected, then as correctly absent. Each interval includes its full
explicit-label count, observed count, and unknown count. A zero denominator is
reported as null, not perfect performance. These are worst/best case bounds for
the selected labels, not statistical confidence intervals. Names with no label
are still reported separately, not assigned to either bound. Aggregate counts
are case-label occurrences: repeated names across cases are not distinct real
deployments. The release statement binds the new results to the corpus and scanner
materials, and the release workflow attests the archive that holds them.

The manifest's `version` identifies the corpus and labels, not the result wire
format; it is unchanged because the cases and labels are unchanged. The additional
result fields are additive. Consumers that reject unknown JSON fields must update
their parser. New result bytes require a new evidence statement and signature;
previously signed results remain verifiable using their original statement.

## Independent effectiveness evaluation

These regression fixtures do not establish a field baseline. To build one,
independently select a versioned and appropriately licensed sample across agent
frameworks and sources before examining predictions; record inclusion criteria,
collection date, source revision, exclusions, and intended deployment population.
Have reviewers label tool declarations and explicit decoys against a written
protocol, blinded to scanner results, and record disagreements and adjudication.
Reserve a held-out set that is not used to tune the scanner or fixture assertions.
Run a fixed built artifact against each snapshot and retain input hashes, scanner
revision, configuration, raw outputs, coverage failures and unmapped labels.
Report per-surface confusion counts and unknowns, as well as the selection
process and limits; do not treat this regression corpus as that held-out set.
No representative sample or independently adjudicated performance claim is
provided by this repository today.

### Sign and check a result outside a release

Releases use the workflow attestation described in the next section. For a result you
produce yourself, install the project's Sigstore extra, prepare the evidence directory
on a trusted checkout and sign the statement with your authorized OIDC identity.
Consumers can verify the exact result bytes offline with their own signer and issuer
policy.

```sh
python benchmarks/inventory/evidence.py prepare run
python -m sigstore sign --bundle run/statement.sigstore.json run/statement.json
python benchmarks/inventory/evidence.py verify run --identity "$EXPECTED_SIGNER" --issuer "$EXPECTED_ISSUER"
```

The statement binds the output, the corpus, the runner, and every file of the installed
scanner package, its vendored schemas included. It records the Python version and the
version of every installed distribution. Add `--compare-installation` to require the
local scanner, fixtures, runner and installed distributions to match. Publish
`results.json`, `statement.json`, and the signature bundle together.


The harness calls installed static MCP and model collectors directly with their
confined collection boundary. It does not execute repository code or apply the
fixture's project policy to the benchmark runner. Policy rejection is a separate
CLI control. Tool TP/FP/FN/TN count literal expected tools and explicit decoys;
model format, signature uncertainty, scoping and secret redaction are reported
separately as controls. A collection failure makes the case fail and remains
visible. Run the command above to inspect results for each case and its excluded labels.

## Verify a release candidate's inventory benchmark

The manual release workflow runs the public corpus against the built wheel on
`main`. The `release-evidence` artifact includes `inventory-benchmark.tar.gz`.
The archive contains the per-case results, the in-toto statement binding those
results to the corpus and installed scanner sources, and the SHA-256 of the
tested wheel. A separate job attests the archive with GitHub's workflow identity.

Download the archive from the candidate run and set `RELEASE_COMMIT` to the full
commit you intend to verify. Check the provenance before extracting the archive.

```sh
gh attestation verify inventory-benchmark.tar.gz \
  --repo Hunzee-VC/Nexus-Symbiote \
  --signer-workflow Hunzee-VC/Nexus-Symbiote/.github/workflows/release.yml \
  --source-ref refs/heads/main --source-digest "${RELEASE_COMMIT:?set the expected commit}" \
  --deny-self-hosted-runners
```

For a retained copy of the attestation, download `inventory-benchmark-attestation`
from that run and supply its file to `gh attestation verify` with `--bundle`.
Compare the candidate wheel against `wheel.sha256` before using the results for
that distribution. The archive has no Sigstore bundle of its own; once its
attestation verifies, check that the statement binds the results, and, in an
environment where that wheel is installed with `requirements-action.lock`, that it
binds that installation:

```sh
mkdir inventory && tar -xzf inventory-benchmark.tar.gz -C inventory
python benchmarks/inventory/evidence.py check inventory --compare-installation
```

The counts describe the versioned public fixtures.
