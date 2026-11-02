# Inventory regression corpus

From a Nexus SymBiote development install run `python benchmarks/inventory/run_inventory.py`. The command prints per-case predictions, missed and unexpected tool names, control outcomes and counts. It returns nonzero on any mismatch. Run offline. Cases extract declared tools without executing repository code.

The upstream servers and their licenses are in `fixtures/upstream`. The TypeScript filesystem server is pinned to a commit and blob, and its upstream test enumerates the expected tools. The Python SDK quickstart is pinned independently by commit, blob and SHA-256; its `@mcp.tool()` declaration is labeled as a tool and its `@mcp.resource()` and `@mcp.prompt()` declarations as explicit non-tool decoys. Those labels were manually derived from the source, not independently adjudicated. The remaining cases are hand-labeled regression fixtures. These public examples were selected for regression testing and do not establish representative production accuracy or held-out performance.

Tool confusion counts include only explicit expected tools and explicit decoys. A predicted name outside both label sets is reported separately as `unexpected_unlabeled` and fails the case pending review; it is not silently added to the false-positive denominator. The report totals these names under `unlabeled_predictions`. Labels must be unique and disjoint. No assertion that an unlabeled name is a true negative or a false positive is implied. If collection fails, missing positive and negative labels are reported as unknown, excluded from scored denominators, and fail the case. Per-collector partial status is also visible; an absence from an excluded surface is not evidence of absence.

### Sign and check a result

Install the project's Sigstore extra. Prepare the evidence directory on a trusted checkout. Sign the statement with the release operator's authorized OIDC identity. Consumers can verify the exact result bytes offline with their own signer and issuer policy.

```sh
python benchmarks/inventory/evidence.py prepare run
python -m sigstore sign --bundle run/statement.sigstore.json run/statement.json
python benchmarks/inventory/evidence.py verify run --identity "$EXPECTED_SIGNER" --issuer "$EXPECTED_ISSUER"
```

The statement binds the output, the corpus, the runner, and the installed scanner source. It records Python and key library versions. Add `--compare-installation` to require the local scanner, fixtures and runner to match. Publish `results.json`, `statement.json`, and the signature bundle together.


The harness calls installed static MCP and model collectors directly with their
confined collection boundary. It does not execute repository code or apply the
fixture's project policy to the benchmark runner. Policy rejection is a separate
CLI control. Tool TP/FP/FN/TN count literal expected tools and explicit decoys;
model format, signature uncertainty, scoping and secret redaction are reported
separately as controls. A collection failure makes the case fail and remains
visible. The two pinned upstream examples do not form a representative real-world
sample or establish detection performance across frameworks.

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
  --repo aisecnomad/Nexus-symbiote \
  --signer-workflow aisecnomad/Nexus-symbiote/.github/workflows/release.yml \
  --source-ref refs/heads/main --source-digest "${RELEASE_COMMIT:?set the expected commit}" \
  --deny-self-hosted-runners
```

For a retained copy of the attestation, download `inventory-benchmark-attestation`
from that run and supply its file to `gh attestation verify` with `--bundle`.
Compare the candidate wheel against `wheel.sha256` before using the results for
that distribution. The counts describe the versioned public fixtures.
