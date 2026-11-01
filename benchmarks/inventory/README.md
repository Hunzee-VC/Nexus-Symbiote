# Inventory regression corpus

From a Nexus SymBiote development install run `python benchmarks/inventory/run_inventory.py`. The command prints per-case predictions, missed and unexpected tool names, control outcomes and counts. It returns nonzero on any mismatch. Run offline. Cases extract declared tools without executing repository code.

The upstream server and its license are in `fixtures/upstream`. The manifest pins the commit, blob and SHA-256, and points to the upstream test that enumerates the expected tools. The remaining cases are hand-labeled regression fixtures. True negatives count only explicitly labeled decoys. This development corpus measures neither production accuracy nor held-out performance.

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
visible. This pinned upstream file is one inspectable public example and is not
a representative real-world sample.
