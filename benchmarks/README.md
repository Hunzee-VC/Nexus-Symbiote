# Inventory regression corpus

From a SymBiote development install run `python benchmarks/run_inventory.py`. The command prints per-case predictions, missed and unexpected tool names, control outcomes and counts. It returns nonzero on any mismatch. Run offline. Cases extract declared tools without executing repository code.

The upstream server and its license are in `fixtures/upstream`. The manifest pins the commit, blob and SHA-256, and points to the upstream test that enumerates the expected tools. The remaining cases are hand-labeled regression fixtures. True negatives count only explicitly labeled decoys. This development corpus measures neither production accuracy nor held-out performance.
