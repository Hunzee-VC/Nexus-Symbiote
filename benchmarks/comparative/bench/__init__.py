"""Comparative AI-BOM benchmark: a generated corpus with ground truth, a sandboxed runner and a scorer.

The method, the scoring rules and their limits are in ``benchmarks/comparative/METHOD.md``.
"""

BENCH_VERSION = "1.0.0"
# Digest of every byte the corpus materializes. A test compares it with the corpus, so
# no case or label changes without this line changing in the same commit.
CORPUS_DIGEST = "935f70a418d8cfa114e6b805a1915e678b89b8386f1386a3bd083c5a16408f8c"
