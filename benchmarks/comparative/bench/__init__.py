"""Comparative AI-BOM benchmark: a generated corpus with ground truth, a sandboxed runner and a scorer.

The method, the scoring rules and their limits are in ``benchmarks/comparative/METHOD.md``.
"""

BENCH_VERSION = "1.0.0"
# Digest of every byte the corpus materializes. A test compares it with the corpus, so
# no case or label changes without this line changing in the same commit.
CORPUS_DIGEST = "93cf36ee3a2fbc24f4502c124f0686a086a214e0cec6601ea62d6f42174694fb"
