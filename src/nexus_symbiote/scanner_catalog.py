"""Built-in scanner universe used when assessing static coverage.

Adding a scanner changes the minimum evidence required for a complete scan.
Keep this set synchronized with the CLI registry and its regression test.
"""

BUILTIN_SCANNER_NAMES = frozenset(
    {"mcp", "model", "prompt", "rag", "registry", "a2a", "ide_agents"}
)
