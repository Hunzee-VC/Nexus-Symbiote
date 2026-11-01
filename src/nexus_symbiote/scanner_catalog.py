"""Built-in collection surfaces shared by policy and inventory validators."""

from typing import Literal, get_args

ScannerName = Literal[
    "shadowscan", "mcp", "model", "prompt", "rag", "registry", "a2a", "ide_agents"
]
DEFAULT_SCANNERS: tuple[ScannerName, ...] = get_args(ScannerName)
BUILTIN_SCANNER_NAMES = frozenset(DEFAULT_SCANNERS)
