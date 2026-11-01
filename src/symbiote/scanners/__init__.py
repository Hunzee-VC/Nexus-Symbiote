"""Scanners discover agent supply chain components from project files."""

from symbiote.scanners.base import Scanner, ScanResult
from symbiote.scanners.mcp import MCPScanner
from symbiote.scanners.model import ModelScanner
from symbiote.scanners.prompt import PromptScanner
from symbiote.scanners.rag import RAGScanner
from symbiote.scanners.registry import RegistryScanner

ALL_SCANNERS: list[type[Scanner]] = [
    MCPScanner,
    ModelScanner,
    PromptScanner,
    RAGScanner,
    RegistryScanner,
]

__all__ = [
    "ALL_SCANNERS",
    "MCPScanner",
    "ModelScanner",
    "PromptScanner",
    "RAGScanner",
    "RegistryScanner",
    "Scanner",
    "ScanResult",
]
