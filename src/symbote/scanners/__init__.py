"""Scanners discover agent supply chain components from project files."""

from symbote.scanners.base import Scanner, ScanResult
from symbote.scanners.mcp import MCPScanner
from symbote.scanners.model import ModelScanner
from symbote.scanners.prompt import PromptScanner
from symbote.scanners.rag import RAGScanner
from symbote.scanners.registry import RegistryScanner

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
