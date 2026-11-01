"""Scanners discover agent supply chain components from project files."""

from symbiote.scanners.a2a import A2AScanner
from symbiote.scanners.base import Scanner, ScanResult
from symbiote.scanners.ide_agents import IDEAgentScanner
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
    A2AScanner,
    IDEAgentScanner,
]

__all__ = [
    "ALL_SCANNERS",
    "A2AScanner",
    "IDEAgentScanner",
    "MCPScanner",
    "ModelScanner",
    "PromptScanner",
    "RAGScanner",
    "RegistryScanner",
    "Scanner",
    "ScanResult",
]
