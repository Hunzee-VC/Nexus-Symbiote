"""Scanners discover agent supply chain components from project files.

Nexus-ShadowScan is the preferred primary discovery engine for multi-surface
agent inventory. The ShadowScanImporter consumes its reports. Local scanners
remain available for fine-grained, project-local verification.
"""

from symbiote.scanners.a2a import A2AScanner
from symbiote.scanners.base import Scanner, ScanResult
from symbiote.scanners.ide_agents import IDEAgentScanner
from symbiote.scanners.mcp import MCPScanner
from symbiote.scanners.model import ModelScanner
from symbiote.scanners.prompt import PromptScanner
from symbiote.scanners.rag import RAGScanner
from symbiote.scanners.registry import RegistryScanner
from symbiote.scanners.shadowscan import ShadowScanImporter

ALL_SCANNERS: list[type[Scanner]] = [
    ShadowScanImporter,  # primary discovery
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
    "ShadowScanImporter",
]
