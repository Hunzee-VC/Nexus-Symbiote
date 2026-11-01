"""Tests for component scanners."""

from __future__ import annotations

import json

from symbote.core.enums import ComponentType, RiskSeverity, SerializationSafety
from symbote.scanners.mcp import MCPScanner
from symbote.scanners.model import ModelScanner
from symbote.scanners.prompt import PromptScanner
from symbote.scanners.rag import RAGScanner
from symbote.scanners.registry import RegistryScanner


class TestMCPScanner:
    def test_scan_mcp_json_config(self, tmp_path):
        config = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/data"],
                }
            }
        }
        (tmp_path / "mcp.json").write_text(json.dumps(config))
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) >= 1
        mcp_comps = [c for c in result.components if c.component_type == ComponentType.MCP_SERVER]
        assert len(mcp_comps) >= 1
        assert mcp_comps[0].name == "filesystem"

    def test_scan_claude_config(self, tmp_path):
        config = {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": "***"},
                }
            }
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(config))
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) >= 1

    def test_scan_no_config(self, tmp_path):
        scanner = MCPScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) == 0
        assert len(result.surfaces_excluded) > 0


class TestModelScanner:
    def test_scan_safetensors(self, tmp_path):
        model_dir = tmp_path / "my_model"
        model_dir.mkdir()
        (model_dir / "model.safetensors").write_bytes(b"\x00" * 100)
        (model_dir / "config.json").write_text('{"model_type": "llama"}')

        scanner = ModelScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) >= 1
        comp = result.components[0]
        assert comp.component_type == ComponentType.MODEL
        assert comp.serialization_safety == SerializationSafety.SAFE

    def test_scan_pickle_flags_risk(self, tmp_path):
        model_dir = tmp_path / "unsafe_model"
        model_dir.mkdir()
        (model_dir / "model.pkl").write_bytes(b"\x00" * 100)

        scanner = ModelScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) >= 1
        comp = result.components[0]
        assert comp.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION
        critical_risks = [r for r in comp.risks if r.severity == RiskSeverity.CRITICAL]
        assert len(critical_risks) >= 1

    def test_scan_trust_remote_code(self, tmp_path):
        model_dir = tmp_path / "remote_code_model"
        model_dir.mkdir()
        (model_dir / "model.safetensors").write_bytes(b"\x00" * 100)
        (model_dir / "config.json").write_text('{"trust_remote_code": true}')

        scanner = ModelScanner()
        result = scanner.scan(tmp_path)
        comp = result.components[0]
        assert comp.trust_remote_code is True
        critical = [r for r in comp.risks if r.category == "code_execution"]
        assert len(critical) >= 1

    def test_scan_no_models(self, tmp_path):
        scanner = ModelScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) == 0


class TestPromptScanner:
    def test_scan_claude_md(self, tmp_path):
        (tmp_path / "CLAUDE.md").write_text("You are a helpful assistant.")
        scanner = PromptScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) >= 1
        comp = result.components[0]
        assert comp.component_type == ComponentType.PROMPT_TEMPLATE
        assert comp.content_hash is not None

    def test_scan_cursorrules(self, tmp_path):
        (tmp_path / ".cursorrules").write_text("Always use TypeScript.")
        scanner = PromptScanner()
        result = scanner.scan(tmp_path)
        prompts = [c for c in result.components if c.component_type == ComponentType.PROMPT_TEMPLATE]
        assert len(prompts) >= 1

    def test_scan_skills_directory(self, tmp_path):
        skill_dir = tmp_path / ".claude" / "skills"
        skill_dir.mkdir(parents=True)
        (skill_dir / "deploy.md").write_text("Deploy the app")
        scanner = PromptScanner()
        result = scanner.scan(tmp_path)
        skills = [c for c in result.components if c.component_type == ComponentType.SKILL_PACKAGE]
        assert len(skills) >= 1

    def test_scan_no_prompts(self, tmp_path):
        scanner = PromptScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) == 0


class TestRAGScanner:
    def test_scan_rag_config(self, tmp_path):
        config = {
            "sources": [
                {
                    "name": "docs-index",
                    "type": "vector-store",
                    "embedding_model": "text-embedding-3-small",
                    "source_uris": ["https://docs.example.com"],
                }
            ]
        }
        (tmp_path / "rag_config.json").write_text(json.dumps(config))
        scanner = RAGScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) >= 1
        assert result.components[0].corpus_type == "vector-store"

    def test_scan_env_detection(self, tmp_path):
        (tmp_path / ".env.example").write_text("PINECONE_API_KEY=xxx\nPINECONE_INDEX=my-index\n")
        scanner = RAGScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) >= 1

    def test_scan_python_imports(self, tmp_path):
        (tmp_path / "app.py").write_text("import chromadb\nclient = chromadb.Client()\n")
        scanner = RAGScanner()
        result = scanner.scan(tmp_path)
        chroma = [c for c in result.components if "chroma" in c.name]
        assert len(chroma) >= 1

    def test_scan_no_rag(self, tmp_path):
        scanner = RAGScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) == 0


class TestRegistryScanner:
    def test_scan_npm_ai_deps(self, tmp_path):
        pkg = {
            "dependencies": {
                "@modelcontextprotocol/sdk": "^1.0.0",
                "express": "^4.18.0",
            }
        }
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        scanner = RegistryScanner()
        result = scanner.scan(tmp_path)
        ai_deps = [c for c in result.components if "modelcontextprotocol" in c.name]
        assert len(ai_deps) >= 1
        non_ai = [c for c in result.components if "express" in c.name]
        assert len(non_ai) == 0

    def test_scan_pip_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("transformers==4.40.0\nrequests>=2.31\n")
        scanner = RegistryScanner()
        result = scanner.scan(tmp_path)
        assert any(c.name == "transformers" for c in result.components)

    def test_scan_unpinned_version_risk(self, tmp_path):
        pkg = {"dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        scanner = RegistryScanner()
        result = scanner.scan(tmp_path)
        for comp in result.components:
            if "modelcontextprotocol" in comp.name:
                pin_risks = [r for r in comp.risks if r.category == "version_pinning"]
                assert len(pin_risks) >= 1

    def test_scan_no_deps(self, tmp_path):
        scanner = RegistryScanner()
        result = scanner.scan(tmp_path)
        assert len(result.components) == 0
