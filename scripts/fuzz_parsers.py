"""Bounded parser fuzz harness (`R1.0.0-1`).

Exercises every in-process parser entry point (YAML, TOML, JSONC, GGUF, SafeTensors,
requirements/Dockerfile, ECMA-262 regex translation, and tree-sitter TypeScript) under
offline enforcement. Runs a deterministic mutation corpus by default (`--iterations N`)
and attaches to `atheris` coverage-guided fuzzing when `--atheris` is passed in an
environment where `atheris` is installed.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
import tempfile
import tomllib
from pathlib import Path

from nexus_symbiote import modes
from nexus_symbiote.policy import PolicyError, parse_yaml_mapping
from nexus_symbiote.runtime_validation import ecma_pattern
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.scanners.ts_tools import collect_typescript_source

SEED_CORPUS: tuple[bytes, ...] = (
    b"version: '1.0'\nrisk:\n  fail_threshold: 40.0\n",
    b"[mcp_servers.demo]\ncommand = 'npx'\nargs = ['-y', '@acme/mcp@1.0.0']\n",
    b'// comment\n{"mcpServers": {"s": {"command": "node", "args": ["a.js"]}}}',
    b"GGUF" + struct.pack("<IQQ", 3, 0, 0),
    struct.pack("<Q", 2) + b"{}",
    b"torch==2.4.0 --hash=sha256:" + b"a" * 64 + b"\nFROM vllm/vllm-openai:v0.6.0\n",
    b"^[a-z0-9_\\p{L}]{1,32}$",
    b"import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n"
    b"const s = new McpServer({ name: 'demo', version: '1.0.0' });\n",
)


def exercise_one_input(data: bytes) -> None:
    """Feed arbitrary bytes into every bounded parser entry point; expected errors are caught."""
    text = data.decode("utf-8", errors="replace")

    try:
        parse_yaml_mapping(text[:4096], max_nodes=256)
    except (PolicyError, ValueError):
        pass

    try:
        tomllib.loads(text[:4096])
    except (tomllib.TOMLDecodeError, ValueError):
        pass

    try:
        ecma_pattern(text[:256])
    except (ValueError, re.error):
        pass

    collect_typescript_source(Path("server.ts"), data[:4096], ScanResult(scanner_name="mcp"))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".mcp.json").write_bytes(data[:4096])
        (root / "requirements.txt").write_bytes(data[:4096])
        (root / "Dockerfile").write_bytes(data[:4096])
        (root / "model.gguf").write_bytes(data[:4096])
        (root / "model.safetensors").write_bytes(data[:4096])

        MCPScanner().scan(root)
        RegistryScanner().scan(root)
        ModelScanner().scan(root)


def _mutate(seed: bytes, step: int) -> bytes:
    digest = hashlib.sha256(seed + step.to_bytes(4, "little")).digest()
    if not seed:
        return digest
    idx = digest[0] % len(seed)
    mode = digest[1] % 4
    if mode == 0:
        return seed[:idx] + bytes([seed[idx] ^ digest[2]]) + seed[idx + 1 :]
    if mode == 1:
        return seed[:idx] + digest[:8] + seed[idx:]
    if mode == 2:
        return seed[:idx] + seed[idx + 1 :]
    return digest + seed[:64]


def run_deterministic(iterations: int) -> int:
    with modes.enforce(modes.Mode.OFFLINE):
        for seed in SEED_CORPUS:
            exercise_one_input(seed)
        for step in range(iterations):
            base = SEED_CORPUS[step % len(SEED_CORPUS)]
            exercise_one_input(_mutate(base, step))
    return len(SEED_CORPUS) + iterations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=64, help="Deterministic mutations to run")
    parser.add_argument("--atheris", action="store_true", help="Run under coverage-guided atheris")
    args = parser.parse_args(argv)
    if args.iterations < 0:
        raise SystemExit("--iterations must be non-negative")
    if args.atheris:
        import importlib
        import sys

        atheris = importlib.import_module("atheris")
        atheris.Setup([sys.argv[0]], exercise_one_input)
        atheris.Fuzz()
        return 0
    total = run_deterministic(args.iterations)
    print(f"Parser fuzz harness: {total} inputs exercised across 8 readers with 0 crashes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
