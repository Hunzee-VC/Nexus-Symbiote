#!/usr/bin/env python3
"""Positive control for AIBOM-Bench: a deliberately unsafe "scanner".

It does everything a scanner must never do with an untrusted repository, so that
every safety probe of the benchmark can be shown to fire inside the sandbox:
deserializes pickles, starts MCP launch commands, builds the project with pip and
npm, connects out, reads through escaping symlinks, and echoes file contents
(credentials and terminal escape sequences included) to standard output.

Run it only through run.py, inside the sandbox, on the generated corpus.

    executor.py <scan_dir> <out_dir>
"""

from __future__ import annotations

import json
import pickle
import socket
import subprocess
import sys
import zipfile
from pathlib import Path

MAX_PICKLE = 64 * 1024**2


def load_pickles(root: Path) -> None:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            if p.suffix == ".pkl":
                pickle.loads(p.read_bytes())  # noqa: S301 - this is the point
            elif zipfile.is_zipfile(p):
                with zipfile.ZipFile(p) as z:
                    for info in z.infolist():
                        if info.filename.endswith("data.pkl") and info.file_size < MAX_PICKLE:
                            pickle.loads(z.read(info))  # noqa: S301
        except Exception as exc:  # noqa: BLE001
            print(f"pickle {p.name}: {type(exc).__name__}", file=sys.stderr)


def start_mcp_servers(root: Path) -> list[dict[str, str]]:
    found = []
    for cfg in list(root.rglob("mcp.json")) + list(root.rglob(".mcp.json")):
        try:
            servers = json.loads(cfg.read_text()).get("mcpServers", {})
        except Exception:  # noqa: BLE001, S112
            continue
        for name, spec in servers.items():
            found.append({"name": name, "type": "mcp server", "file": str(cfg.relative_to(root))})
            cmd = spec.get("command")
            if cmd == "sh":
                subprocess.run([cmd, *spec.get("args", [])], timeout=10, check=False)  # noqa: S603
    return found


def build_project(root: Path) -> None:
    if (root / "pyproject.toml").exists() or (root / "setup.py").exists():
        subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "-e", "."],  # noqa: S603
                       cwd=root, timeout=60, check=False)  # fmt: skip
        if (root / "setup.py").exists():
            subprocess.run([sys.executable, "setup.py", "--version"], cwd=root, timeout=30,  # noqa: S603
                           check=False)  # fmt: skip
    if (root / "package.json").exists():
        subprocess.run(["npm", "install", "--offline", "--no-audit", "--no-fund"], cwd=root,  # noqa: S607
                       timeout=60, check=False)  # fmt: skip


def phone_home() -> None:
    try:
        socket.create_connection(("192.0.2.1", 443), timeout=1)
    except OSError:
        pass


def echo_everything(root: Path) -> None:
    for p in sorted(root.rglob("*")):
        try:
            if p.is_file() and p.stat().st_size < 1 << 20:
                sys.stdout.buffer.write(p.read_bytes() + b"\n")
        except OSError:
            continue


def main() -> None:
    root, out = Path(sys.argv[1]), Path(sys.argv[2])
    phone_home()
    load_pickles(root)
    servers = start_mcp_servers(root)
    build_project(root)
    echo_everything(root)
    (out / "inventory.json").write_text(json.dumps({"components": servers}))


if __name__ == "__main__":
    main()
