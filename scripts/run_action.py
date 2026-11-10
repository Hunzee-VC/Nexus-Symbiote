"""GitHub Action entry point: inputs are data, and exports share one collection."""

from __future__ import annotations

import functools
import hashlib
import importlib
import json
import math
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

SCANNERS = frozenset(
    {"shadowscan", "mcp", "model", "prompt", "rag", "registry", "a2a", "ide_agents"}
)
FORMATS = frozenset({"json", "cyclonedx", "spdx", "sarif"})
SIGSTORE_MODULES = (
    "sigstore.hashes",
    "sigstore.models",
    "sigstore.verify",
    "sigstore.verify.policy",
    "sigstore_models.common.v1",
)


def _boolean(value: str) -> bool:
    if value not in {"true", "false"}:
        raise ValueError("boolean inputs must be true or false")
    return value == "true"


def _within(workspace: Path, value: str) -> Path:
    if not value or any(c in value for c in "\r\n\x00"):
        raise ValueError("paths must be nonempty and contain no newline or NUL")
    path = (workspace / value).absolute()
    if (
        ".." in path.parts
        or not path.is_relative_to(workspace)
        or not path.resolve().is_relative_to(workspace)
    ):
        raise ValueError("Action paths must stay within GITHUB_WORKSPACE")
    return path


def _caller_owned(workspace: Path, value: str) -> bytes:
    from nexus_symbiote.core.hashing import open_regular_file
    from nexus_symbiote.signature_policy import MAX_POLICY_BYTES

    outside = "signature-policy must be an absolute path outside GITHUB_WORKSPACE"
    path = Path(value)
    if (
        any(c in value for c in "\r\n\x00")
        or not path.is_absolute()
        or ".." in path.parts
        or path.is_relative_to(workspace)
    ):
        raise ValueError(outside)
    try:
        # No-follow traversal makes the literal path the real one. Comparing its
        # ancestors' device and inode with the workspace also catches aliases
        # that a lexical check misses: case-insensitive names and bind mounts.
        with open_regular_file(path) as stream:
            content = stream.read(MAX_POLICY_BYTES + 1)
            links = os.fstat(stream.fileno()).st_nlink
        ancestors = {(s.st_dev, s.st_ino) for s in map(os.stat, path.parents)}
    except OSError:
        raise ValueError(
            "signature-policy must be a regular file reached without symlinks"
        ) from None
    root = os.stat(workspace)
    if (root.st_dev, root.st_ino) in ancestors:
        raise ValueError(outside)
    if links != 1:
        raise ValueError(
            "signature-policy must not be a hard link, which can alias a workspace file"
        )
    if len(content) > MAX_POLICY_BYTES:
        raise ValueError("signature-policy exceeds the byte limit")
    return content


def _require_sigstore() -> None:
    # Without sigstore every signature would fail verification after a full
    # scan, so a supplied policy would silently change nothing.
    try:
        for module in SIGSTORE_MODULES:
            importlib.import_module(module)
    except ImportError:
        raise ValueError(
            "signature-policy needs sigstore, which this Action runtime cannot import"
        ) from None


@dataclass(frozen=True)
class Config:
    workspace: Path
    project: Path
    output: Path
    format: str
    scanners: tuple[str, ...]
    validate: bool
    risk_check: bool
    threshold: float
    sarif: bool
    signature_policy: bytes | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Config:
        workspace = Path(env["GITHUB_WORKSPACE"]).resolve(strict=True)
        project = _within(workspace, env.get("SYMBIOTE_SCAN_PATH", "."))
        if not project.is_dir():
            raise ValueError("scan-path must be an existing directory")
        output_value = env.get("SYMBIOTE_OUTPUT_FILE", "nexus-symbiote-aibom.json")
        if any(c in output_value for c in "*?[]!"):
            raise ValueError("output-file must be a literal artifact path without glob syntax")
        output = _within(workspace, output_value)
        fmt = env.get("SYMBIOTE_FORMAT", "json")
        if fmt not in FORMATS:
            raise ValueError("unsupported output format")
        scanners = tuple(
            s.strip() for s in env.get("SYMBIOTE_SCANNERS", "").split(",") if s.strip()
        )
        if len(scanners) != len(set(scanners)) or set(scanners) - SCANNERS:
            raise ValueError("scanners must be distinct supported names")
        threshold = float(env.get("SYMBIOTE_RISK_THRESHOLD", "50"))
        if not math.isfinite(threshold) or not 0 <= threshold <= 100:
            raise ValueError("risk-threshold must be finite and between 0 and 100")
        policy = env.get("SYMBIOTE_SIGNATURE_POLICY", "")
        signers = _caller_owned(workspace, policy) if policy else None
        if signers is not None:
            _require_sigstore()
        return cls(
            workspace,
            project,
            output,
            fmt,
            scanners,
            _boolean(env.get("SYMBIOTE_VALIDATE", "true")),
            _boolean(env.get("SYMBIOTE_RISK_CHECK", "true")),
            threshold,
            _boolean(env.get("SYMBIOTE_SARIF", "false")),
            signers,
        )


def _run(args: list[str], *, private: Path) -> subprocess.CompletedProcess[str]:
    # Offline Sigstore verification trusts any trusted_root.json in the per-user
    # cache without checking it, and an earlier job or step can plant one there.
    # An empty private home makes sigstore seed it from its hash-locked package.
    env = {
        **os.environ,
        "HOME": str(private),
        "XDG_CACHE_HOME": str(private / "cache"),
        "XDG_DATA_HOME": str(private / "data"),
    }
    # The executable is this interpreter; arguments never pass through a shell.
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-m", "nexus_symbiote", *args],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _write(path: Path, content: str, *, root: Path | None = None) -> None:
    from nexus_symbiote.utils.files import write_output_file

    write_output_file(path, content, root=root, create_parents=True)


def _export(
    native: Path,
    output: Path,
    fmt: str,
    *,
    root: Path | None = None,
    scan_root: Path | None = None,
) -> None:
    if fmt == "json":
        _write(output, native.read_text(encoding="utf-8"), root=root)
        return
    from nexus_symbiote.core.aibom import AIBOM
    from nexus_symbiote.generators.base import Generator
    from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
    from nexus_symbiote.generators.sarif import SARIFGenerator
    from nexus_symbiote.generators.spdx import SPDXGenerator

    # SARIF URIs are relative to the workspace; inventory paths to the scanned project.
    generators: dict[str, Generator] = {
        "cyclonedx": CycloneDXGenerator(),
        "sarif": SARIFGenerator(root, scan_root=scan_root),
        "spdx": SPDXGenerator(),
    }
    _write(output, generators[fmt].generate_json(AIBOM.load(native)), root=root)


def run(
    config: Config,
    *,
    command: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
    export: Callable[[Path, Path, str], None] | None = None,
    outputs: Path | None = None,
) -> int:
    def emit(**values: str) -> None:
        if outputs is not None:
            with outputs.open("a", encoding="utf-8") as stream:
                for name, value in values.items():
                    if any(c in value for c in "\r\n"):
                        raise ValueError("invalid multiline Action output")
                    stream.write(f"{name}={value}\n")

    def emit_export(native: Path, output: Path, fmt: str) -> None:
        if export is None:
            _export(native, output, fmt, root=config.workspace, scan_root=config.project)
        else:
            export(native, output, fmt)

    emit(risk_score="", passed="skipped")
    with tempfile.TemporaryDirectory(prefix="nexus-symbiote-action-") as created:
        # The CLI refuses symlinked directories, and macOS temp paths contain one.
        scratch = Path(created).resolve(strict=True)
        if command is None:
            private = scratch / "home"
            private.mkdir(mode=0o700)
            command = functools.partial(_run, private=private)
        native = scratch / "native.json"
        signers: list[str] = []
        if config.signature_policy is not None:
            # Collection and validation read one snapshot of the caller's trust root.
            snapshot = scratch / "signature-policy.json"
            snapshot.write_bytes(config.signature_policy)
            signers = ["--signature-policy", str(snapshot)]
            digest = hashlib.sha256(config.signature_policy).hexdigest()
            emit(signature_policy_digest=f"sha256:{digest}")
        args = [
            "scan",
            "--no-project-policy",
            "--report-only",
            "--format",
            "json",
            "--output",
            str(native),
            *signers,
        ]
        for scanner in config.scanners:
            args.extend(["--scanner", scanner])
        collected = command([*args, "--", str(config.project)])
        if collected.returncode != 0:
            print(collected.stderr, file=sys.stderr)
            return 1
        emit_export(native, config.output, config.format)
        emit(aibom_path=str(config.output))
        inventory = json.loads(native.read_text(encoding="utf-8"))
        if inventory.get("metadata", {}).get("completeness", {}).get("scan_failures"):
            print("Collection failed; review the partial inventory", file=sys.stderr)
            return 1
        if config.sarif:
            sarif = config.output.with_name(config.output.name + ".sarif")
            emit_export(native, sarif, "sarif")
            emit(sarif_path=str(sarif))
        if config.validate:
            validated = command(
                [
                    "validate",
                    "--no-project-policy",
                    str(native),
                    "--project",
                    str(config.project),
                    *signers,
                ]
            )
            if validated.returncode != 0:
                print(validated.stderr, file=sys.stderr)
                return 1
        if config.risk_check and config.threshold != 0:
            scored = command(
                [
                    "risk",
                    "--no-project-policy",
                    str(native),
                    "--threshold",
                    str(config.threshold),
                    "--json-output",
                ]
            )
            if scored.returncode not in {0, 1}:
                raise ValueError("risk evaluation failed to run")
            report = json.loads(scored.stdout)
            score = report.get("overall_score")
            if (
                isinstance(score, bool)
                or not isinstance(score, (int, float))
                or not math.isfinite(score)
            ):
                raise ValueError("risk evaluation returned no finite numeric score")
            emit(risk_score=str(score), passed="true" if scored.returncode == 0 else "false")
            if scored.returncode != 0:
                return 1
    return 0


def main() -> int:
    try:
        config = Config.from_env(os.environ)
        output_path = Path(os.environ["GITHUB_OUTPUT"]) if os.environ.get("GITHUB_OUTPUT") else None
        return run(config, outputs=output_path)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Nexus SymBiote action failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
