"""``models-local`` collector: model artefacts on disk (``spec/collectors.md``; WP3 analysis, WP9 collector).

Finds model directories (Hugging Face snapshots, checkpoints, GGUF/ONNX/Keras files) in the repository — and,
with user scope, the Hugging Face hub cache, whose ``snapshots/<commit>`` layout pins the exact revision — and
records for each: an OMS-compatible per-file manifest (``spec/digests.md`` §6), the serialization risk with
scanner evidence, ``trust_remote_code`` and chat-template facts, typed lineage, and signature status. Nothing is
loaded, imported or deserialized (``symbiote.models_identity``).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path
from typing import Final

from symbiote.collect.base import BaseCollector, CollectContext, CollectionResult
from symbiote.digest import build_dir_manifest, canonical_bytes
from symbiote.digest.jcs import UndigestableError
from symbiote.model.common import Claim, Provenance
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    Derivation,
    Evidence,
    ManifestItem,
    Model,
    ModelManifest,
    Serialization,
    SignatureFacts,
    WeightsIdentity,
)
from symbiote.model.enums import (
    ClaimMethod,
    CollectorMode,
    DerivationKind,
    EdgeType,
    EvidenceKind,
    ModelKind,
    SerializationFormat,
    SerializationRisk,
    SignatureStatus,
    Surface,
    TriState,
    UnknownReason,
)
from symbiote.model.ids import make_id
from symbiote.models_identity import ModelDirAnalysis, analyze_model_dir, huggingface_purl
from symbiote.models_identity.hf import WEIGHT_SUFFIXES

__all__ = ["ModelsLocalCollector"]

SCANNER_NAME: Final = "symbiote-models-identity"
SCANNER_VERSION: Final = "0.1.0"
#: Above this total size the per-file manifest is skipped (identity becomes unknown/truncated) unless overridden.
DEFAULT_HASH_BUDGET_BYTES: Final = 8 * 1024**3

_FORMAT_MAP: Final[dict[str, SerializationFormat]] = {
    "safetensors": SerializationFormat.SAFETENSORS,
    "onnx": SerializationFormat.ONNX,
    "gguf": SerializationFormat.GGUF,
    "pickle": SerializationFormat.PICKLE,
    "torch-zip": SerializationFormat.TORCH_ZIP,
    "torchscript": SerializationFormat.TORCH_ZIP,
    "tf-savedmodel": SerializationFormat.TF_SAVEDMODEL,
    "keras-h5": SerializationFormat.KERAS_H5,
    "joblib": SerializationFormat.JOBLIB,
    "npz": SerializationFormat.NPZ,
}
_RISK_MAP: Final[dict[str, SerializationRisk]] = {r.value: r for r in SerializationRisk}
_DERIVATION_MAP: Final[dict[str, DerivationKind]] = {k.value: k for k in DerivationKind}


def _tri(value: bool | None) -> TriState:
    return TriState.UNKNOWN if value is None else (TriState.TRUE if value else TriState.FALSE)


def _is_model_dir(directory: Path) -> bool:
    config = directory / "config.json"
    if any(p.is_file() and p.suffix.lower() in WEIGHT_SUFFIXES for p in directory.iterdir()):
        return True
    return config.is_file() and any(
        (directory / n).exists()
        for n in ("tokenizer_config.json", "generation_config.json", "adapter_config.json")
    )


def _hf_cache_snapshots(home: Path) -> Iterable[tuple[Path, str, str]]:
    """``(snapshot dir, repo_id, commit)`` from ``~/.cache/huggingface/hub/models--org--name/snapshots/<commit>``."""
    hub = home / ".cache" / "huggingface" / "hub"
    if not hub.is_dir():
        return
    for repo_dir in sorted(hub.glob("models--*")):
        repo_id = repo_dir.name.removeprefix("models--").replace("--", "/")
        for snap in sorted((repo_dir / "snapshots").glob("*")):
            if snap.is_dir():
                yield snap, repo_id, snap.name


def _indicators(analysis: ModelDirAnalysis) -> list[str]:
    tags: list[str] = []
    for f in analysis.files:
        for _member, scan in f.pickle_scans:
            tags.extend(f"malicious-indicator:pickle-global:{g.qualified}" for g in scan.dangerous)
            if scan.malformed:
                tags.append(f"malicious-indicator:malformed-pickle:{f.path}")
        for t in f.chat_templates:
            tags.extend(f"malicious-indicator:ssti:{i}" for i in t.ssti_indicators)
        if f.safetensors is not None:
            tags.extend(f"format-anomaly:{a}" for a in f.safetensors.anomalies)
        if f.format == "archive-7z":
            tags.append(f"malicious-indicator:opaque-archive:{f.path}")
    for t in analysis.chat_templates:
        tags.extend(f"malicious-indicator:ssti:{i}" for i in t.ssti_indicators)
    return sorted(dict.fromkeys(tags))


def _report(analysis: ModelDirAnalysis) -> dict[str, object]:
    return {
        "scanner": {"name": SCANNER_NAME, "version": SCANNER_VERSION},
        "riskClass": analysis.risk_class,
        "trustRemoteCode": analysis.trust_remote_code,
        "files": [
            {
                "path": f.path,
                "format": f.format,
                "riskClass": f.risk_class,
                "reasons": list(f.reasons),
                "pickle": [{"member": m, **s.to_report()} for m, s in f.pickle_scans],
                "safetensorsAnomalies": list(f.safetensors.anomalies) if f.safetensors else [],
            }
            for f in analysis.files
        ],
        "chatTemplates": [
            {"source": t.source, "digest": t.digest, "ssti": list(t.ssti_indicators)}
            for t in analysis.chat_templates
        ],
    }


class ModelsLocalCollector(BaseCollector):
    """Local model artefacts: identity manifest, serialization risk, lineage, signature status."""

    name = "models-local"
    version = "0.1.0"
    surfaces = (Surface.CODE,)
    mode = CollectorMode.DECLARED

    def detect(self, ctx: CollectContext) -> bool:
        del ctx
        return True

    def _candidates(self, ctx: CollectContext) -> list[tuple[Path, str | None, str | None]]:
        dirs: dict[Path, tuple[str | None, str | None]] = {}
        for extra in ctx.options.get("models", []) or []:
            path = Path(extra)
            if path.is_dir():
                dirs[path] = (None, None)
        seen_parents: set[Path] = set()
        for file in ctx.walk():
            parent = file.parent
            if parent in seen_parents:
                continue
            if file.suffix.lower() in WEIGHT_SUFFIXES or file.name == "config.json":
                seen_parents.add(parent)
                if _is_model_dir(parent):
                    dirs.setdefault(parent, (None, None))
        if ctx.home is not None and ctx.options.get("hf_cache", False):
            for snap, repo_id, commit in _hf_cache_snapshots(ctx.home):
                dirs[snap] = (repo_id, commit)
        return [(d, repo, rev) for d, (repo, rev) in sorted(dirs.items())]

    def collect(self, ctx: CollectContext) -> CollectionResult:
        result = self.new_result()
        budget = int(ctx.options.get("models_hash_budget_bytes", DEFAULT_HASH_BUDGET_BYTES))
        for directory, repo_id, revision in self._candidates(ctx):
            display = ctx.display(directory)
            try:
                analysis = analyze_model_dir(directory)
                self._emit(
                    ctx,
                    result,
                    directory=directory,
                    display=display,
                    analysis=analysis,
                    repo_id=repo_id,
                    revision=revision,
                    budget=budget,
                )
            except OSError as exc:
                result.add_source(
                    Surface.CODE, "model-dir", locator=display, ok=False, error_class="unreadable"
                )
                result.warnings.append(f"{display}: {type(exc).__name__}: {exc}")
        if not any(s.source == "model-dir" for c in result.coverage.values() for s in c.sources):
            result.add_source(Surface.CODE, "model-dir", ok=True, items=0)
        return result

    def _emit(
        self,
        ctx: CollectContext,
        result: CollectionResult,
        *,
        directory: Path,
        display: str,
        analysis: ModelDirAnalysis,
        repo_id: str | None,
        revision: str | None,
        budget: int,
    ) -> None:
        model_id = make_id("model", repo_id or display)
        prov = Provenance(
            method=ClaimMethod.MANIFEST, locator=display, collector=self.ref, observed_at=ctx.now
        )
        total = sum(
            p.stat().st_size
            for p in directory.rglob("*")
            if p.is_file() and not p.is_symlink() and ".git" not in p.parts
        )
        manifest: ModelManifest | None = None
        weights: Claim[WeightsIdentity]
        formats = sorted(
            {_FORMAT_MAP.get(f.format, SerializationFormat.OTHER) for f in analysis.files},
            key=lambda f: f.value,
        )
        purl, _pinned = huggingface_purl(repo_id, revision) if repo_id else (None, False)
        if total > budget:
            weights = Claim.unknown(UnknownReason.TRUNCATED, locator=display, collector=self.ref)
            result.add_source(Surface.CODE, "model-dir", locator=display, ok=False, error_class="truncated")
            result.warnings.append(
                f"{display}: {total} bytes exceeds the hashing budget; identity not computed"
            )
        else:
            try:
                dm = build_dir_manifest(directory)
            except UndigestableError as exc:
                weights = Claim.unknown(UnknownReason.UNSUPPORTED_SOURCE, locator=display, collector=self.ref)
                result.add_source(
                    Surface.CODE, "model-dir", locator=display, ok=False, error_class="undigestable"
                )
                result.warnings.append(f"{display}: {exc}")
            else:
                manifest = ModelManifest(
                    resources=[ManifestItem(name=i.name, digest=i.digest, size=i.size) for i in dm.resources],
                    root=dm.root,
                    ignore=list(dm.ignore),
                )
                weights = Claim.declared(
                    WeightsIdentity(
                        purl=purl, manifest_root=dm.root, file_count=len(dm.resources), formats=formats
                    ),
                    locator=display,
                    collector=self.ref,
                    method=ClaimMethod.HASH_COMPARISON,
                    observed_at=ctx.now,
                )
                result.add_source(
                    Surface.CODE, "model-dir", locator=display, ok=True, items=len(dm.resources)
                )
        report_bytes = canonical_bytes(_report(analysis))
        report_digest = "sha256:" + hashlib.sha256(report_bytes).hexdigest()
        evidence = Evidence(
            id="ev:" + report_digest[7:19],
            evidence_kind=EvidenceKind.SCAN_REPORT,
            media_type="application/vnd.symbiote.model-scan+json",
            digest=report_digest,
            created=ctx.now,
        )
        if not any(e.id == evidence.id for e in result.evidence):
            result.evidence.append(evidence)
        serialization = Claim.declared(
            Serialization(
                formats=formats,
                risk_class=_RISK_MAP[analysis.risk_class],
                trust_remote_code=_tri(analysis.trust_remote_code),
                chat_template_executable=_tri(analysis.chat_template_executable),
                scanner_name=SCANNER_NAME,
                scanner_version=SCANNER_VERSION,
                scanner_report_digest=report_digest,
            ),
            locator=display,
            collector=self.ref,
            method=ClaimMethod.MANIFEST,
            observed_at=ctx.now,
        )
        derivations = [
            Derivation(
                kind=_DERIVATION_MAP[d.kind],
                parent=d.parent,
                parent_state="unknown" if d.parent in {"", "unknown"} else "present",
                parameters=dict(d.parameters),
                parameters_digest=d.parameters_digest,
                assurance="declared",
            )
            for d in analysis.derivations
        ]
        kind = ModelKind.ADAPTER if (directory / "adapter_config.json").is_file() else ModelKind.WEIGHTS
        if (directory / "config_sentence_transformers.json").is_file() or (
            directory / "modules.json"
        ).is_file():
            kind = ModelKind.EMBEDDING
        tags = _indicators(analysis)
        if analysis.trust_remote_code:
            tags.append("trust-remote-code")
        if analysis.custom_code_files:
            tags.append(f"custom-code-files:{len(analysis.custom_code_files)}")
        tags += [f"chat-template:{t.digest[7:19]}" for t in analysis.chat_templates]
        model = Model(
            id=model_id,
            name=repo_id or directory.name,
            provenance=prov,
            tags=sorted(dict.fromkeys(tags)),
            model_kind=kind,
            weights=weights,
            manifest=manifest,
            serialization=serialization,
            derivations=derivations,
            signature=SignatureFacts(
                status=SignatureStatus.CLAIMED if analysis.signature_bundles else SignatureStatus.UNSIGNED
            ),
            generation_config_digest=analysis.config_digests.get("generation_config.json"),
        )
        result.entities.append(model)
        result.edges.append(
            Edge.model_validate(
                {
                    "type": EdgeType.DEPENDS_ON,
                    "from": ctx.agent_id,
                    "to": model_id,
                    "qualifiers": {"relation": "local-model-artifact"},
                    "declaredBy": display,
                }
            )
        )
        result.warnings.extend(f"{display}: {w}" for w in analysis.warnings)
