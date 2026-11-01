"""Model identity and serialization risk (WP3).

Static, non-executing analysis of model artefacts — local weights (``serialization``, ``hf``) and hosted
model identifiers (``hosted``) — producing the facts behind ``Model.identity``, ``Model.serialization``,
``Model.derivations`` and the ``SYM-MODEL-*`` checks (``spec/agentbom-profile.md`` §3.8,
``spec/digests.md`` §6, ``spec/checks.md``).
"""

from symbiote.models_identity.hf import Derivation, ModelDirAnalysis, analyze_model_dir, huggingface_purl
from symbiote.models_identity.serialization import (
    RISK_ORDER,
    ChatTemplateFinding,
    FileAssessment,
    GgufMetadata,
    PickleGlobal,
    PickleScan,
    SafetensorsHeader,
    assess_file,
    classify_global,
    max_risk,
    read_gguf_metadata,
    read_safetensors_header,
    scan_chat_template,
    scan_pickle_bytes,
    sniff_format,
)

__all__ = [
    "RISK_ORDER",
    "ChatTemplateFinding",
    "Derivation",
    "FileAssessment",
    "GgufMetadata",
    "ModelDirAnalysis",
    "PickleGlobal",
    "PickleScan",
    "SafetensorsHeader",
    "analyze_model_dir",
    "assess_file",
    "classify_global",
    "huggingface_purl",
    "max_risk",
    "read_gguf_metadata",
    "read_safetensors_header",
    "scan_chat_template",
    "scan_pickle_bytes",
    "sniff_format",
]
