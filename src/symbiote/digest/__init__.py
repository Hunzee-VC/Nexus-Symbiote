"""Canonicalization, typed digests and Merkle commitment (``spec/digests.md``)."""

from __future__ import annotations

from symbiote.digest.dirmanifest import DEFAULT_IGNORE, build_dir_manifest, dirmanifest_digest, manifest_root
from symbiote.digest.envelope import (
    DIGEST_TYPE_BASE,
    digest_str,
    envelope_bytes,
    envelope_digest,
    sha256_hex,
    strip_prefix,
    type_uri,
)
from symbiote.digest.files import bytes_digest, file_digest, line_endings, triage_digest
from symbiote.digest.jcs import UndigestableError, canonical_bytes, parse_json_strict, utf16_sort_key
from symbiote.digest.merkle import (
    MerkleBuilder,
    derive_salt,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    new_nonce,
    redact,
    verify_commitment,
    verify_inclusion,
)
from symbiote.digest.tensormanifest import (
    TensorManifest,
    tensor_manifest,
    tensor_manifest_from_bytes,
    tensormanifest_digest,
)
from symbiote.digest.textflags import (
    cross_tool_directives,
    external_refs,
    hidden_code_points,
    tool_text_flags,
)
from symbiote.digest.tooldef import (
    TOOLDEF_FIELDS,
    agent_digest,
    jsondoc_digest,
    normalize_endpoint,
    prompt_digest,
    server_identity_digest,
    tooldef_digest,
    tooldef_full_digest,
    tooldef_payload,
    toolset_digest,
)

__all__ = [
    "DEFAULT_IGNORE",
    "DIGEST_TYPE_BASE",
    "TOOLDEF_FIELDS",
    "MerkleBuilder",
    "TensorManifest",
    "UndigestableError",
    "agent_digest",
    "build_dir_manifest",
    "bytes_digest",
    "canonical_bytes",
    "cross_tool_directives",
    "derive_salt",
    "digest_str",
    "dirmanifest_digest",
    "envelope_bytes",
    "envelope_digest",
    "external_refs",
    "file_digest",
    "hidden_code_points",
    "inclusion_proof",
    "jsondoc_digest",
    "leaf_hash",
    "line_endings",
    "manifest_root",
    "merkle_root",
    "new_nonce",
    "normalize_endpoint",
    "parse_json_strict",
    "prompt_digest",
    "redact",
    "server_identity_digest",
    "sha256_hex",
    "strip_prefix",
    "tensor_manifest",
    "tensor_manifest_from_bytes",
    "tensormanifest_digest",
    "tool_text_flags",
    "tooldef_digest",
    "tooldef_full_digest",
    "tooldef_payload",
    "toolset_digest",
    "triage_digest",
    "type_uri",
    "utf16_sort_key",
    "verify_commitment",
    "verify_inclusion",
]
