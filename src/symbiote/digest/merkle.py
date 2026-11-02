"""Salted RFC 6962-style Merkle commitment with inclusion proofs and verifiable redaction (``spec/digests.md §5``)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Mapping, Sequence
from typing import Any

from symbiote.digest.envelope import type_uri
from symbiote.digest.jcs import canonical_bytes
from symbiote.model.snapshot import MerkleCommitment, MerkleLeaf

LEAF_TYPE = type_uri("leaf/v1")
ALGORITHM = "rfc6962-sha256-salted"
_SALT_INFO = b"agentbom-leaf"


def new_nonce() -> bytes:
    return secrets.token_bytes(32)


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_salt(nonce: bytes, kind: str, entity_id: str) -> bytes:
    """16-byte per-leaf salt = HKDF-SHA256(ikm=nonce, salt="agentbom-leaf", info=kind‖"/"‖id)."""
    return _hkdf_sha256(nonce, _SALT_INFO, f"{kind}/{entity_id}".encode(), 16)


def leaf_hash(kind: str, entity_id: str, body: Any, salt: bytes) -> bytes:
    payload = {"_type": LEAF_TYPE, "salt": salt.hex(), "kind": kind, "id": entity_id, "body": body}
    return hashlib.sha256(b"\x00" + canonical_bytes(payload)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaf_hashes: Sequence[bytes]) -> bytes:
    """RFC 6962-shaped tree: adjacent pairs are hashed; an odd trailing node is promoted unchanged."""
    if not leaf_hashes:
        return hashlib.sha256(b"").digest()
    level = list(leaf_hashes)
    while len(level) > 1:
        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def inclusion_proof(leaf_hashes: Sequence[bytes], index: int) -> list[tuple[str, str]]:
    """Return ``[(side, sibling_hex), ...]`` from the leaf up; ``side`` is where the sibling sits (``left``/``right``)."""
    if not 0 <= index < len(leaf_hashes):
        raise IndexError(index)
    proof: list[tuple[str, str]] = []
    level = list(leaf_hashes)
    pos = index
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(node_hash(level[i], level[i + 1]))
        odd = len(level) % 2 == 1
        if odd:
            nxt.append(level[-1])
        if odd and pos == len(level) - 1:
            pass  # promoted unchanged: no sibling at this level
        elif pos % 2 == 0:
            proof.append(("right", level[pos + 1].hex()))
        else:
            proof.append(("left", level[pos - 1].hex()))
        pos //= 2
        level = nxt
    return proof


def verify_inclusion(leaf: bytes, proof: Sequence[tuple[str, str]], root: bytes) -> bool:
    node = leaf
    for side, sibling_hex in proof:
        sibling = bytes.fromhex(sibling_hex)
        node = node_hash(node, sibling) if side == "right" else node_hash(sibling, node)
    return hmac.compare_digest(node, root)


class MerkleBuilder:
    """Collects ``(kind, id, body)`` leaves and produces a :class:`MerkleCommitment`."""

    def __init__(self, nonce: bytes | None = None) -> None:
        self.nonce = nonce or new_nonce()
        self._leaves: dict[tuple[str, str], Any] = {}

    def add(self, kind: str, entity_id: str, body: Any) -> None:
        key = (kind, entity_id)
        if key in self._leaves:
            raise ValueError(f"duplicate leaf {key}")
        self._leaves[key] = body

    def ordered_keys(self) -> list[tuple[str, str]]:
        return sorted(self._leaves)

    def leaf_hashes(self) -> list[bytes]:
        return [
            leaf_hash(k, i, self._leaves[(k, i)], derive_salt(self.nonce, k, i))
            for k, i in self.ordered_keys()
        ]

    def build(self, *, include_nonce: bool = True) -> MerkleCommitment:
        keys = self.ordered_keys()
        hashes = self.leaf_hashes()
        leaves = [
            MerkleLeaf(kind=k, id=i, leaf_hash="sha256:" + h.hex(), salt=derive_salt(self.nonce, k, i).hex())
            for (k, i), h in zip(keys, hashes, strict=True)
        ]
        return MerkleCommitment(
            algorithm=ALGORITHM,
            root="sha256:" + merkle_root(hashes).hex(),
            leaf_count=len(hashes),
            nonce=self.nonce.hex() if include_nonce else None,
            leaves=leaves,
        )

    def proof_for(self, kind: str, entity_id: str) -> list[tuple[str, str]]:
        return inclusion_proof(self.leaf_hashes(), self.ordered_keys().index((kind, entity_id)))


def verify_commitment(commitment: MerkleCommitment, bodies: Mapping[tuple[str, str], Any]) -> bool:
    """Recompute the root from disclosed bodies (with their salts) plus the leaf hashes of redacted leaves.

    A disclosed leaf whose recomputed hash differs from the recorded one fails verification; a leaf without a
    salt is treated as redacted and its recorded ``leaf_hash`` is used as-is.
    """
    if commitment.algorithm != ALGORITHM:
        return False
    keys = {(leaf.kind, leaf.id) for leaf in commitment.leaves}
    disclosed = {(leaf.kind, leaf.id) for leaf in commitment.leaves if leaf.salt is not None}
    if len(keys) != len(commitment.leaves) or bodies.keys() != disclosed:
        return False
    hashes: list[bytes] = []
    for leaf in sorted(commitment.leaves, key=lambda l: (l.kind, l.id)):
        recorded = bytes.fromhex(leaf.leaf_hash.split(":", 1)[1])
        key = (leaf.kind, leaf.id)
        if leaf.salt is not None:
            computed = leaf_hash(leaf.kind, leaf.id, bodies[key], bytes.fromhex(leaf.salt))
            if not hmac.compare_digest(computed, recorded):
                return False
        hashes.append(recorded)
    if len(hashes) != commitment.leaf_count:
        return False
    return hmac.compare_digest(merkle_root(hashes), bytes.fromhex(commitment.root.split(":", 1)[1]))


def redact(commitment: MerkleCommitment, keys: set[tuple[str, str]]) -> MerkleCommitment:
    """Return a commitment whose selected leaves carry no salt (and no nonce), keeping the root verifiable."""
    leaves = [leaf.replace(salt=None) if (leaf.kind, leaf.id) in keys else leaf for leaf in commitment.leaves]
    return commitment.replace(leaves=leaves, nonce=None)


__all__ = [
    "ALGORITHM",
    "LEAF_TYPE",
    "MerkleBuilder",
    "derive_salt",
    "inclusion_proof",
    "leaf_hash",
    "merkle_root",
    "new_nonce",
    "node_hash",
    "redact",
    "verify_commitment",
    "verify_inclusion",
]
