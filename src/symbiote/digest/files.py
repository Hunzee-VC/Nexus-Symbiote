"""Raw-byte digests for files and text artefacts (``spec/digests.md §3.11``)."""

from __future__ import annotations

import hashlib
import unicodedata
from pathlib import Path

from symbiote.digest.envelope import digest_str
from symbiote.model.enums import LineEndings

_CHUNK = 1 << 20


def bytes_digest(data: bytes) -> str:
    return digest_str(data)


def file_digest(path: Path) -> tuple[str, int]:
    """SHA-256 of the exact bytes on disk and the size in bytes (streamed)."""
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            h.update(chunk)
            size += len(chunk)
    return "sha256:" + h.hexdigest(), size


def line_endings(data: bytes) -> LineEndings:
    crlf = data.count(b"\r\n")
    lf = data.count(b"\n") - crlf
    if crlf and lf:
        return LineEndings.MIXED
    if crlf:
        return LineEndings.CRLF
    if lf:
        return LineEndings.LF
    return LineEndings.NONE


def triage_digest(data: bytes) -> str | None:
    """Normalised digest used only to classify drift as cosmetic vs semantic — never an identity."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    text = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip(" \t") for line in text.split("\n")]
    return digest_str("\n".join(lines).strip("\n").encode("utf-8"))


__all__ = ["bytes_digest", "file_digest", "line_endings", "triage_digest"]
