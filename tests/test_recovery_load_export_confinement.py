"""``load_export`` reads an export the way every other reader reads a document.

A symbolic link is not followed and a special file is refused without blocking, so a
caller that hands the loader a checkout-controlled path cannot make it read another
file or wait on a FIFO.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from nexus_symbiote.generators.recovery import load_export


@pytest.mark.timeout(30)
def test_a_symbolic_link_is_not_followed(tmp_path: Path) -> None:
    target = tmp_path / "export.cdx.json"
    target.write_text('{"bomFormat": "CycloneDX"}')
    link = tmp_path / "link.json"
    link.symlink_to(target.name)
    with pytest.raises(OSError):
        load_export(link)


@pytest.mark.timeout(30)
def test_a_fifo_is_refused_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "export.json"
    os.mkfifo(fifo)
    with pytest.raises(OSError):
        load_export(fifo)
