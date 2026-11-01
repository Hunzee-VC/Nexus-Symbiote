"""Symbiote — the Agent Bill of Materials (AgentBOM) toolkit for the agentic-AI supply chain.

Symbiote generates, validates, diffs, verifies, attests and enforces AgentBOMs. It supports and extends
CycloneDX 1.7 and SPDX 3.0.1 without forking either standard. See ``spec/`` for the normative profile.
"""

from __future__ import annotations

__all__ = ["BASE_URI", "SPEC_VERSION", "__version__"]

__version__ = "0.1.0"

#: AgentBOM profile version implemented by this release (``spec/versioning.md``).
SPEC_VERSION = "0.1"

#: Base URI for every identifier Symbiote mints (schemas, digest types, predicate types, SPDX terms).
BASE_URI = "https://aisecnomad.github.io/symbiote/"
