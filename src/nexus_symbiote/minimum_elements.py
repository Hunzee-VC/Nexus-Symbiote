"""G7 AI SBOM minimum-element coverage of an inventory's CycloneDX 1.7 export.

The catalog lists the 50 elements of "Software Bill of Materials for AI – Minimum
Elements" (G7 Cybersecurity Working Group, 12 May 2026) in document order, under
identifiers this project mints: the document defines none, and it sets no required
or optional tiers. The names were checked against four independent enumerations;
the primary PDF could not be opened, so the verification is secondary.

The evaluation reads the standard fields of the CycloneDX export this build writes
for one native inventory. It establishes which elements a reader of that export
finds, in which field, and how the inventory says each value was obtained. It does
not establish compliance with anything (the elements are non-binding guidance),
verifies no value, and never counts a value that only a ``nexus-symbiote:``
property carries. What the native inventory records can make a result stricter,
never more lenient: an export default, an inferred placeholder or a component the
standard fields do not identify does not count as present.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from nexus_symbiote import __version__
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
    AgentComponent,
    AnyComponent,
    DataSourceComponent,
    GuardrailComponent,
    MCPServerComponent,
    MemoryStoreComponent,
    ModelComponent,
    RAGSourceComponent,
    RegistryEntryComponent,
)
from nexus_symbiote.generators._common import (
    PROJECTION_PROPERTY,
    imported_discovery_component,
    repository_subject,
)
from nexus_symbiote.graph import INFERRED_AGENT_NAME
from nexus_symbiote.utils.terminal import UNSAFE_TEXT

FORMAT = "nexus-symbiote/minimum-elements/v1"
EDITION = "g7-ai-sbom-2026-05-12"
PREFIX = "g7ai-2026"
TITLE = "Software Bill of Materials for AI – Minimum Elements"
PUBLISHER = "G7 Cybersecurity Working Group"
PUBLISHED = "2026-05-12"
SOURCE_URL = (
    "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.html"
)
VERIFICATION = "secondary"
VERIFICATION_NOTE = (
    "Element names and order were checked against four independent enumerations "
    "(cdxgen 13.7.0, BomLens 1.14.5, openregtech g7ai.ttl and a draft SPDX checker); "
    "the primary PDF was not opened."
)
STATEMENT = (
    "Coverage is not compliance. The G7 minimum elements are non-binding guidance. "
    "This report says which elements the CycloneDX 1.7 export of the inventory carries "
    "in standard fields; a value only a nexus-symbiote: property carries does not count, "
    "and a present element is a recorded value, not a verified one."
)
MAX_LISTED = 20
"""How many offending subjects, and evidence pointers, an element result lists."""
EXTENSION_PREFIX = "nexus-symbiote:"
"""Properties named with this prefix are this project's extension, never a standard field."""

PRESENT = "present"
MISSING = "missing"
EXPLICIT_UNKNOWN = "explicit-unknown"
NEEDS_PRODUCER_INPUT = "needs-producer-input"
NOT_APPLICABLE = "not-applicable"
STATUSES = (PRESENT, MISSING, EXPLICIT_UNKNOWN, NEEDS_PRODUCER_INPUT, NOT_APPLICABLE)
FROM_BOM = "from-bom"
WRITTEN = "written"
NOT_WRITTEN = "not-written"
NO_FIELD = "no-field"
GENERATED = "generated"
OBSERVED = "observed"
DECLARED = "declared"
IMPORTED = "imported"
# The weakest basis is reported when several subjects contribute.
_BASIS_ORDER = (IMPORTED, DECLARED, OBSERVED)


@dataclass(frozen=True)
class Cluster:
    slug: str
    heading: str
    subject: str

    @property
    def id(self) -> str:
        return f"{PREFIX}/{self.slug}"


@dataclass(frozen=True)
class Element:
    """One element: where CycloneDX 1.7 and SPDX 3.0.1 carry it and how to supply it.

    ``assessable`` is ``from-bom`` when a static repository scan, a repository or
    operator declaration, or enrichment can put the value in an SBOM, and
    ``needs-producer-input`` when only the producer's documentation or runtime data
    can. ``carried`` says whether this build's CycloneDX projection writes the field
    (``written``), CycloneDX has a field it does not write (``not-written``), or
    CycloneDX 1.7 has no dedicated field (``no-field``). ``rule`` says when the
    element is present; the literal unknown is an explicit unknown throughout.
    """

    id: str
    cluster: Cluster
    name: str
    assessable: str
    carried: str
    cyclonedx: str
    spdx: str
    rule: str
    hint: str


METADATA = Cluster("metadata", "Metadata", "document")
SYSTEM = Cluster("slp", "System Level Properties", "system")
MODELS = Cluster("models", "Models", "model")
DATASETS = Cluster("dp", "Datasets Properties", "dataset")
INFRASTRUCTURE = Cluster("infrastructure", "Infrastructure", "infrastructure")
SECURITY = Cluster("sp", "Security Properties", "security")
KPI = Cluster("kpi", "Key Performance Indicators", "kpi")
CLUSTERS = (METADATA, SYSTEM, MODELS, DATASETS, INFRASTRUCTURE, SECURITY, KPI)


def _element(
    cluster: Cluster,
    slug: str,
    name: str,
    assessable: str,
    carried: str,
    cyclonedx: str,
    spdx: str,
    rule: str,
    hint: str,
) -> Element:
    identifier = f"{cluster.id}/{slug}"
    return Element(identifier, cluster, name, assessable, carried, cyclonedx, spdx, rule, hint)


_NPI = NEEDS_PRODUCER_INPUT
_NOT_EVALUATED = (
    "Not evaluated: only the producer's documentation, runtime data or a signing step "
    "can supply it."
)
ELEMENTS: tuple[Element, ...] = (
    _element(
        METADATA,
        "sbom-author",
        "SBOM author",
        FROM_BOM,
        WRITTEN,
        "metadata.authors[].name, metadata.manufacturer.name",
        "CreationInfo.createdBy",
        "An author name or the BOM manufacturer's name is set.",
        (
            "Add the responsible person or organisation to metadata.authors in the inventory; no "
            "command records an author, and the tool is not one."
        ),
    ),
    _element(
        METADATA,
        "sbom-version",
        "SBOM version",
        FROM_BOM,
        WRITTEN,
        "version, serialNumber",
        "none",
        (
            "version is a positive integer, serialNumber is set, and the inventory records its "
            "serial number."
        ),
        "Collect the inventory with scan, which records its version and serial number.",
    ),
    _element(
        METADATA,
        "sbom-data-format-name",
        "SBOM data format name",
        FROM_BOM,
        WRITTEN,
        "bomFormat",
        "implied by CreationInfo.specVersion",
        "bomFormat is set.",
        "Export with this build, which writes bomFormat in every CycloneDX document.",
    ),
    _element(
        METADATA,
        "sbom-data-format-version",
        "SBOM data format version",
        FROM_BOM,
        WRITTEN,
        "specVersion",
        "CreationInfo.specVersion",
        "specVersion is set.",
        "Export with this build, which writes specVersion in every CycloneDX document.",
    ),
    _element(
        METADATA,
        "sbom-author-signature",
        "SBOM author signature",
        _NPI,
        NOT_WRITTEN,
        "signature",
        "none (detached signatures only)",
        _NOT_EVALUATED,
        (
            "Sign the exact exported file in the release pipeline; this build embeds no signature, "
            "and a detached one is outside the BOM."
        ),
    ),
    _element(
        METADATA,
        "sbom-tool-name",
        "SBOM tool name",
        FROM_BOM,
        WRITTEN,
        "metadata.tools.components[].name",
        "CreationInfo.createdUsing (Tool name)",
        "A tool's name is set.",
        "Collect the inventory with scan, which records the producing tool in metadata.tool_name.",
    ),
    _element(
        METADATA,
        "sbom-tool-version",
        "SBOM tool version",
        FROM_BOM,
        WRITTEN,
        "metadata.tools.components[].version",
        "none",
        "A tool's version is set, and the inventory records the producing tool's version.",
        (
            "Collect the inventory with scan, which records the producing tool's version in "
            "metadata.tool_version."
        ),
    ),
    _element(
        METADATA,
        "sbom-generation-context",
        "SBOM generation context",
        FROM_BOM,
        WRITTEN,
        "metadata.lifecycles[].phase, metadata.lifecycles[].name",
        "software_sbomType",
        "A lifecycle phase or name is set.",
        "Collect the inventory with scan: a repository scan records the lifecycle phase pre-build.",
    ),
    _element(
        METADATA,
        "sbom-timestamp",
        "SBOM timestamp",
        FROM_BOM,
        WRITTEN,
        "metadata.timestamp",
        "CreationInfo.created",
        "metadata.timestamp is set, and the inventory records its own timestamp.",
        (
            "Collect the inventory with scan, which records when it was generated in "
            "metadata.timestamp."
        ),
    ),
    _element(
        METADATA,
        "sbom-dependency-relationship",
        "SBOM dependency relationship",
        FROM_BOM,
        WRITTEN,
        "dependencies[].dependsOn, components[].pedigree.ancestors",
        "Relationship (dependsOn, contains, descendantOf)",
        "A dependencies entry lists a dependency, or a component lists pedigree ancestors.",
        (
            "Collect tools from MCP server source: only unconditional depends-on and provides-tool "
            "relationships are exported, and a scan's repository associations are conditional."
        ),
    ),
    _element(
        SYSTEM,
        "system-name",
        "System name",
        FROM_BOM,
        WRITTEN,
        "metadata.component.name",
        "name of the root ai_AIPackage",
        "The system subject has a name other than the placeholder repository.",
        "Declare name in agent.yaml.",
    ),
    _element(
        SYSTEM,
        "system-components",
        "System components",
        FROM_BOM,
        WRITTEN,
        "components[]",
        "contains and dependsOn relationships from the root",
        "The system subject exists and components is not empty.",
        "Collect the inventory with scan, which lists the components it finds.",
    ),
    _element(
        SYSTEM,
        "system-producer",
        "System producer",
        FROM_BOM,
        WRITTEN,
        (
            "metadata.supplier.name, metadata.component.supplier.name, "
            "metadata.component.manufacturer.name, metadata.component.authors[].name"
        ),
        "originatedBy, suppliedBy",
        (
            "The BOM supplier, or a supplier, manufacturer or author of the system subject, has a "
            "name."
        ),
        "Declare owner in agent.yaml; it is exported as the subject's supplier.",
    ),
    _element(
        SYSTEM,
        "system-version",
        "System version",
        FROM_BOM,
        WRITTEN,
        "metadata.component.version",
        "software_packageVersion",
        "The system subject has a version.",
        (
            "Declare version in agent.yaml; the G7 text asks for unknown when there is none, which "
            "this report counts as an explicit unknown."
        ),
    ),
    _element(
        SYSTEM,
        "system-timestamp",
        "System timestamp",
        FROM_BOM,
        NO_FIELD,
        "none",
        "releaseTime, builtTime",
        "Never: CycloneDX 1.7 has no dedicated field.",
        (
            "Not available in this build: CycloneDX 1.7 has no field for when the system was last "
            "updated, and the BOM timestamp is not it."
        ),
    ),
    _element(
        SYSTEM,
        "system-data-flow",
        "System data flow",
        FROM_BOM,
        NOT_WRITTEN,
        "services[].endpoints, services[].data[].flow",
        "none",
        "A service lists endpoints or a data flow.",
        (
            "Not available in this build: it writes no services, so declared MCP, A2A, model and "
            "retrieval endpoints stay in the extension."
        ),
    ),
    _element(
        SYSTEM,
        "system-data-usage",
        "System data usage",
        _NPI,
        NOT_WRITTEN,
        "services[].data[].description, services[].data[].classification",
        "ai_useSensitivePersonalInformation (close)",
        _NOT_EVALUATED,
        (
            "Producer documentation: how the system processes and consumes its data, such as data "
            "used to improve models and API call logs."
        ),
    ),
    _element(
        SYSTEM,
        "system-input-output-properties",
        "System input/output properties",
        _NPI,
        NO_FIELD,
        "none",
        "none",
        _NOT_EVALUATED,
        "Producer documentation: the system's input and output modalities and preprocessing.",
    ),
    _element(
        SYSTEM,
        "intended-application-area",
        "Intended application area",
        FROM_BOM,
        NO_FIELD,
        "none",
        "ai_domain",
        "Never: CycloneDX 1.7 has no dedicated field.",
        (
            "Not available in this build: CycloneDX 1.7 has no dedicated field, and a declared "
            "purpose is exported as a description, which is not this element."
        ),
    ),
    _element(
        MODELS,
        "model-name",
        "Model name",
        FROM_BOM,
        WRITTEN,
        "components[].name",
        "name",
        "Every model has a name that is not an imported ShadowScan label.",
        (
            "Keep the model as a local file scan collects, or declare it in agent.yaml models; an "
            "imported ShadowScan label is not a name."
        ),
    ),
    _element(
        MODELS,
        "model-identifier",
        "Model identifier",
        FROM_BOM,
        NOT_WRITTEN,
        (
            "components[].purl, components[].cpe, components[].swid.tagId, components[].omniborId, "
            "components[].swhid"
        ),
        "software_packageUrl, externalIdentifier, software_contentIdentifier",
        "Every model has a purl, CPE, SWID tag, OmniBOR or SWHID identifier.",
        (
            "Not available in this build: it writes no purl, CPE, SWID tag, OmniBOR or SWHID for a "
            "model, and a bom-ref is not an identifier."
        ),
    ),
    _element(
        MODELS,
        "model-version",
        "Model version",
        FROM_BOM,
        WRITTEN,
        "components[].version",
        "software_packageVersion",
        "Every model has a version.",
        (
            "State an exact revision as the model component's version in the inventory; no "
            "collector records one, and an alias such as gpt-4o is not a version."
        ),
    ),
    _element(
        MODELS,
        "model-timestamp",
        "Model timestamp",
        FROM_BOM,
        NO_FIELD,
        "none",
        "builtTime, releaseTime",
        "Never: CycloneDX 1.7 has no dedicated field.",
        "Not available in this build: CycloneDX 1.7 has no field for a model's timestamp.",
    ),
    _element(
        MODELS,
        "model-producer",
        "Model producer",
        FROM_BOM,
        WRITTEN,
        "components[].manufacturer.name, components[].supplier.name, components[].authors[].name",
        "originatedBy",
        "Every model has a manufacturer, supplier or author name.",
        (
            "State the producer as the model component's supplier in the inventory; no collector "
            "records it, and a hosting provider is not the producer."
        ),
    ),
    _element(
        MODELS,
        "model-description",
        "Model description",
        FROM_BOM,
        WRITTEN,
        "components[].description, components[].modelCard, components[].pedigree.ancestors",
        "description, summary, ai_limitation, descendantOf",
        "Every model has a description, a model card or pedigree ancestors.",
        (
            "State the model's capabilities and limitations as its description in the inventory; "
            "no collector records one."
        ),
    ),
    _element(
        MODELS,
        "model-hash-value",
        "Model hash value",
        FROM_BOM,
        WRITTEN,
        "components[].hashes[].content",
        "verifiedUsing hashValue",
        "Every model has a hexadecimal digest whose algorithm is neither MD5 nor SHA-1.",
        (
            "Keep the model as a local weight file, which scan hashes; a hosted model has no local "
            "artifact, and MD5 or SHA-1 alone does not count."
        ),
    ),
    _element(
        MODELS,
        "model-hash-algorithm",
        "Model hash algorithm",
        FROM_BOM,
        WRITTEN,
        "components[].hashes[].alg",
        "verifiedUsing algorithm",
        "Every model has a hexadecimal digest whose algorithm is neither MD5 nor SHA-1.",
        (
            "Keep the model as a local weight file, which scan hashes with SHA-256; a hosted model "
            "has no local artifact."
        ),
    ),
    _element(
        MODELS,
        "model-properties",
        "Model properties",
        FROM_BOM,
        NOT_WRITTEN,
        (
            "components[].modelCard.modelParameters.architectureFamily, "
            "components[].modelCard.modelParameters.modelArchitecture"
        ),
        "ai_typeOfModel, ai_hyperparameter",
        "Every model card names an architecture family or a model architecture.",
        (
            "Not available in this build: it writes no model card, so a quantization method or "
            "GGUF architecture it records stays in the extension."
        ),
    ),
    _element(
        MODELS,
        "model-input-output-properties",
        "Model input-output properties",
        FROM_BOM,
        NOT_WRITTEN,
        (
            "components[].modelCard.modelParameters.inputs, "
            "components[].modelCard.modelParameters.outputs"
        ),
        "none",
        "Every model card lists both inputs and outputs.",
        "Not available in this build: it writes no model card inputs and outputs.",
    ),
    _element(
        MODELS,
        "model-training-properties",
        "Model training properties",
        _NPI,
        NOT_WRITTEN,
        (
            "components[].modelCard.modelParameters.approach.type, "
            "components[].modelCard.modelParameters.datasets"
        ),
        "ai_informationAboutTraining, trainedOn",
        _NOT_EVALUATED,
        "Producer documentation: the learning type and post-training techniques.",
    ),
    _element(
        MODELS,
        "model-license",
        "Model license",
        FROM_BOM,
        NOT_WRITTEN,
        "components[].licenses",
        "hasDeclaredLicense",
        "Every model has a licence identifier, name or expression.",
        (
            "Not available in this build: it records no model licence and writes no licenses for "
            "models."
        ),
    ),
    _element(
        MODELS,
        "model-external-references",
        "Model external references",
        FROM_BOM,
        NOT_WRITTEN,
        "components[].externalReferences[].url",
        "externalRef",
        "Every model has an external reference with a URL.",
        (
            "Not available in this build: it writes no model card, documentation or paper "
            "references for models."
        ),
    ),
    _element(
        DATASETS,
        "dataset-name",
        "Dataset name",
        FROM_BOM,
        NOT_WRITTEN,
        "components[].name, components[].data[].name",
        "name",
        "Every dataset is marked as one and has a name.",
        (
            "Not available in this build: it writes datasets and retrieval sources as generic data "
            "components without a data[] entry of type dataset."
        ),
    ),
    _element(
        DATASETS,
        "dataset-description",
        "Dataset description",
        FROM_BOM,
        NOT_WRITTEN,
        "components[].description, components[].data[].description",
        "description, dataset_datasetAvailability",
        "Every dataset is marked as one and has a description.",
        (
            "Not available in this build: it does not mark datasets; a description would state the "
            "use, such as pre-training, fine-tuning, evaluation or retrieval."
        ),
    ),
    _element(
        DATASETS,
        "dataset-content",
        "Dataset content",
        FROM_BOM,
        NOT_WRITTEN,
        "components[].data[].contents",
        "dataset_datasetType (narrow)",
        "Every dataset is marked as one and describes its contents.",
        (
            "Not available in this build: it writes no data[].contents describing a dataset's "
            "content and format."
        ),
    ),
    _element(
        DATASETS,
        "dataset-identifier",
        "Dataset identifier",
        FROM_BOM,
        NOT_WRITTEN,
        (
            "components[].purl, components[].data[].contents.url, "
            "components[].externalReferences[].url"
        ),
        "software_packageUrl, externalIdentifier",
        (
            "Every dataset is marked as one and has a purl, a contents URL or an external "
            "reference URL."
        ),
        (
            "Not available in this build: source URIs stay in the extension, and it writes no "
            "dataset identifier."
        ),
    ),
    _element(
        DATASETS,
        "dataset-hash",
        "Dataset hash",
        FROM_BOM,
        NOT_WRITTEN,
        "components[].hashes[].content",
        "verifiedUsing",
        (
            "Every dataset is marked as one and has a hexadecimal digest whose algorithm is "
            "neither MD5 nor SHA-1."
        ),
        (
            "Not available in this build: it does not mark datasets, so a content or index "
            "snapshot digest is the hash of a generic data component."
        ),
    ),
    _element(
        DATASETS,
        "dataset-provenance",
        "Dataset provenance",
        FROM_BOM,
        NOT_WRITTEN,
        "components[].data[].governance, components[].supplier.name",
        "originatedBy, dataset_dataCollectionProcess, dataset_dataPreprocessing",
        "Every dataset is marked as one and has governance or a supplier name.",
        "Not available in this build: it writes no data[].governance and does not mark datasets.",
    ),
    _element(
        DATASETS,
        "dataset-statistical-properties",
        "Dataset statistical properties",
        _NPI,
        NO_FIELD,
        "none",
        "dataset_datasetSize, dataset_knownBias",
        _NOT_EVALUATED,
        "Producer documentation: dataset size, distribution statistics and known bias.",
    ),
    _element(
        DATASETS,
        "dataset-sensitivity",
        "Dataset sensitivity",
        _NPI,
        NOT_WRITTEN,
        "components[].data[].classification, components[].data[].sensitiveData",
        "dataset_hasSensitivePersonalInformation, dataset_confidentialityLevel",
        _NOT_EVALUATED,
        (
            "Producer documentation: personal or sensitive data and copyright status; no flag does "
            "not mean no sensitive data."
        ),
    ),
    _element(
        DATASETS,
        "dataset-dependency-relationship",
        "Dataset dependency relationship",
        _NPI,
        NOT_WRITTEN,
        "dependencies[].dependsOn",
        "dependsOn, descendantOf from the dataset",
        _NOT_EVALUATED,
        (
            "Producer documentation: the software that created the dataset and the datasets it "
            "derives from."
        ),
    ),
    _element(
        DATASETS,
        "dataset-license",
        "Dataset license",
        FROM_BOM,
        NOT_WRITTEN,
        "components[].licenses",
        "hasDeclaredLicense",
        "Every dataset is marked as one and has a licence identifier, name or expression.",
        (
            "Not available in this build: a supplied dataset's license stays in the extension, and "
            "it writes no licenses for datasets."
        ),
    ),
    _element(
        INFRASTRUCTURE,
        "infrastructure-software",
        "Infrastructure software",
        FROM_BOM,
        WRITTEN,
        (
            "components[].type library, framework, container, platform or operating-system; "
            "externalReferences[].type bom"
        ),
        "software_Package, dependsOn",
        (
            "An npm or PyPI package or a container image the inventory records as a registry entry "
            "is exported with one of these types, or a bom reference has a URL."
        ),
        (
            "Declare packages and images in manifests the registry collector reads; a declared "
            "agent framework stays in the extension."
        ),
    ),
    _element(
        INFRASTRUCTURE,
        "infrastructure-hardware",
        "Infrastructure hardware",
        _NPI,
        NOT_WRITTEN,
        "components[].type device, externalReferences[].type bom",
        "none",
        _NOT_EVALUATED,
        "Producer documentation: a link to a hardware bill of materials, if one exists.",
    ),
    _element(
        SECURITY,
        "security-controls",
        "Security controls",
        FROM_BOM,
        NO_FIELD,
        "none",
        "none",
        "Never: CycloneDX 1.7 has no dedicated field.",
        (
            "Not available in this build: CycloneDX 1.7 has no dedicated field; declared "
            "guardrail, authentication and encryption settings stay in the extension and do not "
            "show that a control works."
        ),
    ),
    _element(
        SECURITY,
        "security-compliance",
        "Security compliance",
        _NPI,
        NOT_WRITTEN,
        "declarations, externalReferences[].type certification-report",
        "ai_standardCompliance",
        _NOT_EVALUATED,
        (
            "Producer documentation: the standards, certifications or frameworks the system "
            "complies with."
        ),
    ),
    _element(
        SECURITY,
        "cybersecurity-policy-information",
        "Cybersecurity policy information",
        FROM_BOM,
        NOT_WRITTEN,
        "externalReferences[].type rfc-9116 or security-contact",
        "externalRef of type securityPolicy",
        "The BOM or its system subject has an rfc-9116 or security-contact reference with a URL.",
        (
            "Not available in this build: it writes no rfc-9116 or security-contact reference; the "
            "producer publishes a security.txt."
        ),
    ),
    _element(
        SECURITY,
        "vulnerability-referencing",
        "Vulnerability referencing",
        FROM_BOM,
        NOT_WRITTEN,
        "vulnerabilities[].id, externalReferences[].type advisories",
        "security_Vulnerability, externalRef of type securityAdvisory",
        (
            "A vulnerability has an identifier that does not start with NEXUS-, or an advisories "
            "reference has a URL."
        ),
        (
            "Not available in this build: it writes no vulnerabilities or advisory references, and "
            "NEXUS- findings are not vulnerability references."
        ),
    ),
    _element(
        KPI,
        "security-metrics",
        "Security metrics",
        _NPI,
        NOT_WRITTEN,
        (
            "components[].modelCard.quantitativeAnalysis.performanceMetrics, "
            "externalReferences[].type quality-metrics"
        ),
        "ai_metric",
        _NOT_EVALUATED,
        (
            "Producer documentation: security measurements of the models or system, such as "
            "robustness benchmarks."
        ),
    ),
    _element(
        KPI,
        "operational-performance-kpis",
        "Operational performance KPIs",
        _NPI,
        NO_FIELD,
        "none",
        "ai_metric (close)",
        _NOT_EVALUATED,
        (
            "Runtime measurements such as uptime, latency and throughput, which a repository does "
            "not contain."
        ),
    ),
)

REASONS = {
    "export-default": (
        "The inventory does not record it; an export would substitute the time of export, "
        "this build's version or a serial number derived from the content."
    ),
    "inferred-placeholder": (
        "The subject's name is the placeholder repository, not a declared name."
    ),
    "no-dataset-component": "The inventory records no dataset or retrieval source.",
    "no-model-component": "The inventory records no model component.",
    "no-standard-field": "CycloneDX 1.7 has no dedicated standard field for this element.",
    "no-system-subject": (
        "The export has no system subject (metadata.component): the inventory does not "
        "hold exactly one repository agent."
    ),
    "not-identified": (
        "No standard field identifies the component as a model (type "
        "machine-learning-model) or a dataset (a data[] entry of type dataset, or a "
        "dataset tag)."
    ),
    "partial": "A static scan never claims this list is complete.",
    "synthetic-name": (
        "An imported ShadowScan component carries a digest-based label, not its name."
    ),
    "unexported-relationships": (
        "The export carries only unconditional depends-on and provides-tool relationships; "
        "the inventory's other relationships stay in the extension."
    ),
}
NOTES = {
    "retrieval-sources": (
        "Retrieval sources (rag-source) are scored as datasets the system uses; this says "
        "nothing about the data its models were trained on."
    ),
}

_PLACEHOLDERS = frozenset({"noassertion", "noassertionlicense"})
_HEX = re.compile(r"[0-9A-Fa-f]+")
_WEAK_HASHES = frozenset({"MD5", "SHA-1"})
_INFRASTRUCTURE_TYPES = frozenset(
    {"library", "framework", "container", "platform", "operating-system"}
)
# Package and image registries; a model hub or tool registry entry is neither.
_SOFTWARE_REGISTRIES = frozenset({"npm", "pypi", "docker-hub", "docker", "oci"})
_POLICY_REFERENCES = frozenset({"rfc-9116", "security-contact"})
# Letters and symbols that render as blank space.
_BLANK = frozenset("\u115f\u1160\u3164\uffa0\u2800")


def _obj(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _seq(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _visible(character: str) -> bool:
    """A letter, digit, punctuation mark or symbol that does not render as blank space."""
    return unicodedata.category(character)[0] in "LNPS" and character not in _BLANK


def _text_state(value: object) -> str:
    """``present``, ``explicit-unknown`` or ``missing`` for one recorded value.

    Text without a visible character (no letter, digit, punctuation mark or symbol
    other than a blank filler), NOASSERTION and NoAssertionLicense are not present;
    the literal unknown is an explicit unknown.
    """
    if not isinstance(value, str):
        return MISSING
    visible = UNSAFE_TEXT.sub("", value).strip()
    if not any(map(_visible, visible)) or visible.casefold() in _PLACEHOLDERS:
        return MISSING
    return EXPLICIT_UNKNOWN if visible.casefold() == "unknown" else PRESENT


def _extension_property(entry: object) -> bool:
    name = _obj(entry).get("name")
    return isinstance(name, str) and name.startswith(EXTENSION_PREFIX)


def _filled(value: object) -> str:
    """A structured value counts only when it holds visible text beyond a bom-ref
    and this project's extension properties.

    The walk keeps its own stack: an inventory can nest a value deeper than the
    interpreter's recursion limit allows a recursive walk.
    """
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, Mapping):
            for key, entry in item.items():
                if key == "properties" and isinstance(entry, list):
                    pending += [p for p in entry if not _extension_property(p)]
                elif key != "bom-ref":
                    pending.append(entry)
        elif isinstance(item, list):
            pending.extend(item)
        elif _text_state(item) == PRESENT:
            return PRESENT
    return MISSING


def _meaningful(value: object) -> bool:
    return _filled(value) == PRESENT


@dataclass(frozen=True)
class _Located:
    """A native component, its position in the inventory and its exported form."""

    native: AnyComponent
    index: int
    exported: Mapping[str, Any] | None
    pointer: str


@dataclass(frozen=True)
class _Context:
    bom: AIBOM
    export: Mapping[str, Any]
    components: tuple[_Located, ...]
    subject: _Located | None
    models: tuple[_Located, ...]
    datasets: tuple[_Located, ...]


@dataclass(frozen=True)
class _Outcome:
    state: str
    cyclonedx: tuple[str, ...] = ()
    native: tuple[str, ...] = ()
    basis: str | None = None
    reasons: tuple[str, ...] = ()
    relationships: Relationships | None = None


Pairs = list[tuple[str, str]]


def _combine(pairs: Pairs, basis: str | None, native: Sequence[str] = ()) -> _Outcome:
    present = tuple(pointer for pointer, state in pairs if state == PRESENT)
    if present:
        return _Outcome(PRESENT, present, basis=basis)
    state = EXPLICIT_UNKNOWN if any(s == EXPLICIT_UNKNOWN for _, s in pairs) else MISSING
    return _Outcome(state, native=tuple(native))


def _weakest(bases: Iterable[str | None]) -> str | None:
    known = [basis for basis in bases if basis in _BASIS_ORDER]
    return min(known, key=_BASIS_ORDER.index) if known else None


def _basis(component: AnyComponent, claim: str | None = None, *, measured: bool = False) -> str:
    """How the inventory says a value was obtained; never above observed.

    A value of an imported discovery report is imported. A claim recorded for the
    field decides next; a measured value (a name or digest a collector took from
    bytes) follows the component's assurance; anything else was declared.
    """
    if imported_discovery_component(component):
        return IMPORTED
    evidence = component.claims.get(claim) if claim is not None else None
    if evidence is not None:
        return DECLARED if evidence.assurance == AssuranceLevel.DECLARED else OBSERVED
    if measured and component.assurance_level != AssuranceLevel.DECLARED:
        return OBSERVED
    return DECLARED


def _native_value(component: AnyComponent, field: str) -> object:
    if field.startswith("properties."):
        return component.properties.get(field.removeprefix("properties."))
    return getattr(component, field, None)


def _native_pointers(component: AnyComponent, index: int, fields: Iterable[str]) -> list[str]:
    return [
        f"/components/{index}/{field.replace('.', '/')}"
        for field in fields
        if _meaningful(_native_value(component, field))
    ]


def _texts(container: Mapping[str, Any], pointer: str, *fields: str) -> Pairs:
    pairs: Pairs = []
    for field in fields:
        value: object = container
        for part in field.split("."):
            value = _obj(value).get(part)
        pairs.append((f"{pointer}/{field.replace('.', '/')}", _text_state(value)))
    return pairs


def _named(container: Mapping[str, Any], pointer: str, field: str) -> Pairs:
    """``name`` of each entry of a list field, such as authors."""
    return [
        (f"{pointer}/{field}/{index}/name", _text_state(_obj(entry).get("name")))
        for index, entry in enumerate(_seq(container.get(field)))
    ]


def _structures(container: Mapping[str, Any], pointer: str, *fields: str) -> Pairs:
    pairs: Pairs = []
    for field in fields:
        value: object = container
        for part in field.split("."):
            value = _obj(value).get(part)
        pairs.append((f"{pointer}/{field.replace('.', '/')}", _filled(value)))
    return pairs


def _references(
    container: Mapping[str, Any], pointer: str, types: frozenset[str] | None = None
) -> Pairs:
    return [
        (f"{pointer}/externalReferences/{index}/url", _text_state(_obj(entry).get("url")))
        for index, entry in enumerate(_seq(container.get("externalReferences")))
        if types is None or _obj(entry).get("type") in types
    ]


def _data(container: Mapping[str, Any], pointer: str, path: str, *, text: bool) -> Pairs:
    """One value from each ``data[]`` entry of a component, such as ``contents.url``."""
    pairs: Pairs = []
    for index, entry in enumerate(_seq(container.get("data"))):
        value: object = entry
        for part in path.split("."):
            value = _obj(value).get(part)
        state = _text_state(value) if text else _filled(value)
        pairs.append((f"{pointer}/data/{index}/{path.replace('.', '/')}", state))
    return pairs


def _hashes(container: Mapping[str, Any], pointer: str, part: str) -> Pairs:
    """Digests other than MD5 and SHA-1 whose content is hexadecimal."""
    pairs: Pairs = []
    for index, entry in enumerate(_seq(container.get("hashes"))):
        algorithm, content = _obj(entry).get("alg"), _obj(entry).get("content")
        strong = (
            _text_state(algorithm) == PRESENT
            and str(algorithm).upper() not in _WEAK_HASHES
            and isinstance(content, str)
            and _HEX.fullmatch(content) is not None
        )
        pairs.append((f"{pointer}/hashes/{index}/{part}", PRESENT if strong else MISSING))
    return pairs


def _licenses(container: Mapping[str, Any], pointer: str) -> Pairs:
    pairs: Pairs = []
    for index, entry in enumerate(_seq(container.get("licenses"))):
        base = f"{pointer}/licenses/{index}"
        pairs += _texts(_obj(entry), base, "license.id", "license.name", "expression")
    return pairs


def _metadata(context: _Context) -> Mapping[str, Any]:
    return _obj(context.export.get("metadata"))


def _generated(context: _Context, pairs: Pairs, field: str | None = None) -> _Outcome:
    """A value the export writes about itself, counted only when the inventory records it.

    Without the inventory's own ``field``, an export substitutes the time of export, this
    build's version or a serial number derived from the content.
    """
    outcome = _combine(pairs, GENERATED)
    if outcome.state == PRESENT and field and getattr(context.bom.metadata, field) is None:
        return _Outcome(MISSING, reasons=("export-default",))
    return outcome


def _sbom_author(context: _Context) -> _Outcome:
    metadata = _metadata(context)
    pairs = _named(metadata, "/metadata", "authors")
    pairs += _texts(metadata, "/metadata", "manufacturer.name")
    return _combine(pairs, DECLARED)


def _sbom_version(context: _Context) -> _Outcome:
    version = context.export.get("version")
    numbered = isinstance(version, int) and not isinstance(version, bool) and version >= 1
    pairs: Pairs = [("/version", PRESENT if numbered else MISSING)]
    pairs += _texts(context.export, "", "serialNumber")
    if any(state != PRESENT for _, state in pairs):
        return _Outcome(MISSING)
    return _generated(context, pairs, "serial_number")


def _sbom_format_name(context: _Context) -> _Outcome:
    return _combine(_texts(context.export, "", "bomFormat"), GENERATED)


def _sbom_format_version(context: _Context) -> _Outcome:
    return _combine(_texts(context.export, "", "specVersion"), GENERATED)


def _tools(context: _Context) -> list[tuple[str, Mapping[str, Any]]]:
    tools = _metadata(context).get("tools")
    if isinstance(tools, Mapping):
        entries, pointer = _seq(tools.get("components")), "/metadata/tools/components"
    else:
        entries, pointer = _seq(tools), "/metadata/tools"
    return [(f"{pointer}/{index}", _obj(entry)) for index, entry in enumerate(entries)]


def _sbom_tool_name(context: _Context) -> _Outcome:
    pairs = [pair for pointer, tool in _tools(context) for pair in _texts(tool, pointer, "name")]
    return _generated(context, pairs)


def _sbom_tool_version(context: _Context) -> _Outcome:
    pairs = [pair for pointer, tool in _tools(context) for pair in _texts(tool, pointer, "version")]
    return _generated(context, pairs, "tool_version")


def _sbom_generation_context(context: _Context) -> _Outcome:
    pairs: Pairs = []
    for index, entry in enumerate(_seq(_metadata(context).get("lifecycles"))):
        pairs += _texts(_obj(entry), f"/metadata/lifecycles/{index}", "phase", "name")
    return _combine(pairs, GENERATED)


def _sbom_timestamp(context: _Context) -> _Outcome:
    return _generated(context, _texts(_metadata(context), "/metadata", "timestamp"), "timestamp")


def _exported_edge(edge: DependencyEdge) -> bool:
    # The edges CycloneDXGenerator._dependencies projects into ``dependencies``.
    return not edge.conditions and edge.relationship in {"depends-on", "provides-tool"}


def _sbom_dependency_relationship(context: _Context) -> _Outcome:
    pairs: Pairs = [
        (f"/dependencies/{index}/dependsOn", _filled(_obj(row).get("dependsOn")))
        for index, row in enumerate(_seq(context.export.get("dependencies")))
    ]
    for index, component in enumerate(_seq(context.export.get("components"))):
        pairs += _structures(_obj(component), f"/components/{index}", "pedigree.ancestors")
    edges = context.bom.dependencies
    exported = [edge for edge in edges if _exported_edge(edge)]
    # Relationships only the extension carries are listed even when some are exported.
    native = tuple(f"/dependencies/{i}" for i, edge in enumerate(edges) if not _exported_edge(edge))
    basis = _weakest(
        DECLARED if edge.assurance_level in {None, DECLARED} else OBSERVED for edge in exported
    )
    outcome = _combine(pairs, basis or DECLARED)
    counted = Relationships(len(edges), len(exported)) if edges else None
    if outcome.state != PRESENT:
        return _Outcome(outcome.state, native=native, relationships=counted)
    reasons = ("partial", "unexported-relationships") if native else ("partial",)
    return _Outcome(PRESENT, outcome.cyclonedx, native, outcome.basis, reasons, counted)


SubjectCheck = Callable[[_Context, _Located], _Outcome]
DocumentCheck = Callable[[_Context], _Outcome]


def _system(check: SubjectCheck) -> DocumentCheck:
    """Without one system subject in the export, each system element checked here is missing."""

    def run(context: _Context) -> _Outcome:
        subject = context.subject
        if subject is None or subject.exported is None:
            return _Outcome(MISSING, reasons=("no-system-subject",))
        return check(context, subject)

    return run


def _system_name(context: _Context, subject: _Located) -> _Outcome:
    assert subject.exported is not None
    outcome = _combine(
        _texts(subject.exported, subject.pointer, "name"), _basis(subject.native, "name")
    )
    native = subject.native
    if (
        outcome.state == PRESENT
        and native.name == INFERRED_AGENT_NAME
        and "name" not in native.claims
    ):
        return _Outcome(MISSING, reasons=("inferred-placeholder",))
    return outcome


def _system_components(context: _Context, subject: _Located) -> _Outcome:
    if not _seq(context.export.get("components")):
        return _Outcome(MISSING)
    presence = []
    for item in context.components:
        claim = item.native.claims.get("repository_presence")
        if imported_discovery_component(item.native):
            presence.append(IMPORTED)
        elif claim is not None and claim.assurance != AssuranceLevel.DECLARED:
            presence.append(OBSERVED)
        else:
            presence.append(DECLARED)
    basis = _weakest(presence) or DECLARED
    return _Outcome(PRESENT, ("/components",), basis=basis, reasons=("partial",))


def _system_producer(context: _Context, subject: _Located) -> _Outcome:
    assert subject.exported is not None
    component, pointer = subject.exported, subject.pointer
    pairs = _texts(_metadata(context), "/metadata", "supplier.name")
    pairs += _texts(component, pointer, "supplier.name", "manufacturer.name")
    pairs += _named(component, pointer, "authors")
    return _combine(pairs, _basis(subject.native, "owner"))


def _system_version(context: _Context, subject: _Located) -> _Outcome:
    assert subject.exported is not None
    pairs = _texts(subject.exported, subject.pointer, "version")
    # A version longer than the standard field allows stays in the extension.
    native = _native_pointers(subject.native, subject.index, ["version"])
    return _combine(pairs, _basis(subject.native, "version"), native)


def _no_field(native: Sequence[str] = ()) -> _Outcome:
    return _Outcome(MISSING, native=tuple(native), reasons=("no-standard-field",))


def _no_system_field(context: _Context, subject: _Located) -> _Outcome:
    return _no_field()


def _flow_pointers(bom: AIBOM) -> list[str]:
    pointers: list[str] = []
    for index, component in enumerate(bom.components):
        fields: tuple[str, ...] = ()
        if isinstance(component, MCPServerComponent | A2AServerComponent):
            fields = ("endpoint_url",)
        elif isinstance(component, A2AClientComponent):
            fields = ("agent_card_url",)
        elif isinstance(component, ModelComponent):
            fields = ("endpoint",)
        elif isinstance(component, RAGSourceComponent):
            fields = ("source_uris",)
        pointers += _native_pointers(component, index, fields)
    return pointers


def _system_data_flow(context: _Context, subject: _Located) -> _Outcome:
    pairs: Pairs = []
    for index, service in enumerate(_seq(context.export.get("services"))):
        pointer = f"/services/{index}"
        pairs += _structures(_obj(service), pointer, "endpoints")
        pairs += _data(_obj(service), pointer, "flow", text=True)
    outcome = _combine(pairs, DECLARED, _flow_pointers(context.bom))
    if outcome.state == PRESENT:
        return _Outcome(PRESENT, outcome.cyclonedx, basis=DECLARED, reasons=("partial",))
    return outcome


def _infrastructure_software(context: _Context) -> _Outcome:
    counted = [
        item
        for item in context.components
        if isinstance(item.native, RegistryEntryComponent)
        and (item.native.registry_type or "").lower() in _SOFTWARE_REGISTRIES
        and item.exported is not None
        and item.exported.get("type") in _INFRASTRUCTURE_TYPES
    ]
    pairs: Pairs = [(item.pointer, PRESENT) for item in counted]
    pairs += _references(context.export, "", frozenset({"bom"}))
    subject = _obj(_metadata(context).get("component"))
    pairs += _references(subject, "/metadata/component", frozenset({"bom"}))
    native = [
        f"/components/{index}/framework"
        for index, component in enumerate(context.bom.components)
        if isinstance(component, AgentComponent) and _meaningful(component.framework)
    ]
    basis = _weakest([*(_basis(item.native) for item in counted), DECLARED])
    outcome = _combine(pairs, basis, native)
    if outcome.state == PRESENT:
        return _Outcome(PRESENT, outcome.cyclonedx, tuple(native), basis, ("partial",))
    return outcome


def _security_controls(context: _Context) -> _Outcome:
    native: list[str] = []
    for index, component in enumerate(context.bom.components):
        if isinstance(component, GuardrailComponent):
            native.append(f"/components/{index}")
        elif isinstance(component, A2AServerComponent) and component.authentication_required:
            native.append(f"/components/{index}/authentication_required")
        elif isinstance(component, MemoryStoreComponent):
            native += [
                f"/components/{index}/{field}"
                for field in ("encryption_at_rest", "tenant_isolated")
                if getattr(component, field) is True
            ]
    return _no_field(native)


def _cybersecurity_policy_information(context: _Context) -> _Outcome:
    subject = _obj(_metadata(context).get("component"))
    pairs = _references(context.export, "", _POLICY_REFERENCES)
    pairs += _references(subject, "/metadata/component", _POLICY_REFERENCES)
    return _combine(pairs, DECLARED)


def _vulnerability_referencing(context: _Context) -> _Outcome:
    pairs: Pairs = []
    for index, entry in enumerate(_seq(context.export.get("vulnerabilities"))):
        identifier = _obj(entry).get("id")
        # Inventory findings are named NEXUS-; they are not known vulnerabilities.
        if isinstance(identifier, str) and not identifier.upper().startswith("NEXUS-"):
            pairs.append((f"/vulnerabilities/{index}/id", _text_state(identifier)))
    advisories = frozenset({"advisories"})
    pairs += _references(context.export, "", advisories)
    pairs += _references(
        _obj(_metadata(context).get("component")), "/metadata/component", advisories
    )
    for index, component in enumerate(_seq(context.export.get("components"))):
        pairs += _references(_obj(component), f"/components/{index}", advisories)
    return _combine(pairs, DECLARED)


_DOCUMENT_CHECKS: dict[str, DocumentCheck] = {
    f"{METADATA.id}/sbom-author": _sbom_author,
    f"{METADATA.id}/sbom-version": _sbom_version,
    f"{METADATA.id}/sbom-data-format-name": _sbom_format_name,
    f"{METADATA.id}/sbom-data-format-version": _sbom_format_version,
    f"{METADATA.id}/sbom-tool-name": _sbom_tool_name,
    f"{METADATA.id}/sbom-tool-version": _sbom_tool_version,
    f"{METADATA.id}/sbom-generation-context": _sbom_generation_context,
    f"{METADATA.id}/sbom-timestamp": _sbom_timestamp,
    f"{METADATA.id}/sbom-dependency-relationship": _sbom_dependency_relationship,
    f"{SYSTEM.id}/system-name": _system(_system_name),
    f"{SYSTEM.id}/system-components": _system(_system_components),
    f"{SYSTEM.id}/system-producer": _system(_system_producer),
    f"{SYSTEM.id}/system-version": _system(_system_version),
    f"{SYSTEM.id}/system-timestamp": _system(_no_system_field),
    f"{SYSTEM.id}/system-data-flow": _system(_system_data_flow),
    f"{SYSTEM.id}/intended-application-area": _system(_no_system_field),
    f"{INFRASTRUCTURE.id}/infrastructure-software": _infrastructure_software,
    f"{SECURITY.id}/security-controls": _security_controls,
    f"{SECURITY.id}/cybersecurity-policy-information": _cybersecurity_policy_information,
    f"{SECURITY.id}/vulnerability-referencing": _vulnerability_referencing,
}


@dataclass(frozen=True)
class _SubjectRule:
    """How one per-subject element is read from a model or dataset component.

    ``read`` is None when CycloneDX 1.7 has no field for the element. ``native``
    names the inventory fields that hold a related value; a subject without the
    standard value lists those that are set, since only the extension carries them
    where a standard reader would look.
    """

    read: Callable[[Mapping[str, Any], str], Pairs] | None
    native: tuple[str, ...] = ()
    measured: bool = False


def _rule_text(*fields: str) -> Callable[[Mapping[str, Any], str], Pairs]:
    return lambda component, pointer: _texts(component, pointer, *fields)


def _identifier(component: Mapping[str, Any], pointer: str) -> Pairs:
    pairs = _texts(component, pointer, "purl", "cpe", "swid.tagId")
    for field in ("omniborId", "swhid"):
        pairs += [
            (f"{pointer}/{field}/{index}", _text_state(value))
            for index, value in enumerate(_seq(component.get(field)))
        ]
    return pairs


def _producer(component: Mapping[str, Any], pointer: str) -> Pairs:
    pairs = _texts(component, pointer, "manufacturer.name", "supplier.name")
    return pairs + _named(component, pointer, "authors")


def _model_description(component: Mapping[str, Any], pointer: str) -> Pairs:
    pairs = _texts(component, pointer, "description")
    return pairs + _structures(component, pointer, "modelCard", "pedigree.ancestors")


def _model_properties(component: Mapping[str, Any], pointer: str) -> Pairs:
    base = "modelCard.modelParameters."
    return _texts(component, pointer, base + "architectureFamily", base + "modelArchitecture")


def _model_input_output(component: Mapping[str, Any], pointer: str) -> Pairs:
    pairs = _structures(
        component, pointer, "modelCard.modelParameters.inputs", "modelCard.modelParameters.outputs"
    )
    # Both directions are needed: the element describes what goes in and what comes out.
    return pairs if all(state == PRESENT for _, state in pairs) else []


def _dataset_name(component: Mapping[str, Any], pointer: str) -> Pairs:
    return _texts(component, pointer, "name") + _data(component, pointer, "name", text=True)


def _dataset_description(component: Mapping[str, Any], pointer: str) -> Pairs:
    pairs = _texts(component, pointer, "description")
    return pairs + _data(component, pointer, "description", text=True)


def _dataset_identifier(component: Mapping[str, Any], pointer: str) -> Pairs:
    pairs = _texts(component, pointer, "purl")
    pairs += _data(component, pointer, "contents.url", text=True)
    return pairs + _references(component, pointer)


def _dataset_provenance(component: Mapping[str, Any], pointer: str) -> Pairs:
    pairs = _data(component, pointer, "governance", text=False)
    return pairs + _texts(component, pointer, "supplier.name")


_SUBJECT_RULES: dict[str, _SubjectRule] = {
    f"{MODELS.id}/model-name": _SubjectRule(_rule_text("name"), measured=True),
    f"{MODELS.id}/model-identifier": _SubjectRule(_identifier),
    f"{MODELS.id}/model-version": _SubjectRule(
        _rule_text("version"), ("version", "resolved_revision")
    ),
    f"{MODELS.id}/model-timestamp": _SubjectRule(None),
    f"{MODELS.id}/model-producer": _SubjectRule(_producer, ("supplier",)),
    f"{MODELS.id}/model-description": _SubjectRule(
        _model_description,
        ("description", "base_model_ref", "derivation_type", "properties.base_model"),
    ),
    f"{MODELS.id}/model-hash-value": _SubjectRule(
        lambda component, pointer: _hashes(component, pointer, "content"), measured=True
    ),
    f"{MODELS.id}/model-hash-algorithm": _SubjectRule(
        lambda component, pointer: _hashes(component, pointer, "alg"), measured=True
    ),
    f"{MODELS.id}/model-properties": _SubjectRule(
        _model_properties, ("quantization_method", "properties.gguf_architecture")
    ),
    f"{MODELS.id}/model-input-output-properties": _SubjectRule(_model_input_output),
    f"{MODELS.id}/model-license": _SubjectRule(_licenses, ("properties.license",)),
    f"{MODELS.id}/model-external-references": _SubjectRule(
        lambda component, pointer: _references(component, pointer)
    ),
    f"{DATASETS.id}/dataset-name": _SubjectRule(_dataset_name, ("name",), measured=True),
    f"{DATASETS.id}/dataset-description": _SubjectRule(
        _dataset_description, ("description", "dataset_type")
    ),
    f"{DATASETS.id}/dataset-content": _SubjectRule(
        lambda component, pointer: _data(component, pointer, "contents", text=False)
    ),
    f"{DATASETS.id}/dataset-identifier": _SubjectRule(
        _dataset_identifier, ("source_uri", "source_uris")
    ),
    f"{DATASETS.id}/dataset-hash": _SubjectRule(
        lambda component, pointer: _hashes(component, pointer, "content"),
        ("hashes", "content_hash", "index_snapshot_hash"),
        measured=True,
    ),
    f"{DATASETS.id}/dataset-provenance": _SubjectRule(
        _dataset_provenance, ("supplier", "collection_date")
    ),
    f"{DATASETS.id}/dataset-license": _SubjectRule(_licenses, ("license", "properties.license")),
}


def _identified(cluster: Cluster, located: _Located) -> bool:
    exported = located.exported
    if exported is None:
        return False
    if cluster is MODELS:
        return exported.get("type") == "machine-learning-model"
    return "dataset" in _seq(exported.get("tags")) or any(
        _obj(entry).get("type") == "dataset" for entry in _seq(exported.get("data"))
    )


def _subject_outcome(element: Element, rule: _SubjectRule, located: _Located) -> _Outcome:
    native = _native_pointers(located.native, located.index, rule.native)
    if not _identified(element.cluster, located):
        return _Outcome(MISSING, native=tuple(native), reasons=("not-identified",))
    if rule.read is None:
        return _Outcome(MISSING, native=tuple(native), reasons=("no-standard-field",))
    if element.id == f"{MODELS.id}/model-name" and imported_discovery_component(located.native):
        return _Outcome(MISSING, reasons=("synthetic-name",))
    assert located.exported is not None
    basis = _basis(located.native, measured=rule.measured)
    return _combine(rule.read(located.exported, located.pointer), basis, native)


@dataclass(frozen=True)
class Listing:
    """A bounded, ordered list and how many entries it leaves out."""

    items: tuple[str, ...]
    omitted: int

    @classmethod
    def of(cls, values: Sequence[str]) -> Listing:
        return cls(tuple(values[:MAX_LISTED]), max(0, len(values) - MAX_LISTED))

    def to_dict(self) -> dict[str, Any]:
        return {"listed": list(self.items), "omitted": self.omitted}


EMPTY = Listing((), 0)


@dataclass(frozen=True)
class Subjects:
    """For a per-subject element: how many subjects there are and have it."""

    kind: str
    total: int
    present: int
    offenders: Listing


@dataclass(frozen=True)
class Relationships:
    """How many relationships the inventory records, and how many its export carries."""

    recorded: int
    exported: int


@dataclass(frozen=True)
class ElementResult:
    element: Element
    status: str
    basis: str | None = None
    reasons: tuple[str, ...] = ()
    cyclonedx: Listing = EMPTY
    native: Listing = EMPTY
    subjects: Subjects | None = None
    relationships: Relationships | None = None

    @property
    def extension_only(self) -> bool:
        """Missing from standard fields although the inventory records a related value."""
        return self.status == MISSING and bool(self.native.items)

    def to_dict(self) -> dict[str, Any]:
        element = self.element
        return {
            "id": element.id,
            "cluster": element.cluster.heading,
            "name": element.name,
            "subject": element.cluster.subject,
            "assessable": element.assessable,
            "status": self.status,
            "basis": self.basis,
            "reasons": list(self.reasons),
            "extension_only": self.extension_only,
            "subjects": None
            if self.subjects is None
            else {
                "kind": self.subjects.kind,
                "total": self.subjects.total,
                "present": self.subjects.present,
                "without": self.subjects.offenders.to_dict(),
            },
            "relationships": None
            if self.relationships is None
            else {"recorded": self.relationships.recorded, "exported": self.relationships.exported},
            "rule": element.rule,
            "cyclonedx": {
                "fields": element.cyclonedx,
                "carried": element.carried,
                "evidence": self.cyclonedx.to_dict(),
            },
            "native": self.native.to_dict(),
            "hint": element.hint,
        }


@dataclass(frozen=True)
class Coverage:
    """Present elements over the applicable elements assessable from the BOM.

    An explicit unknown is assessable and not present, so stating unknown never
    raises the ratio, and neither does a smaller denominator.
    """

    present: int
    assessable: int

    def tenths(self) -> int | None:
        """The percentage in tenths, rounded down so it never reads better than it is."""
        return None if not self.assessable else self.present * 1000 // self.assessable

    def percent(self) -> str | None:
        tenths = self.tenths()
        return None if tenths is None else f"{tenths // 10}.{tenths % 10}"

    def below(self, threshold: Fraction) -> bool:
        """Compared exactly; with nothing assessable no threshold is met."""
        return not self.assessable or Fraction(100 * self.present, self.assessable) < threshold

    def to_dict(self) -> dict[str, Any]:
        tenths = self.tenths()
        return {
            "present": self.present,
            "assessable": self.assessable,
            "percent": None if tenths is None else tenths / 10,
        }


@dataclass(frozen=True)
class Report:
    elements: tuple[ElementResult, ...]
    subjects: Mapping[str, Any]
    projection: str | None

    def results(self, cluster: Cluster | None = None) -> tuple[ElementResult, ...]:
        return tuple(r for r in self.elements if cluster is None or r.element.cluster is cluster)

    def counts(self, cluster: Cluster | None = None) -> dict[str, int]:
        statuses = [result.status for result in self.results(cluster)]
        return {status: statuses.count(status) for status in STATUSES}

    def coverage(self, cluster: Cluster | None = None) -> Coverage:
        counts = self.counts(cluster)
        assessable = counts[PRESENT] + counts[MISSING] + counts[EXPLICIT_UNKNOWN]
        return Coverage(counts[PRESENT], assessable)

    def notes(self, cluster: Cluster) -> tuple[str, ...]:
        if cluster is DATASETS and self.subjects["retrieval_sources"]:
            return ("retrieval-sources",)
        return ()

    def to_dict(self, *, fail_under: str | None = None) -> dict[str, Any]:
        coverage = self.coverage()
        return {
            "format": FORMAT,
            "edition": EDITION,
            "guidance": {
                "title": TITLE,
                "publisher": PUBLISHER,
                "published": PUBLISHED,
                "binding": False,
                "source": SOURCE_URL,
                "verification": VERIFICATION,
                "verification_note": VERIFICATION_NOTE,
                "identifiers": "minted by nexus-symbiote; the G7 document defines none",
            },
            "statement": STATEMENT,
            "evaluated": {
                "standard": "CycloneDX 1.7",
                "projection": self.projection,
                "tool_version": __version__,
            },
            "subjects": dict(self.subjects),
            "coverage": coverage.to_dict(),
            "counts": self.counts(),
            "gate": None
            if fail_under is None
            else {"fail_under": fail_under, "passed": not coverage.below(Fraction(fail_under))},
            "clusters": [
                {
                    "id": cluster.id,
                    "heading": cluster.heading,
                    "subject": cluster.subject,
                    "coverage": self.coverage(cluster).to_dict(),
                    "counts": self.counts(cluster),
                    "notes": list(self.notes(cluster)),
                }
                for cluster in CLUSTERS
            ],
            "elements": [result.to_dict() for result in self.elements],
        }


def _per_subject(element: Element, context: _Context) -> ElementResult:
    subjects = context.models if element.cluster is MODELS else context.datasets
    rule = _SUBJECT_RULES[element.id]
    outcomes = [(item, _subject_outcome(element, rule, item)) for item in subjects]
    states = {outcome.state for _, outcome in outcomes}
    status = (
        MISSING
        if MISSING in states
        else EXPLICIT_UNKNOWN
        if EXPLICIT_UNKNOWN in states
        else PRESENT
    )
    offenders = [item for item, outcome in outcomes if outcome.state != PRESENT]
    return ElementResult(
        element,
        status,
        basis=_weakest(o.basis for _, o in outcomes) if status == PRESENT else None,
        reasons=tuple(sorted({reason for _, o in outcomes for reason in o.reasons})),
        cyclonedx=Listing.of([p for _, o in outcomes for p in o.cyclonedx]),
        native=Listing.of([p for _, o in outcomes for p in o.native]),
        subjects=Subjects(
            element.cluster.subject,
            len(subjects),
            len(subjects) - len(offenders),
            Listing.of([item.native.bom_ref for item in offenders]),
        ),
    )


def _evaluate(element: Element, context: _Context) -> ElementResult:
    if element.cluster is MODELS and not context.models:
        return ElementResult(element, NOT_APPLICABLE, reasons=("no-model-component",))
    if element.cluster is DATASETS and not context.datasets:
        return ElementResult(element, NOT_APPLICABLE, reasons=("no-dataset-component",))
    if element.assessable == NEEDS_PRODUCER_INPUT:
        return ElementResult(element, NEEDS_PRODUCER_INPUT)
    if element.id in _SUBJECT_RULES:
        return _per_subject(element, context)
    outcome = _DOCUMENT_CHECKS[element.id](context)
    return ElementResult(
        element,
        outcome.state,
        basis=outcome.basis if outcome.state == PRESENT else None,
        reasons=outcome.reasons,
        cyclonedx=Listing.of(outcome.cyclonedx),
        native=Listing.of(outcome.native),
        relationships=outcome.relationships,
    )


def _context(bom: AIBOM, export: Mapping[str, Any]) -> _Context:
    exported: dict[object, tuple[str, Mapping[str, Any]]] = {}
    for index, component in enumerate(_seq(export.get("components"))):
        exported.setdefault(
            _obj(component).get("bom-ref"), (f"/components/{index}", _obj(component))
        )
    native_subject = repository_subject(bom)
    exported_subject = _obj(_obj(export.get("metadata")).get("component"))
    subject: _Located | None = None
    located: list[_Located] = []
    for index, component in enumerate(bom.components):
        if component is native_subject:
            if exported_subject.get("bom-ref") == component.bom_ref:
                subject = _Located(component, index, exported_subject, "/metadata/component")
            continue
        pointer, entry = exported.get(component.bom_ref, ("", None))
        located.append(_Located(component, index, entry, pointer))
    located.sort(key=lambda item: item.native.bom_ref)
    return _Context(
        bom,
        export,
        tuple(located),
        subject,
        tuple(item for item in located if isinstance(item.native, ModelComponent)),
        tuple(
            item
            for item in located
            if isinstance(item.native, DataSourceComponent | RAGSourceComponent)
        ),
    )


def _projection(export: Mapping[str, Any]) -> str | None:
    """The projection version the export declares, as recovery reads it."""
    properties = _seq(_obj(export.get("metadata")).get("properties"))
    values = [
        _obj(entry).get("value")
        for entry in properties
        if _obj(entry).get("name") == PROJECTION_PROPERTY
    ]
    return values[0] if len(values) == 1 and isinstance(values[0], str) else None


def evaluate(bom: AIBOM, export: Mapping[str, Any]) -> Report:
    """Evaluate every element against ``export``, the CycloneDX form of ``bom``."""
    context = _context(bom, export)
    return Report(
        tuple(_evaluate(element, context) for element in ELEMENTS),
        {
            "system": context.subject is not None,
            "models": len(context.models),
            "datasets": sum(isinstance(i.native, DataSourceComponent) for i in context.datasets),
            "retrieval_sources": sum(
                isinstance(i.native, RAGSourceComponent) for i in context.datasets
            ),
        },
        _projection(export),
    )


def assess(bom: AIBOM) -> Report:
    """Generate the CycloneDX export of ``bom`` in memory and evaluate it.

    The export is generated from a copy, so the inventory keeps no value the export
    fills in. Raises ValueError or RecursionError when the inventory cannot be
    exported; nothing is written.
    """
    from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

    return evaluate(bom, CycloneDXGenerator().generate(bom.model_copy(deep=True)))
