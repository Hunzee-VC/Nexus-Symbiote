"""Tool adapters: the exact command each tool is run with, and nothing else.

An adapter says how to invoke a tool and where its output goes. It never rewrites an
output; scoring reads what the tool wrote. Every tool gets its documented AI-BOM
command with only the flags needed to choose an output file and format, to stay quiet,
and to work without a network. No flag that turns a gate on or off is passed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import OUT_DIR

Format = str
OUT_NAMES: dict[Format, str] = {
    "cdx": "bom.cdx.json",
    "sarif": "findings.sarif",
    "native": "native.json",
}


@dataclass(frozen=True)
class Tool:
    id: str
    name: str
    version: str
    license: str
    origin: str
    commands: dict[Format, tuple[str, ...]] = field(default_factory=dict)
    env: tuple[tuple[str, str], ...] = ()
    measured: bool = True
    not_measured: str = ""
    note: str = ""

    def argv(self, fmt: Format, root: str) -> list[str]:
        out = f"{OUT_DIR}/{OUT_NAMES[fmt]}"
        return [part.replace("{root}", root).replace("{out}", out) for part in self.commands[fmt]]


def _symbiote(tool_id: str, version: str, env_dir: str, origin: str, note: str) -> Tool:
    binary = f"{{root}}/{env_dir}/bin/nexus-symbiote"

    def command(fmt: str) -> tuple[str, ...]:
        return (binary, "scan", ".", "--no-project-policy", "-f", fmt, "-o", "{out}")

    return Tool(
        id=tool_id,
        name="Nexus SymBiote",
        version=version,
        license="MIT",
        origin=origin,
        commands={
            "cdx": command("cyclonedx"),
            "sarif": command("sarif"),
            "native": command("json"),
        },
        note=note,
    )


def _agent_bom() -> Tool:
    binary = "{root}/agent-bom/bin/agent-bom"

    def command(fmt: str) -> tuple[str, ...]:
        return (binary, "scan", "-p", ".", "--offline", "--no-scan", "-q", "-f", fmt, "-o", "{out}")

    return Tool(
        id="agent-bom",
        name="agent-bom",
        version="0.115.3",
        license="Apache-2.0",
        origin="PyPI agent-bom==0.115.3",
        commands={
            "cdx": command("cyclonedx"),
            "sarif": command("sarif"),
            "native": command("json"),
        },
        note=(
            "--offline --no-scan: package vulnerability matching needs a downloaded database "
            "and is outside this round; without --no-scan an offline run is reported incomplete."
        ),
    )


def _trusera() -> Tool:
    binary = "{root}/trusera/bin/ai-bom"

    def command(fmt: str) -> tuple[str, ...]:
        return (binary, "scan", ".", "-f", fmt, "-o", "{out}", "--deep", "-q", "--no-telemetry")

    return Tool(
        id="trusera-ai-bom",
        name="Trusera ai-bom",
        version="3.6.0",
        license="Apache-2.0",
        origin="PyPI ai-bom==3.6.0",
        commands={
            "cdx": command("cyclonedx"),
            "sarif": command("sarif"),
            "native": command("json"),
        },
        note="--deep enables its Python AST analysis; LLM enrichment is not used.",
    )


TOOLS: tuple[Tool, ...] = (
    _symbiote(
        "symbiote-release",
        "0.1.0",
        "symbiote-0.1.0",
        "PyPI nexus-symbiote[all]==0.1.0",
        "The latest published release.",
    ),
    _symbiote(
        "symbiote-checkout",
        "a13b622 (unreleased)",
        "symbiote-tree",
        "this repository's source at a13b622 with requirements-ci.lock",
        "The development tree: version 0.2.0 plus unreleased changes, not published on PyPI. "
        "Shown beside the release for the maintainers; not comparable with other tools' releases.",
    ),
    Tool(
        id="cdxgen",
        name="cdxgen",
        version="13.8.0",
        license="Apache-2.0",
        origin="npm @cdxgen/cdxgen@13.8.0, installed with --ignore-scripts",
        commands={"cdx": ("{root}/cdxgen/node_modules/.bin/aibom", "-o", "{out}", ".")},
        note="The dedicated `aibom` command with its defaults.",
    ),
    _agent_bom(),
    _trusera(),
    Tool(
        id="aisbom",
        name="AIsbom",
        version="1.7.0",
        license="Apache-2.0",
        origin="PyPI aisbom-cli==1.7.0",
        commands={
            "cdx": ("{root}/aisbom/bin/aisbom", "scan", ".", "--output", "{out}", "--offline")
        },
        env=(("AISBOM_NO_TELEMETRY", "1"),),
    ),
    Tool(
        id="syft",
        name="Syft",
        version="1.57.2",
        license="Apache-2.0",
        origin="go install github.com/anchore/syft/cmd/syft@v1.57.2",
        commands={
            "cdx": ("{root}/gobin/syft", "scan", "dir:.", "-q", "-o", "cyclonedx-json={out}")
        },
        env=(("SYFT_CHECK_FOR_APP_UPDATE", "false"),),
        note="A general SBOM generator, included as the baseline.",
    ),
    Tool(
        id="xbom",
        name="xbom",
        version="0.0.3",
        license="Apache-2.0",
        origin="go install github.com/safedep/xbom@v0.0.3",
        commands={"cdx": ("{root}/gobin/xbom", "generate", "-D", ".", "--bom", "{out}")},
        note="Posts usage telemetry on every invocation, including --help; it cannot leave the sandbox.",
    ),
    Tool(
        id="cisco-aibom",
        name="Cisco AI BOM",
        version="1.10.1",
        license="Apache-2.0",
        origin="PyPI cisco-aibom==1.10.1",
        measured=False,
        not_measured=(
            "`cisco-aibom analyze` refuses to run without --llm-model, and an LLM provider "
            "cannot be reached from a network-isolated run."
        ),
    ),
    Tool(
        id="owasp-aibom-generator",
        name="OWASP AIBOM Generator",
        version="commit 45851cb (2026-10-17)",
        license="Apache-2.0",
        origin="github.com/GenAI-Security-Project/aibom-generator",
        measured=False,
        not_measured=(
            "Its input is a Hugging Face model identifier, which it resolves over the network; "
            "it does not scan a repository."
        ),
    ),
    Tool(
        id="k8s-aibom",
        name="k8s-aibom",
        version="v1.6.2",
        license="Apache-2.0",
        origin="github.com/GoogleCloudPlatform/k8s-aibom",
        measured=False,
        not_measured="Its input is a running Kubernetes cluster; it does not scan a repository.",
    ),
)


def by_id(tool_id: str) -> Tool:
    for tool in TOOLS:
        if tool.id == tool_id:
            return tool
    raise KeyError(tool_id)
