"""Generated-input checks of the hand-written parsers against reference behaviour.

The requirements collector emulates pip's line handling; ``packaging`` is the reference for
what a requirement means and pip's own requirements-file reader, wherever pip is installed
(always in CI), for how a line is read, so the collector must reach the same name and pin
however the line is decorated. Unparseable or deeply nested input must leave a gap or a
failed collector, never silence. No collected file may crash a scan in any export format
beyond the one failure docs/known-limitations.md documents. Redaction must never let a
planted secret through, and hostile inputs must not make parsing super-linear. The
repository's Hypothesis profile (tests/conftest.py) keeps every run deterministic; the
weekly ``fuzz`` profile explores further.
"""

from __future__ import annotations

import json
import os
import re
import string
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

import pytest
from click.testing import CliRunner
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, NO_CONTENT_SERIAL
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners.base import sanitized_origin
from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.utils.secrets import redact_descriptor, redact_text, redact_url

# Names every version of the AI-package filter has to recognise.
AI_NAMES = st.sampled_from(
    ["torch", "Torch", "transformers", "openai", "OpenAI", "anthropic", "safetensors", "chromadb"]
)
RELEASE = st.lists(st.integers(min_value=0, max_value=99), min_size=1, max_size=4).map(
    lambda parts: ".".join(map(str, parts))
)
PUBLIC = st.tuples(RELEASE, st.sampled_from(["", "rc1", "a2", ".post1", ".dev3"])).map("".join)
LOCAL = st.tuples(PUBLIC, st.sampled_from(["", "+cpu", "+cu121.local"])).map("".join)
CLAUSE = st.one_of(
    st.tuples(st.sampled_from(["==", "!=", "==="]), LOCAL),
    st.tuples(st.sampled_from([">=", "<=", ">", "<"]), PUBLIC),
    st.tuples(st.just("~="), PUBLIC.filter(lambda v: "." in v.split("rc")[0].split("a")[0])),
)
SPECIFIERS = st.lists(CLAUSE, max_size=3).map(lambda cs: ",".join(op + v for op, v in cs))
WILDCARD = st.tuples(st.sampled_from(["==", "!="]), RELEASE).map(lambda c: c[0] + c[1] + ".*")
EXTRAS = st.lists(st.sampled_from(["cuda", "dev", "tests"]), max_size=2, unique=True).map(
    lambda extras: f"[{','.join(extras)}]" if extras else ""
)
MARKERS = st.sampled_from(
    ["", ' ; python_version >= "3.9"', "; sys_platform == 'linux'", ' ; extra == "gpu"']
)


@st.composite
def requirements(draw: st.DrawFn) -> str:
    name = draw(AI_NAMES)
    specifier = draw(st.one_of(SPECIFIERS, WILDCARD))
    spacing = draw(st.sampled_from(["", " ", "  "]))
    text = f"{name}{draw(EXTRAS)}{spacing}{specifier}{draw(MARKERS)}"
    try:
        Requirement(text)
    except InvalidRequirement:
        assume(False)
    return text


@st.composite
def decorated(draw: st.DrawFn, requirement: str) -> str:
    """The requirement as pip would still read it: indentation, comments, options, CRLF."""
    body = requirement
    if draw(st.booleans()):
        # pip joins a continued line with nothing in between, even inside a word.
        cut = draw(st.integers(min_value=1, max_value=len(body) - 1))
        body = f"{body[:cut]}\\\n{body[cut:]}"
    line = draw(st.sampled_from(["", " ", "\t", "   "])) + body
    if draw(st.booleans()):
        line += " --hash=sha256:" + "ab" * 32
    if draw(st.booleans()):
        line += draw(st.sampled_from([" # pinned for CUDA", "  #comment", "\t# note"]))
    if draw(st.booleans()) and " " in requirement.strip():
        head, tail = requirement.strip().split(" ", 1)
        line = f"{head} \\\n{tail}"
    ending = draw(st.sampled_from(["\n", "\r\n", ""]))
    header = draw(
        st.sampled_from(["", "# generated\n", "\ufeff", "--index-url https://pypi.org/simple\n"])
    )
    return header + line + ending


def reference_pin(requirement: Requirement) -> str | None:
    """The exact version packaging says the requirement pins, if any."""
    # A repeated clause adds nothing. packaging 26 drops repeats only once something has
    # compared the set, packaging 24 always: count each clause once either way.
    clauses = list(dict.fromkeys(requirement.specifier))
    if requirement.url or requirement.marker or len(clauses) != 1:
        return None
    clause = clauses[0]
    if clause.operator not in {"==", "==="} or "*" in clause.version:
        return None
    try:
        version = Version(clause.version)
    except InvalidVersion:
        return None
    return clause.version if clause.contains(version, prereleases=True) else None


def scan(files: dict[str, bytes]):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name, data in files.items():
            (root / name).write_bytes(data)
        return RegistryScanner().scan(root)


def pypi_components(result, name):
    ref = f"registry:pypi/{canonicalize_name(name)}"
    return [c for c in result.components if c.bom_ref == ref]


@given(st.data())
def test_requirements_lines_reach_the_name_and_pin_packaging_reads(data):
    text = data.draw(requirements())
    line = data.draw(decorated(text))
    requirement = Requirement(text)
    result = scan({"requirements.txt": line.encode()})
    found = pypi_components(result, requirement.name)
    assert len(found) == 1, (line, result.scan_failures)
    assert result.scan_failures == []
    pin = reference_pin(requirement)
    component = found[0]
    if pin is None:
        assert component.package_url is None
        assert any(risk.category == "version_pinning" for risk in component.risks)
    else:
        name = canonicalize_name(requirement.name)
        assert component.package_url == f"pkg:pypi/{name}@{quote(pin, safe='')}"
        assert not any(risk.category == "version_pinning" for risk in component.risks)


@pytest.fixture(scope="module")
def pip_reader():
    """pip's own requirements-file reader and its version. CI installs with pip."""
    try:
        from pip import __version__
        from pip._internal.network.session import PipSession
        from pip._internal.req.req_file import parse_requirements
    except ImportError:
        if os.environ.get("CI"):
            raise
        pytest.skip("pip is not importable here; CI, which installs with pip, runs this test")
    session = PipSession()

    def read(content: bytes) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.txt"
            path.write_bytes(content)
            return [parsed.requirement for parsed in parse_requirements(str(path), session=session)]

    return __version__, read


@given(st.data())
def test_pip_reads_each_decorated_line_as_the_requirement_the_collector_reports(pip_reader, data):
    version, read = pip_reader
    text = data.draw(requirements())
    content = data.draw(decorated(text)).encode()
    found = read(content)
    assert len(found) == 1, (version, content, found)
    requirement = Requirement(found[0])
    assert requirement == Requirement(text), (version, content, found)
    result = scan({"requirements.txt": content})
    components = pypi_components(result, requirement.name)
    assert len(components) == 1 and result.scan_failures == [], (version, content)
    pin = reference_pin(requirement)
    name = canonicalize_name(requirement.name)
    purl = None if pin is None else f"pkg:pypi/{name}@{quote(pin, safe='')}"
    assert components[0].package_url == purl, (version, content)


@given(st.data())
def test_a_requirement_split_across_files_and_pyproject_is_one_component(data):
    text = data.draw(requirements())
    requirement = Requirement(text)
    pyproject = f'[project]\nname = "demo"\nversion = "1"\ndependencies = [{json.dumps(text)}]\n'
    result = scan(
        {
            "requirements.txt": f"{text}\n".encode(),
            "requirements-dev.txt": f"{text}  # again\n".encode(),
            "pyproject.toml": pyproject.encode(),
        }
    )
    assert len(pypi_components(result, requirement.name)) == 1
    assert result.scan_failures == []


GARBAGE = st.text(
    st.characters(
        exclude_categories=("Cs",),
        include_characters=" \t\u00a0\ufeff\\#@;[]=<>!~*,$\"'{}()/:%\x00\x1b\u202e",
    ),
    min_size=1,
    max_size=40,
)


@given(AI_NAMES, GARBAGE)
def test_an_ai_requirement_line_is_never_silently_dropped(name, garbage):
    assume(not garbage[0].isalnum() and garbage[0] not in "._-")
    result = scan({"requirements.txt": f"{name}{garbage}\n".encode()})
    gaps = [*result.scan_failures, *result.surfaces_excluded]
    assert pypi_components(result, name) or any("requirements" in gap for gap in gaps)


@given(AI_NAMES, st.binary(max_size=64))
def test_undecodable_requirement_files_are_a_gap(name, payload):
    data = name.encode() + b"==1.0\n" + payload
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        result = scan({"requirements.txt": data})
        assert any("requirements.txt" in failure for failure in result.scan_failures)
    else:
        scan({"requirements.txt": data})


IMAGES = st.tuples(
    st.sampled_from(["", "docker.io/", "ghcr.io/acme/", "registry.example:5000/team/"]),
    st.sampled_from(["vllm/vllm-openai", "ollama/ollama", "model-server", "llama-runner"]),
    st.sampled_from(["", ":latest", ":0.6.1", ":v2"]),
    st.sampled_from(["", "@sha256:" + "0123456789abcdef" * 4]),
).map("".join)


@given(
    IMAGES,
    st.sampled_from(["FROM", "from", "From"]),
    st.sampled_from(["", "--platform=linux/amd64 ", "--platform=$BUILDPLATFORM "]),
    st.sampled_from(["", " AS build", " as Build"]),
    st.sampled_from([" ", "  ", "\t", " \\\n  "]),
)
def test_dockerfile_from_names_the_image_buildkit_pulls(image, keyword, flags, stage, gap):
    dockerfile = f"# syntax=docker/dockerfile:1\n{keyword}{gap}{flags}{image}{stage}\nRUN true\n"
    result = scan({"Dockerfile": dockerfile.encode()})
    images = [c for c in result.components if c.bom_ref.startswith("registry:docker/")]
    assert [c.name for c in images] == [image]
    pinned = "@sha256:" in image
    assert pinned == (not images[0].risks)


@given(IMAGES)
def test_a_from_naming_an_earlier_stage_is_not_an_image(image):
    dockerfile = f"FROM {image} AS Base\nFROM base\nRUN true\nFROM BASE AS final\n"
    result = scan({"Dockerfile": dockerfile.encode()})
    assert [c.name for c in result.components] == [image]


SECRETS = st.text(
    st.characters(min_codepoint=48, max_codepoint=122, categories=("Lu", "Ll", "Nd")),
    min_size=12,
    max_size=40,
).filter(lambda s: any(c.isupper() for c in s) and any(c.isdigit() for c in s))
# No ASCII capital letter, so the surrounding text can never itself spell a secret.
CONTEXT = st.text(
    st.characters(exclude_categories=("Cs",), exclude_characters=string.ascii_uppercase),
    max_size=30,
)


@given(SECRETS, CONTEXT, CONTEXT)
def test_a_known_secret_never_survives_redaction(secret, before, after):
    assert secret not in redact_text(f"{before}{secret}{after}", [secret])


@given(
    SECRETS,
    CONTEXT,
    st.sampled_from(
        [
            "https://user:{s}@api.example/v1",
            "https://api.example/v1?token={s}",
            "wss://{s}@stream.example:8443/x#frag",
            "https://api.example/{s}/models",
            "https://api.example/v1#{s}",
            "postgresql://svc:{s}@db.internal:5432/vectors",
        ]
    ),
)
def test_a_secret_in_a_url_never_survives_text_redaction(secret, context, template):
    url = template.format(s=secret)
    assert secret not in redact_text(f"{context} {url} {context}")
    assert secret not in redact_url(url)
    origin = sanitized_origin(url)
    assert secret not in origin
    assert origin.count("/") == 2 or origin == "[redacted]"


@given(
    SECRETS,
    st.sampled_from(["api_key", "API-KEY", "token", "GITHUB_TOKEN", "password", "client_secret"]),
    st.sampled_from(["=", ": ", " = ", ":"]),
    CONTEXT,
)
def test_an_assigned_secret_never_survives_text_redaction(secret, key, separator, context):
    assert secret not in redact_text(f"{context} {key}{separator}{secret} {context}")


@given(SECRETS, st.sampled_from(["Bearer", "bearer", "Basic"]), CONTEXT)
def test_an_authorization_value_never_survives_text_redaction(secret, scheme, context):
    assert secret not in redact_text(f"{context} Authorization: {scheme} {secret}")


DESCRIPTOR_VALUES = st.recursive(
    st.none() | st.booleans() | st.integers() | CONTEXT,
    lambda children: (
        st.lists(children, max_size=3) | st.dictionaries(CONTEXT, children, max_size=3)
    ),
    max_leaves=12,
)


@given(SECRETS, DESCRIPTOR_VALUES, st.data())
def test_a_secret_planted_anywhere_in_a_tool_descriptor_is_redacted(secret, value, data):
    planted = data.draw(st.sampled_from(["description", "key", "default", "nested", "name"]))
    descriptor = {
        "name": "query",
        "description": "Runs a query.",
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
        "annotations": value,
    }
    if planted == "description":
        descriptor["description"] += f" Use {secret}."
    elif planted == "key":
        descriptor[f"x-{secret}"] = value
    elif planted == "default":
        descriptor["inputSchema"]["properties"]["q"]["default"] = secret
    elif planted == "nested":
        descriptor["annotations"] = {"hint": [value, {"v": f"k={secret}"}]}
    else:
        descriptor["name"] = f"query-{secret}"
    redacted = redact_descriptor(descriptor, [secret])
    assert secret not in json.dumps(redacted, ensure_ascii=False)


def _elapsed(action) -> float:
    started = time.perf_counter()
    action()
    return time.perf_counter() - started


# Each input is a few hundred kilobytes: linear parsing takes milliseconds, while a
# quadratic regular expression would take minutes, so the bound is far from either.
HOSTILE_REQUIREMENTS = [
    "torch" + "[" * 200_000,
    "torch==" + "1." * 100_000,
    "torch @ https://" + "a" * 200_000,
    "torch" + " " * 200_000 + "#",
    "torch" + "\\\n" * 100_000,
    "torch;" + " and python_version" * 10_000,
    "torch==1.0" + " --hash=sha256:" * 10_000,
]


def test_hostile_requirements_lines_parse_in_bounded_time():
    for line in HOSTILE_REQUIREMENTS:
        assert _elapsed(lambda line=line: scan({"requirements.txt": line.encode()})) < 10, line[:20]


HOSTILE_TEXT = [
    "a" * 300_000 + "://",
    "token" + "=" * 300_000,
    "Bearer " * 50_000,
    "https://" + "@" * 300_000,
    "x" * 300_000 + "password: ",
]


def test_hostile_text_redacts_in_bounded_time():
    for text in HOSTILE_TEXT:
        assert _elapsed(lambda text=text: redact_text(text, ["secretvalue"])) < 10, text[:20]


COLLECTED_FILES = [
    ".mcp.json",
    ".cursor/mcp.json",
    ".claude/settings.json",
    ".well-known/agent.json",
    "rag_config.json",
    "rag_config.yaml",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "Dockerfile",
    "docker-compose.yml",
    "CLAUDE.md",
    "model.safetensors",
]
JSON_DOCUMENTS = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=12),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4)
    ),
    max_leaves=16,
).map(lambda value: json.dumps(value).encode())
CONTENT = st.one_of(st.binary(max_size=256), st.text(max_size=256).map(str.encode), JSON_DOCUMENTS)
# Letters and lone surrogates: JSON escapes the latter, so the file is valid ASCII JSON whose
# strings cannot be encoded as UTF-8.
SURROGATE_TEXT = st.text(
    st.characters(min_codepoint=0xD800, max_codepoint=0xDFFF, exclude_categories=())
    | st.characters(min_codepoint=0x61, max_codepoint=0x7A),
    min_size=1,
    max_size=6,
)
# Where a value reaches the exported record, not only the native inventory.
STRUCTURED = {
    "rag_config.json": st.fixed_dictionaries(
        {
            "vector_store": st.fixed_dictionaries(
                {"provider": SURROGATE_TEXT, "collection": SURROGATE_TEXT}
            ),
            "embedding_model": SURROGATE_TEXT,
        }
    ),
    ".well-known/agent.json": st.fixed_dictionaries(
        {
            "name": SURROGATE_TEXT,
            "url": st.just("https://agent.example/"),
            "skills": st.lists(
                st.fixed_dictionaries({"id": SURROGATE_TEXT, "name": SURROGATE_TEXT}),
                max_size=2,
            ),
        }
    ),
    "package.json": st.fixed_dictionaries(
        {"dependencies": st.dictionaries(st.just("openai") | SURROGATE_TEXT, SURROGATE_TEXT)}
    ),
    ".mcp.json": st.fixed_dictionaries(
        {
            "mcpServers": st.dictionaries(
                SURROGATE_TEXT,
                st.fixed_dictionaries(
                    {"command": SURROGATE_TEXT, "args": st.lists(SURROGATE_TEXT)}
                ),
                max_size=2,
            )
        }
    ),
}
FORMATS = st.sampled_from(["json", "cyclonedx", "spdx", "sarif"])
LONE_SURROGATE_ESCAPE = re.compile(rb"\\u[dD][89a-fA-F][0-9a-fA-F]{2}")


# The CLI turns an unexpected exception into this message and exit status 1, so a crash
# shows in the output, not as an exception the runner sees.
INTERNAL_ERROR = "internal error ("
EXPORT_REFUSED = "cannot be exported as"


def documented_export_failure(content: bytes) -> bool:
    """Only this inventory is refused ("Malformed input" in docs/known-limitations.md)."""
    return LONE_SURROGATE_ESCAPE.search(content) is not None


def assert_no_crash(result) -> None:
    exception = result.exception
    assert exception is None or isinstance(exception, SystemExit), repr(exception)
    assert INTERNAL_ERROR not in result.output, result.output


@pytest.mark.parametrize("name", COLLECTED_FILES)
@settings(max_examples=max(5, settings.default.max_examples // 10))
@given(data=st.data())
def test_any_content_in_a_collected_file_yields_an_inventory_not_a_crash(name, data):
    strategy = CONTENT
    if name in STRUCTURED:
        strategy = strategy | STRUCTURED[name].map(lambda value: json.dumps(value).encode())
    content = data.draw(strategy)
    fmt = data.draw(FORMATS)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / "project" / name
        path.parent.mkdir(parents=True)
        path.write_bytes(content)
        output = root / "inventory.json"
        result = CliRunner().invoke(
            main, ["scan", str(root / "project"), "--report-only", "-f", fmt, "-o", str(output)]
        )
        assert_no_crash(result)
        assert EXPORT_REFUSED not in result.output, (fmt, result.output)
        if NO_CONTENT_SERIAL in " ".join(result.output.split()):
            assert documented_export_failure(content), (fmt, result.output)
            assert not output.exists()
        if result.exit_code != 0:
            return
        document = json.loads(output.read_text())
        assert isinstance(document, dict)
        if fmt != "json":
            return
        assert isinstance(document.get("components"), list)
        # An inventory without a content digest is never written, so what is written reads.
        inventory = AIBOM.load(output)
        report = AIBOMDiffer().diff(inventory, AIBOM.load(output))
        assert not report.has_changes and report.total_changes == 0
        assert report.security_alerts == []


NESTING = 1_000
NESTED_INPUTS = {
    "requirements.txt": (
        "torch; " + "(" * NESTING + 'python_version >= "3"' + ")" * NESTING + "\nopenai==1.0\n"
    ),
    ".mcp.json": '{"mcpServers": ' + '{"a": ' * NESTING + "1" + "}" * NESTING + "}",
    "package.json": '{"dependencies": ' + "[" * NESTING + "]" * NESTING + "}",
    "pyproject.toml": (
        "[project]\nname = 'x'\nversion = '1'\ndependencies = ["
        + "[" * NESTING
        + "]" * NESTING
        + "]\n"
    ),
    ".well-known/agent.json": "[" * NESTING + "]" * NESTING,
    "rag_config.json": '{"vector_store": ' + "[" * NESTING + "]" * NESTING + "}",
}


@pytest.mark.parametrize("name", sorted(NESTED_INPUTS))
def test_deeply_nested_input_fails_closed_in_bounded_time(tmp_path, name):
    path = tmp_path / "project" / name
    path.parent.mkdir(parents=True)
    path.write_text(NESTED_INPUTS[name])
    output = tmp_path / "inventory.json"
    started = time.perf_counter()
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path / "project"), "--report-only", "-f", "json", "-o", str(output)]
    )
    assert time.perf_counter() - started < 30
    assert_no_crash(result)
    if not output.exists():
        assert result.exit_code != 0
        return
    inventory = json.loads(output.read_text())
    completeness = inventory["metadata"]["completeness"]
    refs = {component["bom_ref"] for component in inventory["components"]}
    if name == "requirements.txt":
        # Each line is understood, a gap, or its collector is reported as failed.
        failed = completeness["scanner_status"].get("registry") == "failed"
        gaps = [*completeness["scan_failures"], *completeness["surfaces_excluded"]]
        assert "registry:pypi/openai" in refs or failed
        assert (
            "registry:pypi/torch" in refs
            or failed
            or any("requirements.txt" in gap for gap in gaps)
        )
