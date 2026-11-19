"""Safety invariants of every built-in collector on the hostile seeded corpus.

The corpus comes from ``benchmarks/seeded-corpus/generate.py`` (seeds 20261118 and 4242),
built into a temporary directory once per module and deleted afterwards, plus the
``s10-new-surfaces`` scenario this module writes. Its pickles, MCP launch commands and
build hooks only create empty files under ``<corpus>/canary`` if something executes them;
nothing here executes them. Scans run through the real CLI, in this process and in an
isolated interpreter under CPU and memory caps, and every collector also runs directly.

Each invariant is a separate test: nothing executes, connects, reads through a symbolic
link that leaves the scan root, leaks a planted credential in any encoding, or writes a
raw terminal control character; time and memory stay bounded on the decompression bomb
and the deeply nested JSON; two checkouts scan to identical bytes. New parsers add a row
to ``_new_surfaces``.
"""

from __future__ import annotations

import base64
import contextlib
import ctypes
import errno
import importlib.util
import json
import os
import shutil
import stat
import struct
import sys
import zipfile
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import quote, quote_plus

import click
import pytest
from click.testing import CliRunner, Result

from nexus_symbiote import modes
from nexus_symbiote.cli import main
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from nexus_symbiote.scanners import ALL_SCANNERS
from tests.support import ROOT, CappedRun, capped_cli

GENERATOR = ROOT / "benchmarks" / "seeded-corpus" / "generate.py"
PUBLIC_SEED, HOLDOUT_SEED = 20261118, 4242
NEW_SURFACES = "s10-new-surfaces"
SCENARIOS = {
    PUBLIC_SEED: (
        "s01-models",
        "s02-model-refs",
        "s03-data",
        "s04-mcp",
        "s05-tooldefs-v1",
        "s05-tooldefs-v2",
        "s06-skills",
        "s07-agents",
        "s08-packages",
        "s09a-pickle-exec",
        "s09b-mcp-exec",
        "s09c-symlink-escape",
        "s09d-terminal-injection",
        "s09e-resource-exhaustion",
        "s09f-build-exec",
        NEW_SURFACES,
    ),
    HOLDOUT_SEED: ("s04-mcp", "s06-skills", NEW_SURFACES),
}
CASES = [(seed, scenario) for seed, scenarios in SCENARIOS.items() for scenario in scenarios]
CASE_IDS = [f"{seed}-{scenario}" for seed, scenario in CASES]
REPRODUCIBLE = [scenario for scenario in SCENARIOS[PUBLIC_SEED] if scenario < "s09"]
FORMATS = ("json", "cyclonedx", "spdx", "sarif")
SOURCE_DATE_EPOCH = "1763424000"
INTERNAL_ERROR = "internal error ("
# The distinct collection failures each scenario names, one per entry, by substring;
# every other scenario names none. "{surrogate}" is the server that s10's lone-surrogate
# row names.
EXPECTED_FAILURES = {
    "s09c-symlink-escape": (
        ".cursor/mcp.json: symlink target is outside the collection root",
        "models: symlink target is outside the collection root",
    ),
    "s09e-resource-exhaustion": (".cursor/mcp.json: invalid JSON or duplicate keys",),
    NEW_SURFACES: (
        ".cursor/mcp.json: invalid tool definition for server '{surrogate}'",
        ".mcp.json: nonregular file excluded",
        ".mcp.json: read refused",
        "CLAUDE.md: nonregular file excluded",
        "CLAUDE.md: read refused",
    ),
}
# C0 controls other than tab, line feed and carriage return, DEL, and the C1 controls
# (CSI is U+009B, DCS U+0090): any of them raw in an output can drive a terminal. Outputs
# are decoded with surrogateescape, so a raw byte that is not valid UTF-8, such as a lone
# 0x9B, arrives as U+DC9B and is matched in that form too.
_CONTROL_CODES = frozenset((*range(0x20), *range(0x7F, 0xA0))) - {0x09, 0x0A, 0x0D}
_CONTROL = frozenset(chr(code) for code in _CONTROL_CODES) | frozenset(
    chr(0xDC00 + code) for code in _CONTROL_CODES if code >= 0x80
)
# Audit events that mean a collector reached the network, started a process or resolved
# a pickle global; code executed or imported from a file under the corpus is reported
# too. Socket creation is not here: an import-time probe in urllib3 creates a loopback
# socket before the offline guard starts. The guard replaces the Python entry points, so
# an attempt it refuses raises no event: every OfflineViolation is recorded as well,
# because a collector that swallows one would otherwise hide the attempt.
_FORBIDDEN_EVENTS = (
    "socket.connect",
    "socket.sendto",
    "socket.sendmsg",
    "socket.getaddrinfo",
    "socket.gethostbyname",
    "socket.gethostbyaddr",
    "socket.getnameinfo",
    "subprocess.Popen",
    "os.system",
    "os.exec",
    "os.fork",
    "os.forkpty",
    "os.posix_spawn",
    "os.spawn",
    "pickle.find_class",
)
_AUDIT_PRELUDE = """
import os as _audit_os, sys as _audit_sys
_audit_log = _audit_os.open({log!r}, _audit_os.O_WRONLY | _audit_os.O_CREAT | _audit_os.O_APPEND)
_audit_roots = {roots!r}
_audit_forbidden = frozenset({forbidden!r})
def _audit_record(event, args):
    if event in _audit_forbidden:
        note = event
    elif event == "exec" and str(getattr(args[0], "co_filename", "")).startswith(_audit_roots):
        note = "exec " + args[0].co_filename
    elif event == "import" and isinstance(args[1], str) and args[1].startswith(_audit_roots):
        note = "import " + args[1]
    else:
        return
    _audit_os.write(_audit_log, note.encode("unicode_escape") + b"\\n")
_audit_sys.addaudithook(_audit_record)
import nexus_symbiote.modes as _audit_modes
_audit_refusal = _audit_modes.OfflineViolation.__init__
def _audit_refused(self, *args):
    _audit_os.write(_audit_log, ("refused " + repr(args)).encode("unicode_escape") + b"\\n")
    _audit_refusal(self, *args)
_audit_modes.OfflineViolation.__init__ = _audit_refused
"""


def _load_generator() -> ModuleType:
    name = "seeded_corpus_generate"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Dataclasses resolve string annotations through sys.modules.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class OutsideWatch:
    """Every open of, or read from, a file or directory outside the scan roots.

    inotify reports opens made through any path, a symbolic link included, by any process.
    """

    _IN_ACCESS, _IN_OPEN = 0x1, 0x20
    _IN_NONBLOCK, _IN_CLOEXEC = os.O_NONBLOCK, 0o2000000

    def __init__(self, directories: list[Path]) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        self._fd = libc.inotify_init1(self._IN_NONBLOCK | self._IN_CLOEXEC)
        if self._fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self._names: dict[int, Path] = {}
        for directory in directories:
            wd = libc.inotify_add_watch(
                self._fd, os.fsencode(directory), self._IN_ACCESS | self._IN_OPEN
            )
            if wd < 0:
                raise OSError(ctypes.get_errno(), f"inotify_add_watch failed for {directory}")
            self._names[wd] = directory

    def opened(self) -> list[str]:
        """What was opened or read since the last call."""
        events: list[str] = []
        while True:
            try:
                data = os.read(self._fd, 65536)
            except OSError as exc:
                if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    return sorted(set(events))
                raise
            offset = 0
            while offset < len(data):
                wd, _mask, _cookie, length = struct.unpack_from("iIII", data, offset)
                name = data[offset + 16 : offset + 16 + length].rstrip(b"\0")
                events.append(str(self._names[wd] / os.fsdecode(name)))
                offset += 16 + length

    def close(self) -> None:
        os.close(self._fd)


@dataclass
class SeededCorpus:
    seed: int
    root: Path
    secrets: list[str]
    outside_tokens: list[str]
    sentinels: dict[str, list[str]]
    failures: dict[str, tuple[str, ...]]

    @property
    def canary(self) -> Path:
        return self.root / "canary"

    def scenario(self, name: str) -> Path:
        return self.root / "scenarios" / name


def _new_surfaces(corpus: Any) -> tuple[list[str], list[str], dict[str, str]]:
    """Write s10: one row per hostile input aimed at an existing reader.

    Returns the planted credentials, the sentinel names that must still be inventoried,
    and the values that EXPECTED_FAILURES names.
    """
    base = corpus.root / "scenarios" / NEW_SURFACES
    (base / ".cursor").mkdir(parents=True)
    (base / ".vscode").mkdir()
    secrets: list[str] = []
    sentinels: list[str] = []
    # A JSON tool description holding a lone surrogate: the server fails by name and
    # the inventory is still written.
    surrogate = f"{corpus.tok()}-surrogate"
    tool = {"name": "lookup", "description": "Look up <> records", "inputSchema": {}}
    server = {"command": "npx", "args": ["-y", f"@acme/{surrogate}@1.0.0"], "tools": [tool]}
    (base / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {surrogate: server}}).replace("<>", "\\ud800")
    )
    # A literal AWS key pair in a VS Code server's environment.
    keyed = corpus.tok()
    key_id = "AKIA" + corpus.alnum(16).upper()
    secret_key = corpus.alnum(40)
    secrets += [key_id, secret_key]
    sentinels.append(keyed)
    (base / ".vscode" / "mcp.json").write_text(
        json.dumps(
            {
                "servers": {
                    keyed: {
                        "type": "stdio",
                        "command": "npx",
                        "args": ["-y", f"@acme/{keyed}@2.0.0"],
                        "env": {"AWS_ACCESS_KEY_ID": key_id, "AWS_SECRET_ACCESS_KEY": secret_key},
                    }
                }
            }
        )
    )
    # FIFOs where a client configuration and an instruction file belong: reading either
    # would block the scan forever.
    os.mkfifo(base / ".mcp.json")
    os.mkfifo(base / "CLAUDE.md")
    return secrets, sentinels, {"surrogate": surrogate}


def _build(generator: ModuleType, root: Path, seed: int, builders: tuple[str, ...]) -> SeededCorpus:
    root.mkdir()
    (root / "canary").mkdir()
    corpus = generator.Corpus(root, seed)
    for builder in builders:
        getattr(generator, builder)(corpus)
    secrets, surface_sentinels, values = _new_surfaces(corpus)
    sentinels: dict[str, list[str]] = {NEW_SURFACES: surface_sentinels}
    for item in corpus.items:
        if item["domain"] == "safety" and item["kind"] == "component" and item["weight"] > 0:
            sentinels.setdefault(item["scenario"], []).extend(item["match"])
    failures = {
        scenario: tuple(text.format(**values) for text in texts)
        for scenario, texts in EXPECTED_FAILURES.items()
        if (root / "scenarios" / scenario).is_dir()
    }
    return SeededCorpus(
        seed=seed,
        root=root,
        secrets=[*corpus.safety.get("secrets", ()), *secrets],
        outside_tokens=list(corpus.safety.get("outside_tokens", ())),
        sentinels=sentinels,
        failures=failures,
    )


@dataclass
class Corpora:
    seeds: dict[int, SeededCorpus]
    watch: OutsideWatch
    secrets: list[str]
    outside_tokens: list[str]

    def canaries(self) -> list[str]:
        return sorted(
            str(path) for corpus in self.seeds.values() for path in corpus.canary.rglob("*")
        )


@pytest.fixture(scope="module")
def corpora(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Corpora]:
    generator = _load_generator()
    base = tmp_path_factory.mktemp("hostile-corpus")
    seeds = {
        PUBLIC_SEED: _build(
            generator,
            base / str(PUBLIC_SEED),
            PUBLIC_SEED,
            (
                "build_models",
                "build_model_refs",
                "build_data",
                "build_mcp",
                "build_tooldefs",
                "build_skills",
                "build_agents",
                "build_packages",
                "build_hostile",
            ),
        ),
        HOLDOUT_SEED: _build(
            generator, base / str(HOLDOUT_SEED), HOLDOUT_SEED, ("build_mcp", "build_skills")
        ),
    }
    outside = seeds[PUBLIC_SEED].root / "outside"
    watch = OutsideWatch([outside, *sorted(p for p in outside.rglob("*") if p.is_dir())])
    try:
        yield Corpora(
            seeds=seeds,
            watch=watch,
            secrets=sorted({s for corpus in seeds.values() for s in corpus.secrets}),
            outside_tokens=sorted({t for c in seeds.values() for t in c.outside_tokens}),
        )
    finally:
        watch.close()
        shutil.rmtree(base)


def _base64_forms(data: bytes, encode: Callable[[bytes], bytes]) -> list[str]:
    """The part of ``data``'s encoding that does not depend on its neighbours, at each
    of the three alignments it can start at inside a longer encoded value."""
    forms = []
    for shift in range(3):
        encoded = encode(b"\0" * shift + data).decode()
        start = 4 * -(-shift // 3)
        end = 4 * ((shift + len(data)) // 3)
        forms.append(encoded[start:end])
    return forms


def secret_forms(secret: str) -> list[str]:
    raw = secret.encode()
    return sorted(
        {
            secret,
            raw.hex(),
            raw.hex().upper(),
            quote(secret, safe=""),
            quote_plus(secret),
            "".join(f"\\u{ord(char):04x}" for char in secret),
            "".join(f"\\u{ord(char):04X}" for char in secret),
            *_base64_forms(raw, base64.b64encode),
            *_base64_forms(raw, base64.urlsafe_b64encode),
        }
    )


def assert_no_secret(texts: dict[str, str], secrets: list[str]) -> None:
    leaks = [
        (label, form)
        for secret in secrets
        for form in secret_forms(secret)
        for label, text in texts.items()
        if form in text
    ]
    assert not leaks, leaks


def assert_no_control(texts: dict[str, str]) -> None:
    found = [
        (label, f"U+{ord(char):04X}")
        for label, text in texts.items()
        for char in sorted(_CONTROL.intersection(text))
    ]
    assert not found, found


def unpinned(failures: list[str], expected: tuple[str, ...]) -> tuple[list[str], list[str]]:
    """The expected failures no failure names and the distinct failures no expected one
    accounts for, each matched to at most one expected substring. Every collector that
    reads a surface records its failure, so a failure can repeat."""
    unexpected = sorted(set(failures))
    missing = []
    for text in expected:
        match = next((failure for failure in unexpected if text in failure), None)
        if match is None:
            missing.append(text)
        else:
            unexpected.remove(match)
    return missing, unexpected


def assert_no_crash(result: Result) -> None:
    exception = result.exception
    assert exception is None or isinstance(exception, SystemExit), repr(exception)
    assert INTERNAL_ERROR not in result.output, result.output


@contextlib.contextmanager
def offline_refusals() -> Iterator[list[str]]:
    """Every attempt the offline guard refuses while the block runs, swallowed or not."""
    refused: list[str] = []
    original = modes.OfflineViolation.__init__

    def recording(self: modes.OfflineViolation, *args: object) -> None:
        refused.append(repr(args))
        original(self, *args)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(modes.OfflineViolation, "__init__", recording)
        yield refused


def _decoded(data: bytes) -> str:
    return data.decode("utf-8", errors="surrogateescape")


@dataclass
class InProcessScan:
    outputs: dict[str, str] = field(default_factory=dict)
    results: dict[str, Result] = field(default_factory=dict)
    outside_opens: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)

    def texts(self) -> dict[str, str]:
        streams = {
            f"{label} {name}": _decoded(data)
            for label, result in self.results.items()
            for name, data in (("stdout", result.stdout_bytes), ("stderr", result.stderr_bytes))
        }
        return {**self.outputs, **streams}


class InProcessScans:
    """Each scenario scanned once through the CLI in this process, in every format,
    then exported as VEX and scored as risk text."""

    def __init__(self, corpora: Corpora, directory: Path) -> None:
        self._corpora = corpora
        self._directory = directory
        self._done: dict[tuple[int, str], InProcessScan] = {}

    def __call__(self, seed: int, scenario: str) -> InProcessScan:
        if (seed, scenario) not in self._done:
            self._done[seed, scenario] = self._scan(seed, scenario)
        return self._done[seed, scenario]

    def _scan(self, seed: int, scenario: str) -> InProcessScan:
        record = InProcessScan()
        out = self._directory / str(seed) / scenario
        out.mkdir(parents=True)
        project = str(self._corpora.seeds[seed].scenario(scenario))
        runner = CliRunner()
        for output_format in FORMATS:
            target = out / f"scan.{output_format}"
            with offline_refusals() as refused:
                record.results[output_format] = runner.invoke(
                    main,
                    ["scan", project, "--no-project-policy", "--report-only"]
                    + ["-f", output_format, "-o", str(target)],
                )
            record.refused += refused
            if target.exists():
                record.outputs[output_format] = _decoded(target.read_bytes())
        inventory = out / "scan.json"
        if inventory.exists():
            with offline_refusals() as refused:
                record.results["vex"] = runner.invoke(
                    main, ["vex", str(inventory), "-o", str(out / "vex.json")]
                )
                record.results["risk"] = runner.invoke(
                    main, ["risk", str(inventory), "--no-project-policy"]
                )
            record.refused += refused
            if (out / "vex.json").exists():
                record.outputs["vex"] = _decoded((out / "vex.json").read_bytes())
        record.outside_opens = self._corpora.watch.opened()
        return record


@pytest.fixture(scope="module")
def in_process(
    corpora: Corpora, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[InProcessScans]:
    directory = tmp_path_factory.mktemp("hostile-in-process")
    yield InProcessScans(corpora, directory)
    shutil.rmtree(directory)


@dataclass(frozen=True)
class IsolatedScan:
    run: CappedRun
    output: str
    stdout: str
    stderr: str
    audit: list[str]


def _isolated_scan(
    corpora: Corpora, project: Path, directory: Path, *arguments: str
) -> IsolatedScan:
    directory.mkdir(parents=True)
    home = directory / "home"
    home.mkdir()
    log = directory / "audit.log"
    log.touch()
    roots = tuple(
        sorted(
            {str(c.root) for c in corpora.seeds.values()}
            | {os.path.realpath(c.root) for c in corpora.seeds.values()}
        )
    )
    prelude = _AUDIT_PRELUDE.format(log=str(log), roots=roots, forbidden=_FORBIDDEN_EVENTS)
    output = directory / "scan.json"
    run = capped_cli(
        "scan",
        str(project),
        "--no-project-policy",
        "--report-only",
        "-f",
        "json",
        "-o",
        str(output),
        *arguments,
        prelude=prelude,
        cwd=directory,
        env={**os.environ, "HOME": str(home)},
        stdout=directory / "stdout",
        stderr=directory / "stderr",
        deadline=180.0,
    )
    return IsolatedScan(
        run=run,
        output=_decoded(output.read_bytes()) if output.exists() else "",
        stdout=_decoded((directory / "stdout").read_bytes()),
        stderr=_decoded((directory / "stderr").read_bytes()),
        audit=log.read_text().splitlines(),
    )


class IsolatedScans:
    """Every scenario scanned once by the CLI in an isolated, capped interpreter.

    The runs go in parallel on the first request: each one's CPU time and peak memory
    are its own, whatever runs beside it.
    """

    def __init__(self, corpora: Corpora, directory: Path) -> None:
        self._corpora = corpora
        self._directory = directory
        self._done: dict[tuple[int, str], IsolatedScan] = {}
        self.outside_opens: list[str] = []

    def __call__(self, seed: int, scenario: str) -> IsolatedScan:
        if not self._done:
            with ThreadPoolExecutor(max_workers=max(2, os.cpu_count() or 2)) as pool:
                futures = {
                    case: pool.submit(
                        _isolated_scan,
                        self._corpora,
                        self._corpora.seeds[case[0]].scenario(case[1]),
                        self._directory / str(case[0]) / case[1],
                    )
                    for case in CASES
                }
                self._done = {case: future.result() for case, future in futures.items()}
            self.outside_opens = self._corpora.watch.opened()
        return self._done[seed, scenario]


@pytest.fixture(scope="module")
def isolated(corpora: Corpora, tmp_path_factory: pytest.TempPathFactory) -> Iterator[IsolatedScans]:
    directory = tmp_path_factory.mktemp("hostile-isolated")
    yield IsolatedScans(corpora, directory)
    shutil.rmtree(directory)


def test_the_corpus_has_the_scenarios_this_suite_pins(corpora):
    for seed, corpus in corpora.seeds.items():
        built = sorted(path.name for path in (corpus.root / "scenarios").iterdir())
        assert built == sorted(SCENARIOS[seed])
    assert corpora.seeds[PUBLIC_SEED].outside_tokens
    assert all(corpus.secrets for corpus in corpora.seeds.values())


def test_a_failure_beside_the_pinned_ones_or_counted_twice_is_unpinned():
    expected = ("a.json: invalid JSON", "b: nonregular file excluded")
    pinned = ["a.json: invalid JSON or duplicate keys", "b: nonregular file excluded"]
    assert unpinned(pinned, expected) == ([], [])
    assert unpinned(pinned * 6, expected) == ([], [])
    extra = [*pinned, "a.json: collector crashed mid-file"]
    assert unpinned(extra, expected) == ([], ["a.json: collector crashed mid-file"])
    assert unpinned(pinned[:1], expected) == (["b: nonregular file excluded"], [])
    assert unpinned([], ()) == ([], [])


@pytest.mark.parametrize("data", [b"a\x9b2Kb", b"a\x90qb", b"a\xc2\x9b2Kb", b"a\x1b[2Kb"])
def test_a_raw_control_byte_is_found_whether_or_not_it_is_valid_utf8(data):
    with pytest.raises(AssertionError):
        assert_no_control({"file": _decoded(data)})

    @click.command()
    def write() -> None:
        sys.stdout.buffer.write(data)
        sys.stderr.buffer.write(data)

    record = InProcessScan(results={"probe": CliRunner().invoke(write)})
    found = list(record.texts())
    assert found == ["probe stdout", "probe stderr"]
    for label in found:
        with pytest.raises(AssertionError):
            assert_no_control({label: record.texts()[label]})
    assert_no_control({"file": _decoded("tab\tline\r\n\u00e9\u2028".encode())})


def test_the_cli_and_this_suite_run_every_built_in_collector():
    assert {scanner.name for scanner in ALL_SCANNERS} == BUILTIN_SCANNER_NAMES


@pytest.mark.parametrize(("seed", "scenario"), CASES, ids=CASE_IDS)
def test_in_process_scan_completes_in_every_format_and_executes_nothing(
    corpora, in_process, seed, scenario
):
    record = in_process(seed, scenario)
    for label, result in record.results.items():
        assert_no_crash(result)
        if label in FORMATS:
            assert result.exit_code == 0, (label, result.output)
            assert label in record.outputs, label
    assert set(record.results) == {*FORMATS, "vex", "risk"}
    inventory = json.loads(record.outputs["json"])
    assert sorted(inventory["metadata"]["completeness"]["collectors_requested"]) == sorted(
        BUILTIN_SCANNER_NAMES
    )
    assert corpora.canaries() == []
    assert record.outside_opens == []
    assert record.refused == []


@pytest.mark.parametrize(("seed", "scenario"), CASES, ids=CASE_IDS)
def test_no_planted_credential_reaches_any_in_process_output(corpora, in_process, seed, scenario):
    assert_no_secret(in_process(seed, scenario).texts(), corpora.secrets)


@pytest.mark.parametrize(("seed", "scenario"), CASES, ids=CASE_IDS)
def test_nothing_outside_the_root_reaches_any_in_process_output(
    corpora, in_process, seed, scenario
):
    record = in_process(seed, scenario)
    found = [
        (label, token)
        for token in corpora.outside_tokens
        for label, text in record.texts().items()
        if token in text
    ]
    assert not found, found
    assert record.outside_opens == []


@pytest.mark.parametrize(("seed", "scenario"), CASES, ids=CASE_IDS)
def test_no_raw_terminal_control_in_any_in_process_output(in_process, seed, scenario):
    assert_no_control(in_process(seed, scenario).texts())


@pytest.mark.parametrize(("seed", "scenario"), CASES, ids=CASE_IDS)
def test_benign_neighbours_of_hostile_inputs_are_still_inventoried(
    corpora, in_process, seed, scenario
):
    expected = corpora.seeds[seed].sentinels.get(scenario, [])
    inventory = in_process(seed, scenario).outputs["json"]
    assert [token for token in expected if token not in inventory] == []


@pytest.mark.parametrize(("seed", "scenario"), CASES, ids=CASE_IDS)
def test_collection_failures_are_the_pinned_ones(corpora, in_process, seed, scenario):
    failures = json.loads(in_process(seed, scenario).outputs["json"])["metadata"]["completeness"][
        "scan_failures"
    ]
    missing, unexpected = unpinned(failures, corpora.seeds[seed].failures.get(scenario, ()))
    assert missing == []
    assert unexpected == []


@pytest.mark.no_cover
@pytest.mark.parametrize(("seed", "scenario"), CASES, ids=CASE_IDS)
def test_isolated_scan_is_bounded_and_executes_connects_or_leaks_nothing(
    corpora, isolated, seed, scenario
):
    scan = isolated(seed, scenario)
    detail = scan.stderr[-2000:]
    assert scan.run.returncode == 0, detail
    assert scan.output, detail
    assert scan.audit == []
    assert corpora.canaries() == []
    assert isolated.outside_opens == []
    assert scan.run.peak_rss_kib < 1024 * 1024, scan.run
    assert scan.run.cpu_seconds < 120, scan.run
    texts = {"output": scan.output, "stdout": scan.stdout, "stderr": scan.stderr}
    assert INTERNAL_ERROR not in scan.stderr
    assert_no_secret(texts, corpora.secrets)
    assert_no_control(texts)
    assert [t for t in corpora.outside_tokens for text in texts.values() if t in text] == []


def _write_bomb(path: Path, size: int) -> None:
    """A PyTorch-style archive whose pickle entry inflates to ``size`` zero bytes."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        info = zipfile.ZipInfo("archive/data.pkl", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        with archive.open(info, "w", force_zip64=True) as entry:
            entry.write(b"\x80\x03B" + struct.pack("<I", size))
            chunk = b"\0" * (1 << 22)
            for _ in range(size // len(chunk)):
                entry.write(chunk)
            entry.write(b".")
        archive.writestr(
            zipfile.ZipInfo("archive/version", date_time=(1980, 1, 1, 0, 0, 0)), b"3\n"
        )


@pytest.mark.no_cover
def test_memory_and_time_do_not_grow_with_the_inflated_size_of_a_bomb(corpora, tmp_path):
    runs: dict[int, list[CappedRun]] = {}
    for mib in (64, 256):
        project = tmp_path / f"bomb-{mib}"
        (project / "models" / "bomb").mkdir(parents=True)
        _write_bomb(project / "models" / "bomb" / "model.pt", mib << 20)
        runs[mib] = []
        for attempt in range(3):
            scan = _isolated_scan(corpora, project, tmp_path / f"run-{mib}-{attempt}")
            assert scan.run.returncode == 0, scan.stderr[-2000:]
            assert scan.audit == []
            runs[mib].append(scan.run)
    peak = {mib: min(run.peak_rss_kib for run in done) for mib, done in runs.items()}
    cpu = {mib: min(run.cpu_seconds for run in done) for mib, done in runs.items()}
    assert peak[256] < peak[64] + 32 * 1024, runs
    assert cpu[256] < 2.5 * cpu[64], runs


def _copy(source: str, destination: str) -> object:
    if stat.S_ISFIFO(os.lstat(source).st_mode):
        os.mkfifo(destination)
        return destination
    return shutil.copy2(source, destination)


def _checkout(source: Path, destination: Path) -> Path:
    shutil.copytree(source, destination, symlinks=True, copy_function=_copy)
    return destination


def _interpreter_scan(checkout: Path, directory: Path, output_format: str) -> bytes:
    """Scan ``checkout`` from inside it in an isolated interpreter, which has a hash seed
    of its own."""
    home = directory / "home"
    home.mkdir(parents=True)
    target = directory / f"scan.{output_format}"
    run = capped_cli(
        "scan",
        ".",
        "--no-project-policy",
        "--report-only",
        "-f",
        output_format,
        "-o",
        str(target),
        cwd=checkout,
        env={**os.environ, "HOME": str(home), "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH},
        stderr=directory / "stderr",
    )
    assert run.returncode == 0, (directory / "stderr").read_bytes()[-2000:]
    return target.read_bytes()


@pytest.mark.no_cover
@pytest.mark.parametrize("scenario", REPRODUCIBLE)
def test_two_checkouts_scan_to_identical_bytes_in_every_format(
    corpora, tmp_path, monkeypatch, scenario
):
    source = corpora.seeds[PUBLIC_SEED].scenario(scenario)
    checkouts = [
        _checkout(source, tmp_path / "laptop" / scenario),
        _checkout(source, tmp_path / "ci" / "runner" / "work" / scenario),
    ]
    with ThreadPoolExecutor(max_workers=len(FORMATS)) as pool:
        separate = {
            output_format: pool.submit(
                _interpreter_scan,
                checkouts[1],
                tmp_path / "isolated" / output_format,
                output_format,
            )
            for output_format in FORMATS
        }
        interpreted = {output_format: future.result() for output_format, future in separate.items()}
    runner = CliRunner()
    for output_format in FORMATS:
        outputs = []
        for index, checkout in enumerate(checkouts):
            target = tmp_path / f"{index}.{output_format}"
            # From inside the checkout, as CI and the pre-commit hooks scan.
            monkeypatch.chdir(checkout)
            result = runner.invoke(
                main,
                ["scan", ".", "--no-project-policy", "--report-only"]
                + ["-f", output_format, "-o", str(target)],
                env={"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH},
            )
            assert_no_crash(result)
            assert result.exit_code == 0, result.output
            outputs.append(target.read_bytes())
        assert outputs[0] == outputs[1], output_format
        assert interpreted[output_format] == outputs[0], output_format
        assert os.fsencode(tmp_path) not in outputs[0], output_format
        assert os.fsencode(os.path.realpath(tmp_path)) not in outputs[0], output_format
    assert corpora.canaries() == []


@pytest.mark.parametrize("scenario", ["s09c-symlink-escape", NEW_SURFACES])
def test_excluded_hostile_paths_are_neither_read_nor_failed(corpora, tmp_path, scenario):
    seeded = corpora.seeds[PUBLIC_SEED]
    # Beside scenarios/, so the relative links still resolve into outside/.
    project = _checkout(seeded.scenario(scenario), seeded.root / "excluded" / scenario)
    try:
        excluded = sorted({failure.split(":", 1)[0] for failure in seeded.failures[scenario]})
        (project / ".nexus-symbiote.yaml").write_text(
            "scan:\n  exclude_paths: " + json.dumps(excluded) + "\n"
        )
        target = tmp_path / "scan.json"
        with offline_refusals() as refused:
            result = CliRunner().invoke(
                main,
                ["scan", str(project), "--accept-project-policy", "--report-only"]
                + ["-o", str(target)],
            )
        assert_no_crash(result)
        assert result.exit_code == 0, result.output
        completeness = json.loads(target.read_bytes())["metadata"]["completeness"]
        assert completeness["scan_failures"] == []
        assert (
            sorted(entry.split(":", 1)[0] for entry in completeness["surfaces_excluded"])
            == excluded
        )
        assert refused == []
        assert corpora.watch.opened() == []
        assert corpora.canaries() == []
    finally:
        shutil.rmtree(seeded.root / "excluded")


@pytest.mark.parametrize(("seed", "scenario"), CASES, ids=CASE_IDS)
def test_every_collector_called_directly_raises_nothing(corpora, seed, scenario):
    project = corpora.seeds[seed].scenario(scenario)
    with offline_refusals() as refused, modes.enforce(modes.Mode.OFFLINE):
        for scanner in ALL_SCANNERS:
            scanner().scan(project)
    assert refused == []
    assert corpora.canaries() == []
    assert corpora.watch.opened() == []
