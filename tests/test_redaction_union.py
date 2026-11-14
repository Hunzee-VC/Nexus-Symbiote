"""Rules and known values are matched in the original text and redacted as one union."""

from __future__ import annotations

import json
import random
import string

import pytest
from hypothesis import given
from hypothesis import strategies as st

from nexus_symbiote.cli import main
from nexus_symbiote.scanners import mcp
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.utils.secrets import (
    REDACTED,
    SecretScrubber,
    redact_keyed_text,
    redact_text,
)
from tests.support import scaling_ratio

PASSWORD = "Tr0ub4dor3xyz"  # noqa: S105 - synthetic fixture
GITHUB = "ghp_" + "A1b2C3d4E5" * 4


def _descriptions(tmp_path, servers):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert not result.scan_failures
    return [c.description_text for c in result.components if c.component_type.value == "tool"]


def _env(*assignments):
    return {"command": "env", "args": [*assignments, "node", "a.js"]}


def _tool(description, **extra):
    return {"command": "node", **extra, "tools": [{"name": "t", "description": description}]}


CASES = {
    # A known value erased the name the assignment rule reads.
    "inline-name": (
        {"auth": _env("AUTH_METHOD=password"), "db": _tool(f"Logs in with password={PASSWORD}")},
        "Logs in with ***=***",
        [PASSWORD],
    ),
    "env-name": (
        {
            "auth": {"command": "node", "env": {"AUTH_METHOD": "password"}},
            "db": _tool(f"Logs in with password={PASSWORD}"),
        },
        "Logs in with ***=***",
        [PASSWORD],
    ),
    # A known value erased the scheme the URL rule reads.
    "url-prefix": (
        {
            "a": _env("AUTH_URL=https://auth.example.com/authorize?client_id=abc12345"),
            "b": _tool(
                "Open https://auth.example.com/authorize?client_id=abc12345&code=AUTHCODE987654zz"
            ),
        },
        "Open ***",
        ["AUTHCODE987654zz", "abc12345", "auth.example.com"],
    ),
    # Two known values overlap; the longer one hid the start of the shorter one.
    "overlapping-values": (
        {
            "a": _env("API_TOKEN=longprefixvalue-S"),
            "b": _tool("x longprefixvalue-SECRETAAAAzq81bb y", **_env("API_KEY=SECRETAAAAzq81bb")),
        },
        "x *** y",
        ["ECRETAAAAzq81bb", "longprefixvalue"],
    ),
    # A known prefix of a token hid the prefix the token rule reads.
    "token-prefix": (
        {"a": _env(f"API_TOKEN={GITHUB[:10]}"), "b": _tool(f"use {GITHUB} now")},
        "use *** now",
        [GITHUB[10:], GITHUB[:10]],
    ),
    # A known header name hid the header the scheme rule looks back for.
    "header-name": (
        {
            "a": _env("AUTH_HEADER=Authorization"),
            "b": _tool("Send Authorization: Bearer abcdefghijk"),
        },
        "Send ***: Bearer ***",
        ["abcdefghijk", "Authorization"],
    ),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_known_values_never_erase_the_context_a_rule_reads(tmp_path, case):
    servers, expected, hidden = CASES[case]
    (description,) = _descriptions(tmp_path, servers)
    assert description == expected
    for value in hidden:
        assert value not in description


@pytest.mark.parametrize(
    ("text", "values", "expected"),
    [
        ("password=hunter2isbad", (), "password=***"),
        ("see https://host.example/cb?code=abc", (), "see https://host.example"),
        (
            "see https://host.example/cb?code=SECRETVALUE1",
            ("SECRETVALUE1",),
            "see https://host.example",
        ),
        ("see https://SECRETHOST1.example/cb", ("SECRETHOST1",), "see ***"),
        ("Authorization: Bearer abcdefghijk", (), "Authorization: Bearer ***"),
        ("Bearer authentication is used", (), "Bearer authentication is used"),
        ("Cookie: sid=abcdefgh12; Path=/", (), "Cookie: sid=***; Path=/"),
        ("a KNOWNVALUE1KNOWNVALUE2 b", ("KNOWNVALUE1", "KNOWNVALUE2"), "a *** b"),
        ("token: Bearer abcdefg1", (), "token: *** ***"),
    ],
)
def test_ordinary_redaction_keeps_its_output_format(text, values, expected):
    assert redact_text(text, values) == expected


def test_cookie_pairs_are_read_before_a_known_cookie_name_is_redacted():
    shown = redact_keyed_text("Cookie", "sessionid=abcdefgh12; theme=dark", ["sessionid"])
    assert shown == "***=***; theme=dark"
    assert redact_keyed_text("Cookie", "sid=abcdefgh12; Path=/") == "sid=***; Path=/"


def test_identifier_names_keep_their_narrower_rules():
    scrubber = SecretScrubber(["KnownValue01"])
    assert redact_text("sk-learn-classifier", scrubber, identifier=True) == "sk-learn-classifier"
    assert redact_text("read-KnownValue01", scrubber, identifier=True) == "read-***"
    assert redact_text(f"x-{GITHUB}", SecretScrubber([f"x-{GITHUB[:6]}"]), identifier=True) == (
        REDACTED
    )


def test_known_prefix_of_a_token_in_a_server_name_is_not_left_partly(tmp_path):
    servers = {"a": _env(f"API_TOKEN=agent-{GITHUB[:6]}"), f"agent-{GITHUB}": {"command": "node"}}
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    result = MCPScanner().scan(tmp_path, config_only=True)
    names = {c.name for c in result.components if c.component_type.value == "mcp-server"}
    assert names == {"a", REDACTED}


def _reference(text, values):
    """Brute force: every occurrence of every value, touching runs replaced once."""
    covered = [False] * len(text)
    for index in range(len(text)):
        for value in values:
            if value and text.startswith(value, index):
                covered[index : index + len(value)] = [True] * len(value)
    shown, index = [], 0
    while index < len(text):
        if covered[index]:
            while index < len(text) and covered[index]:
                index += 1
            shown.append(REDACTED)
        else:
            shown.append(text[index])
            index += 1
    return "".join(shown)


_PLAIN = st.text(alphabet="ab. ", max_size=80)
_VALUES = st.lists(st.text(alphabet="ab", min_size=1, max_size=9), max_size=6)


@given(text=_PLAIN, values=_VALUES, split=st.integers(min_value=0, max_value=6))
def test_known_value_exposure_matches_a_reference_model(text, values, split):
    expected = _reference(text, values)
    assert redact_text(text, values) == expected
    extended = SecretScrubber(values[:split]).extended(values[split:])
    assert redact_text(text, extended) == expected
    assert extended.scrub(text) == expected


@given(
    values=st.lists(st.text(alphabet="ab", min_size=1, max_size=14), min_size=1, max_size=4),
    layout=st.lists(
        st.tuples(st.integers(min_value=0, max_value=3), st.integers(min_value=1, max_value=40)),
        max_size=6,
    ),
    filler=st.text(alphabet="ab. ", max_size=3),
)
def test_long_runs_of_overlapping_values_match_the_reference_model(values, layout, filler):
    # Repeated values build the long periodic runs that short random texts rarely reach.
    text = filler.join(values[index % len(values)] * count for index, count in layout)
    assert redact_text(text, values) == _reference(text, values)


@pytest.mark.parametrize(
    ("value", "text"),
    [
        # Shifts 3 and 4: the second is not a multiple of the smallest period.
        ("aabaa", "aabaaabaa"),
        ("aabaa", "aabaabaa"),
        ("abcab", "abcabcab"),
        ("abcab", "abcababcab"),
        ("aaaa", "aaaaaaa"),
        ("abab", "ababab"),
    ],
)
def test_every_overlapping_occurrence_of_a_value_is_covered(value, text):
    assert SecretScrubber([value]).scrub(text) == _reference(text, [value]) == REDACTED


_PIECES = st.sampled_from(
    [
        "password=",
        "Authorization: ",
        "Bearer ",
        "https://h.example/p?q=",
        " ",
        "token: ",
        "Cookie: sid=",
        "ghp_",
        "&",
    ]
)


@given(
    values=st.lists(st.text(alphabet="abAB01", min_size=3, max_size=12), min_size=1, max_size=5),
    layout=st.lists(st.one_of(_PIECES, st.integers(min_value=0, max_value=4)), max_size=24),
)
def test_no_known_value_survives_next_to_rule_contexts(values, layout):
    text = "".join(
        piece if isinstance(piece, str) else values[piece % len(values)] for piece in layout
    )
    shown = redact_text(text, values)
    for value in values:
        assert value not in shown


def test_overlapping_values_scrub_in_time_linear_in_text_length():
    # "aabaa" overlaps itself at shifts 3 and 4; the others at every shift of their period.
    values = ["a" * width for width in range(8, 40)] + ["aabaa", "ab" * 6, "aab" * 3 + "aa"]
    scrubber = SecretScrubber(values)
    block = "aabaa" * 400 + "aab" * 700 + "aa" + "a" * 2000 + "ab" * 1000
    texts = {scale: block * scale for scale in (1, 4)}

    def run(scale):
        assert redact_text(texts[scale], scrubber) == REDACTED

    assert scaling_ratio(run) < 10


def test_overlapping_values_scrub_in_time_linear_in_the_number_of_values():
    text = "a" * 4000 + " password=x " + "ab" * 2000
    scrubbers = {
        scale: SecretScrubber(
            ["a" * width for width in range(8, 8 + 64 * scale)]
            + [("ab" * 64)[:width] for width in range(8, 8 + 64 * scale)]
        )
        for scale in (1, 4)
    }

    def run(scale):
        assert redact_text(text, scrubbers[scale]) == "*** password=*** ***"

    assert scaling_ratio(run) < 10


F2_SERVERS = {
    "auth": {"command": "env", "args": ["AUTH_METHOD=password", "node"]},
    f"login password={PASSWORD}": {
        "command": "node",
        "tools": [{"name": "read", "inputSchema": []}],
    },
}


def test_failure_names_use_the_same_union_redaction(tmp_path):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": F2_SERVERS}))
    result = MCPScanner().scan(tmp_path, config_only=True)
    (failure,) = result.scan_failures
    assert PASSWORD not in failure
    assert "server 'login ***=***'" in failure


@pytest.mark.parametrize("output_format", ["json", "cyclonedx", "spdx", "sarif"])
def test_failure_names_reach_no_report_only_export_or_risk_report(tmp_path, runner, output_format):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": F2_SERVERS}))
    output = tmp_path / "inventory.json"
    scanned = runner.invoke(
        main,
        [
            "scan",
            str(project),
            "--no-project-policy",
            "--report-only",
            "-f",
            output_format,
            "-o",
            str(output),
        ],
    )
    assert scanned.exit_code == 0, scanned.output
    assert "invalid tool definition" in scanned.output
    assert PASSWORD not in scanned.output + output.read_text()
    if output_format == "json":
        risk = runner.invoke(main, ["risk", str(output), "--no-project-policy", "--json"])
        assert PASSWORD not in risk.output


def test_refused_servers_do_not_count_toward_the_file_secret_limit(tmp_path):
    servers = {
        f"refused{index}": {
            "command": "env",
            "args": [f"T{field}_TOKEN=RefusedValue{index}x{field:04d}" for field in range(1001)]
            + ["node"],
        }
        for index in range(5)
    }
    servers["kept"] = {"command": "node"}
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert (
        result.scan_failures
        == [f".mcp.json: MCP server list limit ({mcp.MAX_LIST_ENTRIES} entries) exceeded"] * 5
    )
    assert [c.name for c in result.components if c.component_type.value == "mcp-server"] == ["kept"]


def test_counted_values_are_those_of_admitted_servers():
    admitted = {"command": "env", "args": ["API_TOKEN=AdmittedValue001", "node"]}
    refused = {"command": "env", "args": ["API_TOKEN=RefusedValue0001", *["x"] * 1000]}
    assert MCPScanner._file_secrets([("a", admitted), ("r", refused)]) == ["AdmittedValue001"]


@pytest.mark.parametrize("field", ["env", "headers", "http_headers", "inline"])
def test_diagnostic_without_file_context_collects_every_declared_value(field):
    secret = "KnownDiagnosticValue42"  # noqa: S105 - synthetic fixture
    config = {"command": "node"}
    if field == "inline":
        config.update(command="env", args=[f"API_TOKEN={secret}", "node"])
    else:
        config[field] = {"API_TOKEN" if field == "env" else "Authorization": secret}
    assert MCPScanner._diagnostic_server_name(f"agent-{secret}", config) == "agent-***"


# A known value ending in a letter or digit, right before or after a credential.
KNOWN = "abcdefgh1"
EDGE_DESCRIPTION = (
    f"Use {KNOWN}{GITHUB} ; {KNOWN}Cookie: sid=sessval12345 ; "
    f"{KNOWN}Authorization: Negotiate yyyyyyyy9"
)
EDGE_HOLDERS = {
    "env": {"command": "node", "env": {"API_KEY": KNOWN}},
    "inline": _env(f"API_KEY={KNOWN}"),
}


@pytest.mark.parametrize("holder", sorted(EDGE_HOLDERS))
def test_a_known_value_edge_separates_a_credential_as_its_redaction_did(tmp_path, holder):
    servers = {"a": EDGE_HOLDERS[holder], "b": _tool(EDGE_DESCRIPTION)}
    (description,) = _descriptions(tmp_path, servers)
    assert description == "Use *** ; ***Cookie: sid=*** ; ***Authorization: Negotiate ***"
    for secret in (GITHUB[4:], "sessval12345", "yyyyyyyy9"):
        assert secret not in description


AKIA = "AKIA" + "ABCDEFGHIJKLMNOP"
TWILIO = "SK" + "0123456789abcdef" * 2
JWT = "eyJhbGciOiJI.eyJpc3MiOiJh.c2ln"


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (KNOWN + GITHUB, GITHUB[4:]),
        (KNOWN + AKIA + " x", AKIA[4:]),
        (AKIA + KNOWN, AKIA[4:]),
        (TWILIO + KNOWN, TWILIO[2:]),
        (KNOWN + "sk-" + "Q" * 24, "Q" * 24),
        (KNOWN + JWT, "eyJpc3MiOiJh"),
        (KNOWN + "Bearer Mx9yW8kU12", "Mx9yW8kU12"),
        (KNOWN + "Authorization: Mx9yW8kU12", "Mx9yW8kU12"),
        (KNOWN + "Cookie: sid=Mx9yW8kU12", "Mx9yW8kU12"),
    ],
)
def test_rules_with_a_boundary_match_next_to_a_known_value(text, secret):
    shown = redact_text(text, [KNOWN])
    assert secret not in shown
    assert KNOWN not in shown


def test_a_known_value_holding_a_separator_does_not_end_a_value_early():
    # Redacted first, such a value no longer ended the assignment or the URL there.
    values = ["ab cd efgh"]
    assert redact_text("password=ab cd efghSECRETZ", values) == "password=***"
    assert redact_text("see https://h.example/ab cd efghSECRETZ/x", values) == (
        "see https://h.example"
    )


def test_identifier_rules_also_match_next_to_a_known_value():
    assert redact_text(f"{KNOWN}{GITHUB}", [KNOWN], identifier=True) == REDACTED
    assert redact_text(f"{KNOWN}sk-learn-classifier", [KNOWN], identifier=True) == (
        "***sk-learn-classifier"
    )


_CREDENTIALS = {
    GITHUB: GITHUB[4:],
    AKIA: AKIA[4:],
    TWILIO: TWILIO[2:],
    "sk-" + "Q" * 24: "Q" * 24,
    JWT: "eyJpc3MiOiJh",
    "Bearer Mx9yW8kU12": "Mx9yW8kU12",
    "Authorization: Negotiate Mx9yW8kU12": "Mx9yW8kU12",
    "Authorization: Mx9yW8kU12": "Mx9yW8kU12",
    "Cookie: sid=Mx9yW8kU12": "Mx9yW8kU12",
    "password=Mx9yW8kU12": "Mx9yW8kU12",
}
# A separator, or a known value: both end the word a rule reads.
_EDGES = st.one_of(st.sampled_from(["", " ", "; ", "="]), st.integers(0, 3))


@given(
    values=st.lists(st.text(alphabet="vVzZ", min_size=3, max_size=10), min_size=1, max_size=4),
    layout=st.lists(
        st.tuples(_EDGES, st.sampled_from(sorted(_CREDENTIALS)), _EDGES), min_size=1, max_size=5
    ),
    identifier=st.booleans(),
)
def test_no_credential_survives_next_to_known_values(values, layout, identifier):
    def edge(piece):
        return piece if isinstance(piece, str) else values[piece % len(values)]

    text = " ".join(edge(left) + credential + edge(right) for left, credential, right in layout)
    shown = redact_text(text, values, identifier=identifier)
    for value in values:
        assert value not in shown
    for _left, credential, _right in layout:
        if not identifier or credential in (GITHUB, AKIA, TWILIO, JWT):
            assert _CREDENTIALS[credential] not in shown


def _periodic_values(period):
    rng = random.Random(7)  # noqa: S311 - a reproducible corpus, not a secret
    base = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(period))
    return base, sorted({(base * 2)[i : i + w] for w in range(8, period) for i in range(period)})


def test_values_that_cover_a_repeated_text_cost_about_what_a_plain_text_costs():
    # Every substring of a 64-character period occurs at every repetition. Each one
    # used to add a span per occurrence: 3,584 values made millions of them.
    base, values = _periodic_values(64)
    scrubber = SecretScrubber(values)
    size = 16384
    rng = random.Random(3)  # noqa: S311 - a reproducible corpus, not a secret
    texts = {
        1: "".join(rng.choice(string.ascii_letters) for _ in range(size)),
        4: (base * (size // len(base) + 1))[:size],
    }

    def run(scale):
        redact_text(texts[scale], scrubber)

    # Scale 4 is the covered repeated text, scale 1 a plain text of the same length.
    assert scaling_ratio(run) < 6
    assert redact_text(texts[4], scrubber) == REDACTED


def test_values_passing_over_repeated_covered_runs_fall_back_to_a_widened_cover():
    # Each part of the longest value occurs inside every repetition of it, between
    # uncovered gaps: without the fallback every part would pass over each one.
    base, values = _periodic_values(64)
    part = base[:63]
    values = sorted({part[i : i + w] for w in range(8, 64) for i in range(64 - w)})
    scrubber = SecretScrubber(values)
    repeated = (part + "#") * 1024
    rng = random.Random(3)  # noqa: S311 - a reproducible corpus, not a secret
    texts = {1: "".join(rng.choice(string.ascii_letters) for _ in repeated), 4: repeated}

    def run(scale):
        redact_text(texts[scale], scrubber)

    # Scale 4 is the repeated text, scale 1 a plain text of the same length.
    assert scaling_ratio(run) < 6
    assert redact_text(repeated, scrubber) == REDACTED


@given(
    text=_PLAIN,
    values=st.lists(st.text(alphabet="ab", min_size=1, max_size=9), min_size=1, max_size=6),
)
def test_the_widened_cover_holds_every_occurrence(text, values):
    covered = SecretScrubber(values)._widened_greedy(text)
    for start in range(len(text)):
        for value in values:
            if text.startswith(value, start):
                assert all(covered[start : start + len(value)])
