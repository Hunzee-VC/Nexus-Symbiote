"""Labelled differential corpus for the two credential-finding implementations.

    python corpus.py build <directory>     write one project per case and manifest.json
    python corpus.py list                  print id, origin, label, shape, position per case

Each case is one project directory holding one MCP client file with ONE planted value in
one position, a label (credential or benign) and a shape tag. Origins:

    t255    parametrized tables of tests/test_mcp_credential_exposure.py (PR 255)
    t259    parametrized tables of tests/test_literal_credential_findings.py (PR 259)
    r259    positive and benign lists the PR 259 reviewers wrote (break/tools/fn.py, fp.py,
            fp2.py, regress/probe/cases1.py, cases3.py, cases4.py, cases5.py,
            verify-break-1/tools/battery.py)
    matrix  values of both test files placed in every position that suits them
    own     cases neither author is likely to have thought of

Every credential-shaped value is put together from parts when this file runs; nothing in
it is a literal in a token format. Random values come from a seeded generator, so two
builds are byte-identical, and are redrawn until they hold none of the placeholder marks
PR 259 sets a value aside for (123456, abcdef, your, example, ...), so that a chance miss
does not blur the comparison; one deliberate case covers such a mark.
"""

from __future__ import annotations

import base64
import json
import random
import shlex
import string
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
UPNUM = string.ascii_uppercase + string.digits
B64 = ALNUM + "+/"
_MARKS = (
    "123456", "abcdef", "your", "example", "sample", "placeholder", "changeme", "change_me",
    "change-me", "replace", "insert", "dummy", "redacted", "xxxx",
)  # fmt: skip


def rnd(n: int, alphabet: str = ALNUM, seed: str = "") -> str:
    rng = random.Random(f"coord-cred:{seed}:{n}:{alphabet}")
    while True:
        text = "".join(rng.choice(alphabet) for _ in range(n))
        low = text.lower()
        if any(mark in low for mark in _MARKS):
            continue
        if n >= 8 and alphabet in (ALNUM, B64) and not (
            any(c.isdigit() for c in text)
            and any(c.islower() for c in text)
            and any(c.isupper() for c in text)
        ):
            continue
        if n >= 8 and alphabet in (HEX, UPNUM) and not (
            any(c.isdigit() for c in text) and any(c.isalpha() for c in text)
        ):
            continue
        return text


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def b64url(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


# --- values, all assembled at run time ----------------------------------------------
GH = "gh" + "p_" + rnd(36, seed="gh")
GH2 = "gh" + "p_" + rnd(36, seed="gh2")
GH_FG = "github" + "_pat_" + rnd(22, seed="fg1") + "_" + rnd(59, seed="fg2")
AWS_ID = "AK" + "IA" + rnd(16, UPNUM, "aws")
ANT = "sk" + "-ant-" + "api03-" + rnd(93, seed="ant") + "AA"
OAI = "sk" + "-proj-" + rnd(48, seed="oai")
OAI_OLD = "sk" + "-" + rnd(48, seed="oai-old")
GITLAB = "gl" + "pat-" + rnd(20, seed="gl")
SLACK = "xo" + "xb-" + rnd(12, string.digits, "s1") + "-" + rnd(13, string.digits, "s2") + "-" + rnd(24, seed="s3")
GOOG = "AI" + "za" + rnd(35, seed="goog")
STRIPE = "sk" + "_live_" + rnd(24, seed="stripe")
STRIPE_RK = "rk" + "_live_" + rnd(24, seed="stripe-rk")
HF = "hf" + "_" + rnd(34, seed="hf")
NPM = "np" + "m_" + rnd(36, seed="npm")
SENDGRID = "S" + "G." + rnd(22, seed="sg1") + "." + rnd(43, seed="sg2")
JWT = ".".join((
    b64url('{"alg":"HS256","typ":"JWT"}'),
    b64url('{"sub":"svc-reader","iat":1716239022}'),
    rnd(43, seed="jwt-sig"),
))  # fmt: skip
JWT_SAMPLE = ".".join((
    b64url('{"alg":"HS256","typ":"JWT"}'),
    b64url('{"sub":"1234567890","name":"John Doe","iat":1516239022}'),
    "SflKxwRJSMeKKF2QT4" + "fwpMeJf36POk6yJV_adQssw5c",
))  # fmt: skip
HEX32 = rnd(32, HEX, "hex32")
HEX32B = rnd(32, HEX, "hex32b")
HEX64 = rnd(64, HEX, "hex64")
B62_40 = rnd(40, seed="b62-40")
B62_32 = rnd(32, seed="b62-32")
B62_20 = rnd(20, seed="b62-20")
B62_16 = rnd(16, seed="b62-16")
UUID_TOKEN = "-".join((rnd(8, HEX, "u1"), rnd(4, HEX, "u2"), "4" + rnd(3, HEX, "u3"), "9" + rnd(3, HEX, "u4"), rnd(12, HEX, "u5")))
UUID_ID = "3f2b8c1e-7a4d-4e9b-9c6f-1d2e3f4a5b6c"
WORDY = "hunter2" + "hunter"
PW_PUNCT = "kT9#vQ2" + "!mZ7@wL4&"
PW_DOLLAR = "Pq7$xK2w9" + "!Lm4vZt"
PW_SHORT = "s3cr3t" + "Pw9!"
PW_SUPER = "Sup3r" + "Secret99"
SENTINEL_11 = "SYMBIOTE_PUBLIC_SYNTHETIC_" + "SECRET_SENTINEL_11"
SENTINEL_12 = "SYMBIOTE_PUBLIC_SYNTHETIC_" + "SECRET_SENTINEL_12"
PASSWORD_255 = "synthetic-launch-" + "password-98765"
VENDOR_255 = "gh" + "p_" + "A1" * 18
KEY_255 = "gh" + "p_" + "B2" * 18
HF_255 = "hf" + "_" + "C3" * 15
# The constants tests/test_literal_credential_findings.py builds, by the same recipe.
BODY = "Ab3dEf6hIj9k" * 3
T_GITHUB = "gh" + "p_" + BODY
T_FINE = "github" + "_pat_" + BODY
T_AWS = "AK" + "IA" + "Q7RTZ2MWX4PLD9VN"
T_ANT = "sk" + "-ant-" + "api03-" + BODY * 2
T_OAI = "sk" + "-proj-" + BODY
T_GITLAB = "gl" + "pat-" + BODY[:24]
T_JWT = ".".join(("ey" + "J" + BODY[:20], "ey" + "J" + BODY[:24], BODY[:22]))
T_RANDOM = "9f8e7d6c5b4a" + "3f2e1d0c9b8a" + "7f6e5d4c"
T_MIXED = "Zq8vLm2p" + "Xr7tKw4n"
T_BASIC = b64(f"service:{WORDY}")
PEM_BEGIN, PEM_END = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"
T_PEM = "\n".join((PEM_BEGIN, "MIIEvQIBADANBgkqhkiG9w0BAQEF" + "AASCBKcwggSjAgEAAoIBAQC7", PEM_END))
PEM = "\n".join((PEM_BEGIN, rnd(64, B64, "pem1"), rnd(64, B64, "pem2"), rnd(64, B64, "pem3"), PEM_END))
PEM_RSA = "\n".join(("-----BEGIN RSA " + "PRIVATE KEY-----", rnd(64, B64, "rsa1"), rnd(64, B64, "rsa2"), "-----END RSA " + "PRIVATE KEY-----"))
PEM_SSH = "\n".join(("-----BEGIN OPENSSH " + "PRIVATE KEY-----", rnd(70, B64, "ssh1"), "-----END OPENSSH " + "PRIVATE KEY-----"))
PEM_PGP = "\n".join(("-----BEGIN PGP " + "PRIVATE KEY BLOCK-----", "", rnd(64, B64, "pgp1"), rnd(64, B64, "pgp2"), "-----END PGP " + "PRIVATE KEY BLOCK-----"))
CERT = "\n".join((
    "-----BEGIN CERTIFICATE-----",
    "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ",
    "RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD",
    "-----END CERTIFICATE-----",
))  # fmt: skip
PUBKEY = "\n".join((
    "-----BEGIN PUBLIC KEY-----",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo",
    "4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u",
    "-----END PUBLIC KEY-----",
))  # fmt: skip
SSHPUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ci@build"
AWS_DOC_ID = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"
AWS_DOC_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCY" + "EXAMPLEKEY"

URL = "https://mcp.example.test/mcp"
PIN = ["-y", "some-mcp@1.0.0"]
DIGEST = "mcp/x@sha256:" + "a" * 64
IMG = "img@sha256:" + "a" * 64

ALL = (
    "env", "header", "arg_flag_sep", "arg_flag_eq", "arg_kv", "sh_c", "command",
    "url_userinfo_endpoint", "url_userinfo_env", "url_userinfo_arg",
    "url_query_endpoint", "url_query_env", "url_query_arg",
)  # fmt: skip
NO_URL = ("env", "header", "arg_flag_sep", "arg_flag_eq", "arg_kv", "sh_c", "command")
VALUE5 = ("env", "header", "arg_flag_sep", "arg_flag_eq", "arg_kv")
DEFAULT_NAMES = {
    "env": "API_TOKEN", "header": "X-Api-Key", "arg_flag_sep": "--token",
    "arg_flag_eq": "--token", "arg_kv": "API_TOKEN", "sh_c": "API_TOKEN",
    "sh_c_flag": "--token", "command": "--token", "url_query_endpoint": "api_key",
    "url_query_env": "api_key", "url_query_arg": "api_key",
}  # fmt: skip


def E(name: str, value: str) -> dict[str, Any]:
    return {"command": "npx", "args": list(PIN), "env": {name: value}}


def H(name: str, value: str) -> dict[str, Any]:
    return {"type": "http", "url": URL, "headers": {name: value}}


def A(*args: str) -> dict[str, Any]:
    return {"command": "npx", "args": [*PIN, *args]}


def U(url: str) -> dict[str, Any]:
    return {"type": "http", "url": url}


def D(*args: str) -> dict[str, Any]:
    return {"command": "docker", "args": ["run", "-i", "--rm", *args, DIGEST]}


def SH(script: str) -> dict[str, Any]:
    return {"command": "sh", "args": ["-c", script]}


def place(position: str, name: str, value: str, raw_url: bool = False) -> dict[str, Any]:
    """The server definition that holds ``value`` at ``position`` under ``name``.

    ``raw_url`` marks a benign value written as a person writes it: unencoded in a URL,
    and in double quotes in a script, where a shell still expands a reference; a
    credential is percent-encoded and single-quoted where it needs to be.
    """
    quoted = shlex.quote(value)
    if raw_url and quoted != value:
        quoted = '"' + value + '"'
    in_url = value if raw_url else quote(value, safe="-._~")
    if position == "env":
        return E(name, value)
    if position == "header":
        return H(name, value)
    if position == "arg_flag_sep":
        return A(name, value)
    if position == "arg_flag_eq":
        return A(f"{name}={value}")
    if position == "arg_kv":
        return D("-e", f"{name}={value}")
    if position == "sh_c":
        return SH(f"{name}={quoted} exec npx -y some-mcp@1.0.0")
    if position == "sh_c_flag":
        return SH(f"exec npx -y some-mcp@1.0.0 {name} {quoted}")
    if position == "command":
        return {"command": f"npx -y some-mcp@1.0.0 {name} {quoted}"}
    if position == "url_userinfo_endpoint":
        return U(f"https://svc:{in_url}@mcp.example.test/mcp")
    if position == "url_userinfo_env":
        return E("DATABASE_URL", f"postgres://app:{in_url}@db.example.test:5432/app")
    if position == "url_userinfo_arg":
        return A(f"postgresql://app:{in_url}@db.example.test:5432/app")
    if position == "url_query_endpoint":
        return U(f"{URL}?{name}={in_url}")
    if position == "url_query_env":
        return E("SERVICE_URL", f"{URL}?{name}={in_url}")
    if position == "url_query_arg":
        return {"command": "npx", "args": ["-y", "mcp-remote@1.0.0", f"{URL}?{name}={in_url}"]}
    raise ValueError(position)


CASES: list[dict[str, Any]] = []
_SEEN: set[str] = set()


def _name_of(position: str, server: dict[str, Any] | None) -> str:
    """The name that holds the planted value in a server written out by hand, for the tables."""
    if not server:
        return ""
    if position in ("env", "url_userinfo_env", "url_query_env"):
        names = list(server.get("env", {}))
        return names[0] if len(names) == 1 else ""
    if position == "header":
        names = [*server.get("headers", {}), *server.get("http_headers", {})]
        return names[0] if len(names) == 1 else ""
    args = [a for a in server.get("args", []) if isinstance(a, str)]
    if position == "arg_flag_sep" and len(args) >= 2 and args[-2].startswith("-"):
        return args[-2]
    if position in ("arg_flag_eq", "arg_kv"):
        for arg in reversed(args):
            if "=" in arg and not arg.startswith(("http", "postgres")):
                return arg.split("=", 1)[0]
    return ""


def add(
    origin: str,
    label: str,
    shape: str,
    position: str,
    value: str,
    *,
    name: str | None = None,
    secret: str | None = None,
    server: dict[str, Any] | None = None,
    file: str = ".mcp.json",
    note: str = "",
    raw_url: bool = False,
    author_label: str | None = None,
    content: str | None = None,
) -> None:
    assert label in ("credential", "benign"), label
    if name is None:
        name = DEFAULT_NAMES.get(position, "") if server is None and content is None else _name_of(position, server)
    if server is None and content is None:
        server = place(position, name, value, raw_url)
    key = json.dumps([file, server, content], sort_keys=True)
    if key in _SEEN:
        return
    _SEEN.add(key)
    CASES.append(
        {
            "id": f"c{len(CASES) + 1:04d}",
            "origin": origin,
            "label": label,
            "shape": shape,
            "position": position,
            "file": file,
            "name": name,
            "value": value,
            "secret": value if secret is None else secret,
            "note": note,
            "author_label": author_label or label,
            "server": server,
            "content": content,
        }
    )


def spread(origin: str, label: str, shape: str, value: str, positions, *, names=None, **kw) -> None:
    for position in positions:
        name = (names or {}).get(position)
        add(origin, label, shape, position, value, name=name, **kw)


# =====================================================================================
# matrix: values of both test files in every position that suits them
# =====================================================================================
for shape, value in (
    ("vendor-token", GH),
    ("vendor-token", AWS_ID),
    ("vendor-token", JWT),
    ("random-under-credential-name", HEX32),
    ("random-under-credential-name", B62_40),
    ("password-wordy", WORDY),
    ("password-wordy", PASSWORD_255),
    ("password-punctuation", PW_PUNCT),
    ("password-short", PW_SHORT),
    ("uuid-as-token", UUID_TOKEN),
    ("sentinel-uppercase-name", SENTINEL_11),
):
    spread("matrix", "credential", shape, value, ALL)

for shape, value, positions in (
    ("ref-client", "${API_TOKEN}", ALL),
    ("ref-client", "$API_TOKEN", ALL),
    ("ref-client", "${env:API_TOKEN}", (*VALUE5, "url_query_endpoint", "url_userinfo_endpoint")),
    ("ref-client", "${input:api_token}", ("env", "header", "arg_flag_sep", "url_query_endpoint")),
    ("ref-windows", "%API_TOKEN%", (*VALUE5, "command")),
    ("ref-windows", "$env:API_TOKEN", VALUE5),
    ("ref-template", "${{ secrets.API_TOKEN }}", VALUE5),
    ("ref-template", "{{ secrets.api_token }}", VALUE5),
    ("ref-secret-store", "op://Private/GitHub/token", VALUE5),
    ("ref-secret-store", "vault:secret/data/app#password", VALUE5),
    ("ref-cmd-subst", "$(cat /run/secrets/api_token)", (*VALUE5, "sh_c", "command")),
    ("placeholder-marked", "<your-api-key>", ALL),
    ("placeholder-marked", "YOUR_API_KEY_HERE", ALL),
    ("placeholder-marked", "x" * 16, ALL),
    ("explanatory-text", "Get this from the Acme dashboard", VALUE5),
    ("default-word", "not-needed", (*NO_URL, "url_userinfo_endpoint", "url_query_endpoint")),
):
    spread("matrix", "benign", shape, value, positions, raw_url=True)
_KEY_NAMES = {"env": "SSH_PRIVATE_KEY", "arg_flag_sep": "--private-key", "arg_flag_eq": "--private-key", "arg_kv": "SSH_PRIVATE_KEY", "sh_c": "SSH_PRIVATE_KEY", "command": "--private-key"}
for shape, value in (("keyfile-path-abs", "/run/secrets/api_token"), ("keyfile-path-rel", "keys/id_ed25519")):
    spread("matrix", "benign", shape, value, ("env", "arg_flag_sep", "arg_flag_eq", "arg_kv", "sh_c", "command"))
    spread("matrix", "benign", shape, value, ("env", "arg_flag_sep", "arg_flag_eq", "arg_kv"), names=_KEY_NAMES)

# =====================================================================================
# t255: tests/test_mcp_credential_exposure.py
# =====================================================================================
_FIX = ["-y", "fixture-mcp@1.2.3"]
add("t255", "credential", "vendor-token", "arg_flag_sep", VENDOR_255, name="--token", server={"command": "npx", "args": [*_FIX, "--token", VENDOR_255]}, note="LITERAL")
add("t255", "credential", "password-wordy", "arg_flag_eq", PASSWORD_255, name="--password", server={"command": "npx", "args": [*_FIX, f"--password={PASSWORD_255}"]}, note="LITERAL")
add("t255", "credential", "sentinel-uppercase-name", "env", SENTINEL_11, name="API_TOKEN", server={"command": "npx", "args": _FIX, "env": {"API_TOKEN": SENTINEL_11}}, note="LITERAL")
add("t255", "credential", "scheme-bearer", "header", f"Bearer {SENTINEL_12}", name="Authorization", secret=SENTINEL_12, server={"url": "https://example.invalid/mcp", "headers": {"Authorization": f"Bearer {SENTINEL_12}"}}, note="LITERAL")
add("t255", "benign", "ref-client", "arg_flag_sep", "${TOKEN}", name="--token", server={"command": "npx", "args": [*_FIX, "--token", "${TOKEN}"]}, note="REFERENCED")
add("t255", "benign", "ref-client", "arg_flag_eq", "$PASSWORD", name="--password", server={"command": "npx", "args": [*_FIX, "--password=$PASSWORD"]}, note="REFERENCED")
add("t255", "benign", "ref-client", "header", "Bearer ${TOKEN}", name="Authorization", server={"url": "https://example.invalid/mcp", "headers": {"Authorization": "Bearer ${TOKEN}"}}, note="REFERENCED")
for value in ("${TOKEN}", "$TOKEN", "{{ secrets.token }}", "Bearer ${TOKEN}", "  Basic $TOKEN ", "Token {{ vault.read('x') }}"):
    add("t255", "benign", "ref-client" if "{{" not in value else "ref-template", "env", value, note="names_reference accepts")
add("t255", "benign", "ref-lowercase-or-empty", "env", "$token", note="names_reference rejects; six characters")
add("t255", "benign", "ref-lowercase-or-empty", "env", "${}", note="names_reference rejects")
add("t255", "benign", "ref-lowercase-or-empty", "env", "{{}}", note="names_reference rejects")
add("t255", "credential", "scheme-bearer", "env", f"Bearer {SENTINEL_12}", secret=SENTINEL_12, note="names_reference rejects")
add("t255", "credential", "password-punctuation", "env", "pa$SWORD" + "12x", note="names_reference rejects")
add("t255", "benign", "partial-reference", "env", "x-${TOKEN}", note="names_reference rejects; a prefix and a reference")
add("t255", "benign", "prose-with-scheme-word", "env", "Bearer", note="names_reference rejects")
# test_each_credential_position_is_named_with_its_pattern_class
add("t255", "credential", "scheme-bearer", "sh_c", f"Bearer {SENTINEL_12}", name="API_TOKEN", secret=SENTINEL_12, server=SH(f'API_TOKEN="Bearer {SENTINEL_12}" exec uvx x==1.0'))
add("t255", "credential", "sentinel-uppercase-name", "arg_kv", SENTINEL_11, name="API_KEY", server={"command": "docker", "args": ["run", "-i", "-e", f"API_KEY={SENTINEL_11}", IMG]})
add("t255", "credential", "url-password", "url_userinfo_env", PW_SUPER, name="DATABASE_URL", server={"command": "npx", "args": ["x@1.0.0"], "env": {"DATABASE_URL": f"postgres://app:{PW_SUPER}@db.invalid/app"}})
add("t255", "credential", "vendor-token", "env", HF_255, name="HF_HOME_TOKEN", server={"command": "npx", "args": ["x@1.0.0"], "env": {"HF_HOME_TOKEN": HF_255}})
add("t255", "credential", "password-wordy", "header", PASSWORD_255, name="X-Api-Key", server={"url": "https://example.invalid/mcp", "headers": {"X-Api-Key": PASSWORD_255}})
add("t255", "credential", "user-colon-password", "env", f"admin:{PASSWORD_255}", name="DB_PASSWORD", secret=PASSWORD_255, server={"command": "npx", "args": ["x@1.0.0"], "env": {"DB_PASSWORD": f"admin:{PASSWORD_255}"}})
add("t255", "credential", "user-colon-password", "env", f"Xyz9:{SENTINEL_11}", name="TOKEN", secret=SENTINEL_11, server={"command": "npx", "args": ["x@1.0.0"], "env": {"TOKEN": f"Xyz9:{SENTINEL_11}"}})
add("t255", "credential", "user-colon-password", "arg_flag_sep", f"user:{PASSWORD_255}", name="--password", secret=PASSWORD_255, server={"command": "npx", "args": ["x@1.0.0", "--password", f"user:{PASSWORD_255}"]})
add("t255", "credential", "sentinel-uppercase-name", "sh_c_flag", SENTINEL_11, name="--token", server=SH(f"server --token {SENTINEL_11} --port 1"))
# test_locators_references_and_short_values_stay_clean
_X = ["x@1.0.0"]
add("t255", "benign", "locator-url", "env", "https://example.invalid/oauth/token", name="TOKEN_URL", server={"command": "npx", "args": _X, "env": {"TOKEN_URL": "https://example.invalid/oauth/token"}})
add("t255", "benign", "ref-in-url", "url_userinfo_env", "${DB_PASSWORD}", name="DATABASE_URL", server={"command": "npx", "args": _X, "env": {"DATABASE_URL": "postgres://app:${DB_PASSWORD}@db.invalid/app"}})
add("t255", "benign", "weak-or-doc-password", "url_userinfo_env", "postgres", name="DATABASE_URL", server={"command": "npx", "args": _X, "env": {"DATABASE_URL": "postgres://postgres:postgres@localhost/app"}})
add("t255", "benign", "short-word", "env", "short", name="API_TOKEN", server={"command": "npx", "args": _X, "env": {"API_TOKEN": "short"}})
add("t255", "benign", "package-requirement", "arg_raw", "mcp-server-tokens==10.20.30", server={"command": "uvx", "args": ["mcp-server-tokens==10.20.30"]})
add("t255", "benign", "ref-client", "arg_header_line", "Authorization: Bearer ${TOKEN}", server={"command": "npx", "args": ["x@1.0.0", "--header", "Authorization: Bearer ${TOKEN}"]})
add("t255", "benign", "ref-client", "env", "$OTHER_TOKEN", name="OTHER", server={"command": "npx", "args": _X, "env": {"OTHER": "$OTHER_TOKEN"}})
add("t255", "benign", "ref-template", "env", "{{ secrets.token }}", name="TPL", server={"command": "npx", "args": _X, "env": {"TPL": "{{ secrets.token }}"}})
add("t255", "benign", "ref-template", "header", "{{ vault.key }}", name="X-Api-Key", server={"url": "https://example.invalid/mcp", "headers": {"X-Api-Key": "{{ vault.key }}"}})
# test_the_finding_fires_exactly_where_the_scrubber_redacts_a_literal
for field, value, literal, shape, secret in (
    ("env", SENTINEL_11, True, "sentinel-uppercase-name", None),
    ("env", f"admin:{PASSWORD_255}", True, "user-colon-password", PASSWORD_255),
    ("env", f"Authorization: Bearer {SENTINEL_12}", True, "scheme-bearer", SENTINEL_12),
    ("env", f"Bearer {SENTINEL_12}", True, "scheme-bearer", SENTINEL_12),
    ("env", f"https://app:{PASSWORD_255}@db.invalid/app", True, "url-password", PASSWORD_255),
    ("env", VENDOR_255, True, "vendor-token", None),
    ("env", "${API_TOKEN}", False, "ref-client", None),
    ("env", "Authorization: Bearer ${TOKEN}", False, "ref-client", None),
    ("env", "postgres://app:${DB_PASSWORD}@db.invalid/app", False, "ref-in-url", None),
    ("env", "https://example.invalid/oauth/token", False, "locator-url", None),
    ("env", "short", False, "short-word", None),
    ("headers", f"Bearer {SENTINEL_12}", True, "scheme-bearer", SENTINEL_12),
    ("headers", PASSWORD_255, True, "password-wordy", None),
    ("headers", "Bearer ${TOKEN}", False, "ref-client", None),
    ("headers", "{{ vault.key }}", False, "ref-template", None),
    ("args", f"--token={SENTINEL_11}", True, "sentinel-uppercase-name", SENTINEL_11),
    ("args", f"run --password {PASSWORD_255}", True, "password-wordy", PASSWORD_255),
    ("args", f"--password=user:{PASSWORD_255}", True, "user-colon-password", PASSWORD_255),
    ("args", "--token=${TOKEN}", False, "ref-client", None),
    ("args", "run --password $PASSWORD", False, "ref-client", None),
    ("args", "--port=8080", False, "noncredential-name", None),
):
    config: dict[str, Any] = {"command": "npx", "args": ["x@1.0.0"]}
    if field == "args":
        config["args"] = ["x@1.0.0", value]
        position = "arg_flag_eq" if value.startswith("--") else "arg_inline_words"
    else:
        config[field] = {"API_TOKEN": value}
        position = "env" if field == "env" else "header"
        if field == "headers":
            config = {"url": "https://example.invalid/mcp", "headers": {"API_TOKEN": value}}
    add("t255", "credential" if literal else "benign", shape, position, value, name="API_TOKEN" if field != "args" else "", secret=secret, server=config, note="fires-exactly table")
add("t255", "credential", "password-wordy", "header", PASSWORD_255, name="X-Api-Key", server={"url": "https://example.invalid/mcp", "headers": {"X-Api-Key": PASSWORD_255}, "http_headers": {"X-Api-Key": "${KEY}"}}, note="header shadowed by http_headers")
_LONG = "Q7" * 5000
add("t255", "credential", "synthetic-repetitive", "env", _LONG, name="API_TOKEN", server={"command": "npx", "args": _X, "env": {"API_TOKEN": _LONG}}, note="oversized value; two distinct characters")
add("t255", "credential", "synthetic-repetitive", "arg_flag_sep", _LONG, name="--token", server={"command": "npx", "args": ["x@1.0.0", "--verbose", "--token", _LONG]}, note="oversized value; two distinct characters")
_CHAIN = "X-A: " * 2000 + PASSWORD_255
add("t255", "credential", "synthetic-colon-chain", "env", _CHAIN, name="API_TOKEN", secret=PASSWORD_255, server={"command": "npx", "args": _X, "env": {"API_TOKEN": _CHAIN}}, note="colon chain ending in a password")
add("t255", "credential", "synthetic-colon-chain", "arg_flag_sep", _CHAIN, name="--token", secret=PASSWORD_255, server={"command": "npx", "args": ["x@1.0.0", "--token", _CHAIN]}, note="colon chain ending in a password")
add("t255", "credential", "synthetic-colon-chain", "header", _CHAIN, name="API_TOKEN", secret=PASSWORD_255, server={"command": "npx", "args": _X, "headers": {"API_TOKEN": _CHAIN}}, note="colon chain ending in a password")
add("t255", "credential", "token-shaped-name", "env_name", KEY_255, name=KEY_255, server={"command": "npx", "args": _X, "env": {KEY_255: "1"}}, note="token pasted as an env name")
add("t255", "credential", "token-shaped-name", "header_name", KEY_255, name=KEY_255, server={"url": "https://example.invalid/mcp", "headers": {KEY_255: "1"}}, note="token pasted as a header name")

# =====================================================================================
# t259: tests/test_literal_credential_findings.py
# =====================================================================================
def _stdio(*args: str, **fields: Any) -> dict[str, Any]:
    return {"command": "npx", "args": ["-y", "some-mcp@1.0.0", *args], **fields}


def _http(**fields: Any) -> dict[str, Any]:
    return {"type": "http", "url": URL, **fields}


def _docker(*args: str) -> dict[str, Any]:
    return {"command": "docker", "args": ["run", "-i", "--rm", *args, DIGEST]}


# name: planted server, twin server, position, planted shape, planted secret, twin shape, twin value
T259_CASES = {
    "a bearer token in an Authorization header": (_http(headers={"Authorization": f"Bearer {T_RANDOM}"}), _http(headers={"Authorization": "Bearer ${API_TOKEN}"}), "header", "scheme-bearer", T_RANDOM, "ref-client", "Bearer ${API_TOKEN}"),
    "basic credentials in an Authorization header": (_http(headers={"Authorization": f"Basic {T_BASIC}"}), _http(headers={"Authorization": "Basic ${BASIC_CREDENTIALS}"}), "header", "scheme-basic", T_BASIC, "ref-client", "Basic ${BASIC_CREDENTIALS}"),
    "a bearer value with characters outside the token alphabet": (_http(headers={"Authorization": f"Bearer svc:{WORDY}"}), _http(headers={"Authorization": "Bearer svc:${API_TOKEN}"}), "header", "scheme-bearer", WORDY, "partial-reference", "Bearer svc:${API_TOKEN}"),
    "basic credentials in a Proxy-Authorization header": (_http(headers={"Proxy-Authorization": f"Basic {T_BASIC}"}), _http(headers={"Proxy-Authorization": "Basic %PROXY_CREDENTIALS%"}), "header", "scheme-basic", T_BASIC, "ref-windows", "Basic %PROXY_CREDENTIALS%"),
    "an Authorization header without a scheme": (_http(headers={"Authorization": T_RANDOM}), _http(headers={"Authorization": "${input:api_token}"}), "header", "random-under-credential-name", T_RANDOM, "ref-client", "${input:api_token}"),
    "a Codex header named for a credential": (_http(http_headers={"X-Api-Key": T_RANDOM}), _http(http_headers={"X-Request-Id": T_RANDOM}), "header", "random-under-credential-name", T_RANDOM, "random-under-noncredential-name", T_RANDOM),
    "a bearer value under a name that marks no credential": (_stdio(env={"AUTH_HEADER": f"Bearer {T_RANDOM}"}), _stdio(env={"AUTH_HEADER": "Bearer ${AUTH_TOKEN}"}), "env", "scheme-bearer", T_RANDOM, "ref-client", "Bearer ${AUTH_TOKEN}"),
    "a GitHub token in an environment value": (_stdio(env={"GITHUB_TOKEN": T_GITHUB}), _stdio(env={"GITHUB_TOKEN": "${GITHUB_TOKEN}"}), "env", "vendor-token", T_GITHUB, "ref-client", "${GITHUB_TOKEN}"),
    "a fine-grained GitHub token under an unrelated name": (_stdio(env={"LOG_LEVEL": T_FINE}), _stdio(env={"LOG_LEVEL": "github" + "_pat_" + "x" * 30}), "env", "vendor-token", T_FINE, "placeholder-token-format", "github" + "_pat_" + "x" * 30),
    "an AWS access key ID": (_stdio(env={"AWS_ACCESS_KEY_ID": T_AWS}), _stdio(env={"AWS_ACCESS_KEY_ID": AWS_DOC_ID}), "env", "vendor-token", T_AWS, "placeholder-token-format", AWS_DOC_ID),
    "an Anthropic key": (_stdio(env={"ANTHROPIC_API_KEY": T_ANT}), _stdio(env={"ANTHROPIC_API_KEY": "${env:ANTHROPIC_API_KEY}"}), "env", "vendor-token", T_ANT, "ref-client", "${env:ANTHROPIC_API_KEY}"),
    "an OpenAI key": (_stdio(env={"OPENAI_API_KEY": T_OAI}), _stdio(env={"OPENAI_API_KEY": "sk" + "-your-openai-api-key-here"}), "env", "vendor-token", T_OAI, "placeholder-token-format", "sk" + "-your-openai-api-key-here"),
    "a token in another known format": (_stdio(env={"UPSTREAM": T_GITLAB}), _stdio(env={"UPSTREAM": "gl" + "pat-" + "x" * 24}), "env", "vendor-token", T_GITLAB, "placeholder-token-format", "gl" + "pat-" + "x" * 24),
    "a JSON Web Token": (_stdio(env={"SERVICE_ROLE": T_JWT}), _stdio(env={"SERVICE_ROLE": "<service-role-jwt>"}), "env", "vendor-token", T_JWT, "placeholder-marked", "<service-role-jwt>"),
    "a private key block": (_stdio(env={"SIGNING_KEY": T_PEM}), _stdio(env={"SIGNING_KEY": "\n".join((PEM_BEGIN, "...", PEM_END))}), "env", "private-key", T_PEM.split("\n")[1], "placeholder-token-format", "\n".join((PEM_BEGIN, "...", PEM_END))),
    "a password under a name that ends in a credential word": (_stdio(env={"DB_PASSWORD": WORDY}), _stdio(env={"DB_PASSWORD": "postgres"}), "env", "password-wordy", WORDY, "default-word", "postgres"),
    "a password in the user information of an argument": (_stdio(f"postgresql://app:{T_MIXED}@db.internal/app"), _stdio("postgresql://app:${DB_PASSWORD}@db.internal/app"), "url_userinfo_arg", "url-password", T_MIXED, "ref-in-url", "${DB_PASSWORD}"),
    "a password in the user information of an endpoint": ({"type": "http", "url": f"https://svc:{T_MIXED}@mcp.example.test/mcp"}, {"type": "http", "url": "https://svc:${MCP_PASSWORD}@mcp.example.test/mcp"}, "url_userinfo_endpoint", "url-password", T_MIXED, "ref-in-url", "${MCP_PASSWORD}"),
    "a query parameter of an endpoint named for a credential": ({"type": "http", "serverUrl": f"{URL}?api_key={T_RANDOM}"}, {"type": "http", "serverUrl": f"{URL}?request={T_RANDOM}"}, "url_query_endpoint", "url-query-token", T_RANDOM, "random-under-noncredential-name", T_RANDOM),
    "the value of an option named for a credential": (_stdio("--api-key", T_RANDOM), _stdio("--api-key", "${API_KEY}"), "arg_flag_sep", "random-under-credential-name", T_RANDOM, "ref-client", "${API_KEY}"),
    "the value of an option named for a bearer": (_stdio("--sse", URL, "--oauth2Bearer", T_RANDOM), _stdio("--sse", URL, "--oauth2Bearer", "${GATEWAY_TOKEN}"), "arg_flag_sep", "random-under-credential-name", T_RANDOM, "ref-client", "${GATEWAY_TOKEN}"),
    "an option named for a credential with its value attached": (_stdio(f"--api-key={T_RANDOM}"), _stdio("--api-key=<your-api-key>"), "arg_flag_eq", "random-under-credential-name", T_RANDOM, "placeholder-marked", "<your-api-key>"),
    "an environment assignment passed to a container": (_docker("-e", f"API_KEY={T_RANDOM}"), _docker("-e", "API_KEY"), "arg_kv", "random-under-credential-name", T_RANDOM, "env-name-only", "API_KEY"),
    "a container environment option with its assignment attached": (_docker(f"--env=API_KEY={T_RANDOM}"), _docker("--env=API_KEY"), "arg_kv", "random-under-credential-name", T_RANDOM, "env-name-only", "--env=API_KEY"),
    "a header line after a header option": (_stdio(URL, "--header", f"Authorization: Bearer {T_RANDOM}"), _stdio(URL, "--header", "Authorization: Bearer ${AUTH_TOKEN}"), "arg_header_line", "scheme-bearer", T_RANDOM, "ref-client", "Authorization: Bearer ${AUTH_TOKEN}"),
    "a header line attached to its option": (_stdio(URL, f"--header=X-Api-Key: {T_RANDOM}"), _stdio(URL, f"--header=X-Request-Id: {T_RANDOM}"), "arg_header_line", "random-under-credential-name", T_RANDOM, "random-under-noncredential-name", T_RANDOM),
    "a header line joined to a short header option": (_stdio(URL, f"-HX-Api-Key: {T_RANDOM}"), _stdio(URL, f"-HX-Request-Id: {T_RANDOM}"), "arg_header_line", "random-under-credential-name", T_RANDOM, "random-under-noncredential-name", T_RANDOM),
    "an assignment in an inline shell script": ({"command": "sh", "args": ["-c", f'API_TOKEN="Bearer {T_RANDOM}" exec uvx x==1.0']}, {"command": "sh", "args": ["-c", 'API_TOKEN="Bearer $API_TOKEN" exec uvx x==1.0']}, "sh_c", "scheme-bearer", T_RANDOM, "ref-client", "Bearer $API_TOKEN"),
    "a scheme word and its credential in a cmd script": ({"command": "cmd", "args": ["/c", f"set API_TOKEN=Bearer {T_RANDOM}&& npx -y x@1.0.0"]}, {"command": "cmd", "args": ["/c", "set API_TOKEN=Bearer %API_TOKEN%&& npx -y x@1.0.0"]}, "cmd_c", "scheme-bearer", T_RANDOM, "ref-windows", "Bearer %API_TOKEN%"),
    "a bearer token inside a JSON argument": (_stdio("--headers", json.dumps({"Authorization": f"Bearer {T_RANDOM}"})), _stdio("--headers", json.dumps({"Authorization": "Bearer ${AUTH_TOKEN}"})), "arg_json", "scheme-bearer", T_RANDOM, "ref-client", "Bearer ${AUTH_TOKEN}"),
    "a header line in an inline script": ({"command": "sh", "args": ["-c", f"exec gateway -H 'X-Api-Key: {T_RANDOM}' --stdio"]}, {"command": "sh", "args": ["-c", f"exec gateway -H 'X-Request-Id: {T_RANDOM}' --stdio"]}, "sh_c", "random-under-credential-name", T_RANDOM, "random-under-noncredential-name", T_RANDOM),
    "a passphrase with spaces as the value of an option": (_stdio("--passphrase", f"correct horse {WORDY}"), _stdio("--passphrase", "correct horse battery staple"), "arg_flag_sep", "passphrase-words", f"correct horse {WORDY}", "passphrase-doc-example", "correct horse battery staple"),
    "a value under a numbered credential name": (_stdio(env={"API_KEY_2": T_RANDOM}), _stdio(env={"API_KEY_NAME": T_RANDOM}), "env", "random-under-credential-name", T_RANDOM, "random-under-noncredential-name", T_RANDOM),
    "a command line in the command field": ({"command": f"npx -y some-mcp@1.0.0 --token {T_RANDOM}"}, {"command": "npx -y some-mcp@1.0.0 --token $SERVICE_TOKEN"}, "command", "random-under-credential-name", T_RANDOM, "ref-client", "$SERVICE_TOKEN"),
}
for rule, (planted, twin, position, shape, secret, twin_shape, twin_value) in T259_CASES.items():
    add("t259", "credential", shape, position, secret, server=planted, note=f"CASES: {rule}")
    add("t259", "benign", twin_shape, position, twin_value, server=twin, note=f"CASES twin: {rule}")

T259_POSITIONS = {
    "authorization": lambda v: ("header", _http(headers={"Authorization": v})),
    "bearer": lambda v: ("header", _http(headers={"Authorization": f"Bearer {v}"})),
    "header": lambda v: ("header", _http(headers={"X-Api-Key": v})),
    "environment": lambda v: ("env", _stdio(env={"API_TOKEN": v})),
    "option": lambda v: ("arg_flag_sep", _stdio("--api-key", v)),
    "assignment": lambda v: ("arg_flag_eq", _stdio(f"--api-key={v}")),
    "container": lambda v: ("arg_kv", _docker("-e", f"API_KEY={v}")),
    "password": lambda v: ("url_userinfo_endpoint", {"type": "http", "url": f"https://svc:{quote(v, safe='')}@h.test/mcp"}),
    "query": lambda v: ("url_query_endpoint", {"type": "http", "url": f"{URL}?api_key={quote(v, safe='')}"}),
}
T259_REFERENCES = ("${API_TOKEN}", "${input:api_token}", "${env:API_TOKEN}", "$API_TOKEN", "%API_TOKEN%", "$(cat /run/secrets/api_token)")
T259_PLACEHOLDERS = (
    "CHANGE_ME", "<token>", "xxxx", "your-api-key", "x" * 32, "<YOUR_API_KEY>", "API_KEY_GOES_HERE_1",
    "[redacted]", "{{API_TOKEN}}", "changeme123", "replace-with-token-1", "dummy-token-12345",
    "example-token-12345", "sk" + "-...", "*" * 12, "[api-token-1]", "{{ api_token_1 }}",
    "prefix-<token-1>", "1234567890", "abcdef0123456789", "sk" + "-1234567890abcdef1234567890abcdef",
    "{api-token-1}", "token-1...token-2", "sample-token-1", "placeholder-token-1",
    "insert-token-1-here", "redacted-token-1",
)  # fmt: skip
T259_WORDS = ("postgres", "not-needed", "lm-studio", "development", "MyApiKey", "correct-horse-battery-staple", "1" * 12, "ab12" * 3)
_SPOTS = list(T259_POSITIONS)
_turn = 0
for group, values in (("ref", T259_REFERENCES), ("placeholder", T259_PLACEHOLDERS), ("word", T259_WORDS)):
    for value in values:
        if group == "ref":
            shape = {"%": "ref-windows", "$(": "ref-cmd-subst"}.get(value[:2] if value.startswith("$(") else value[:1], "ref-client")
        elif group == "placeholder":
            shape = "placeholder-token-format" if value.startswith("sk" + "-") else "placeholder-marked"
        else:
            shape = "default-word"
        # The environment position for every value, and one other position in turn.
        for spot in ("environment", [s for s in _SPOTS if s != "environment"][_turn % 8]):
            position, server = T259_POSITIONS[spot](value)
            add("t259", "benign", shape, position, value, server=server, note=f"{group.upper()} at {spot}")
        _turn += 1
for position_name in _SPOTS:
    position, server = T259_POSITIONS[position_name](T_RANDOM)
    add("t259", "credential", "scheme-bearer" if position_name == "bearer" else ("url-password" if position_name == "password" else ("url-query-token" if position_name == "query" else "random-under-credential-name")), position, T_RANDOM, server=server, note=f"same positions report a credential: {position_name}")
for value, shape, label in (
    ("sk" + "-local-development-key-for-ollama", "placeholder-token-format", "benign"),
    ("sk" + "-your-openai-api-key-here", "placeholder-token-format", "benign"),
    ("sk" + "-" + "x" * 48, "placeholder-token-format", "benign"),
    (f"Bearer {T_RANDOM}$SUFFIX", "literal-plus-reference", "benign"),
    (f"Bearer {T_RANDOM}" + "${SUFFIX}", "literal-plus-reference", "benign"),
    ("Bearer authentication", "prose-with-scheme-word", "benign"),
):
    add("t259", label, shape, "env", value, server=_stdio(env={"OPENAI_API_KEY": value}), name="OPENAI_API_KEY", note="stand-in or composed value")
    add("t259", label, shape, "arg_flag_sep", value, server=_stdio("--upstream", value), name="--upstream", note="stand-in or composed value")
for value in ("/run/secrets/api_token1", "./secrets/token1.txt", "~/.config/service/token9", "C:\\secrets\\token1", "service-account-1.json", "https://vault.example.test/v1/secret9"):
    shape = "locator-url" if "://" in value else ("keyfile-path-rel" if value.startswith("service") else "keyfile-path-abs")
    add("t259", "benign", shape, "env", value, name="API_TOKEN", note="LOCATORS")
    add("t259", "benign", shape, "env", value, name="PRIVATE_KEY", note="LOCATORS")
    add("t259", "benign", shape, "arg_flag_sep", value, name="--private-key", note="LOCATORS")
    add("t259", "benign", shape, "arg_flag_sep", value, name="--token", note="LOCATORS")
for args in (["mcp-server-tokens==10.20.30"], ["--with", "some-secret==10.20.30", "mcp-server-git==0.6.2"], ["--with", "auth-token>=10.20.30", "mcp-server-git==0.6.2"]):
    add("t259", "benign", "package-requirement", "arg_raw", args[-2] if len(args) > 1 else args[0], server={"command": "uvx", "args": args}, note="requirement")
for name in ("GITHUB_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN", "token2", "clientSecret", "DB_PASSWORD", "PGPASSWORD", "MYSQL_PWD", "SMTP_PASS", "GITHUB_PAT", "apikey", "AWS_SECRET_ACCESS_KEY", "private.key", "SSH_PASSPHRASE", "GITHUB_TOKEN_2"):
    add("t259", "credential", "random-under-credential-name", "env", T_RANDOM, name=name, note="credential name table")
add("t259", "credential", "random-under-credential-name", "header", T_RANDOM, name="X-API-Key", note="credential name table")
add("t259", "credential", "random-under-credential-name", "arg_flag_sep", T_RANDOM, name="--account-key", note="credential name table")
add("t259", "credential", "random-under-credential-name", "arg_flag_sep", T_RANDOM, name="--oauth2Bearer", note="credential name table")
for name in ("TOKEN_FILE", "MAX_TOKENS", "SECRET_NAME", "API_KEY_ID", "SORT_KEY", "PUBLIC_KEY", "BYPASS", "COMPASS", "DISPATCH", "LOG_LEVEL", "tokenizer"):
    add("t259", "benign", "random-under-noncredential-name", "env", T_RANDOM, name=name, note="non-credential name table; a random value under a name that marks none")
for name in ("TOKEN_FILE", "SORT_KEY", "LOG_LEVEL"):
    add("t259", "credential", "vendor-token", "env", T_GITHUB, name=name, note="known format under a non-credential name")
for value, shape in (
    ("123e4567-e89b-12d3-a456-426614174000", "uuid-as-token"),
    (T_RANDOM[:19], "random-under-credential-name"),
    ("ab12cd34" * 3, "random-under-credential-name"),
    ("correct horse battery staple 1", "passphrase-words"),
    ("MixedCaseLettersOnlyValue", "mixedcase-letters-value"),
):
    add("t259", "credential", shape, "env", value, name="API_TOKEN", note="candidate kinds table")

# =====================================================================================
# r259: the reviewers' lists
# =====================================================================================
R32 = rnd(32, seed="r259-R")
R_GH = "gh" + "p_" + rnd(36, seed="r259-gh")
R_GOOG = "AI" + "za" + rnd(35, seed="r259-goog")
R_OAI = "sk" + "-" + rnd(48, seed="r259-oai")
R_HEX32 = rnd(32, HEX, "r259-hex")
R_HEX64 = rnd(64, HEX, "r259-hex64")


def rp(shape: str, position: str, server: dict[str, Any], secret: str = R32, value: str | None = None, note: str = "") -> None:
    add("r259", "credential", shape, position, secret if value is None else value, secret=secret, server=server, note=note or "break/tools/fn.py")


# --- positives (break/tools/fn.py) ---
for name in ("X-Api-Key", "api-key", "x-goog-api-key", "X-API-KEY", "Ocp-Apim-Subscription-Key", "X-Auth-Token", "X-Access-Token", "PRIVATE-TOKEN", "X-Subscription-Token"):
    rp("random-under-credential-name", "header", H(name, R32))
rp("vendor-token", "header", H("x-goog-api-key", R_GOOG), R_GOOG)
rp("vendor-token", "header", H("x-api-key", R_GH), R_GH)
rp("cookie-session", "header", H("Cookie", "session=" + R32))
for scheme in ("Bearer ", "bearer ", "BEARER "):
    rp("scheme-bearer", "header", H("X-Custom", scheme + R32), note="scheme outside Authorization")
for name, value, held in (
    ("Authorization", "Bearer\t" + R32, R32), ("Authorization", "Bearer  " + R32, R32), ("Authorization", "Bearer\u00a0" + R32, R32),
    ("Authorization", "Bearer:" + R32, R32), ("Authorization", "Bearer=" + R32, R32), ("authorization", R32, R32),
    ("AUTHORIZATION", "Token " + R32, R32), ("Authorization", "token " + R32, R32), ("Authorization", "ApiKey " + R32, R32),
    ("Authorization", "Api-Key " + R32, R32), ("Authorization", "Bot " + R32, R32),
    ("Authorization", "Bearer " + R32[:10] + ":" + R32[10:], R32[10:]), ("Authorization", "Bearer v2|" + R32, R32),
):  # fmt: skip
    rp("scheme-authorization-variant", "header", H(name, value), held)
for label_, creds in (("user:pass", "user:pass"), ("user:secret", "user:secret"), ("admin:admin", "admin:admin")):
    add("r259", "benign", "weak-or-doc-password", "header", "Basic " + b64(creds), name="Authorization", secret=b64(creds), server=H("Authorization", "Basic " + b64(creds)), note="break/tools/fn.py lists it as a miss; a documentation pair", author_label="credential")
rp("scheme-basic", "header", H("Authorization", "Basic " + b64("svc:" + R32)), b64("svc:" + R32))
rp("scheme-basic", "header", H("Authorization", "basic " + b64("svc:" + R32)), b64("svc:" + R32))
rp("scheme-basic", "header", H("X-Custom", "Basic " + b64("svc:" + R32)), b64("svc:" + R32), note="scheme outside Authorization")
rp("scheme-basic", "header", H("Proxy-Authorization", "Basic " + b64("svc:" + R32)), b64("svc:" + R32))
rp("scheme-other", "header", H("Authorization", 'Digest username="u", response="' + R32 + '"'))
rp("scheme-other", "header", H("Authorization", "Negotiate " + R32))
rp("scheme-other", "header", H("Authorization", "AWS4-HMAC-SHA256 Credential=" + T_AWS + "/20260101/us-east-1/s3/aws4_request, Signature=" + R_HEX64), R_HEX64)
rp("scheme-bearer", "header", H("X-Custom", "Bearer " + R32 + "$"), note="scheme outside Authorization; token then $")
rp("scheme-bearer", "header", H("X-Custom", "Bearer " + R32 + "%"), note="scheme outside Authorization; token then %")
for q in ("api_key", "apikey", "key", "token", "access_token", "auth"):
    rp("url-query-token", "url_query_endpoint", U(f"{URL}?{q}={R32}"))
rp("url-query-token", "url_query_endpoint", U(f"{URL}?key={R_GOOG}"), R_GOOG)
rp("url-query-token", "url_fragment_endpoint", U(f"{URL}#access_token={R32}"))
rp("url-query-token", "url_matrix_endpoint", U(f"{URL};api_key={R32}"))
rp("url-query-token", "url_query_endpoint", U(f"{URL}?x=1;api_key={R32}"))
rp("url-path-token", "url_path_endpoint", U(f"https://mcp.example.test/{R32}/mcp"))
rp("url-path-token", "url_path_endpoint", U(f"https://mcp.example.test/{R_GH}/mcp"), R_GH)
rp("url-password", "url_userinfo_endpoint", U(f"https://u:{R32}@mcp.example.test/mcp"))
for mark in (";", ",", "'", "%40"):
    rp("url-password", "url_userinfo_endpoint", U(f"https://u:{R32[:8]}{mark}{R32[8:]}@mcp.example.test/mcp"), R32[8:], note=f"password with {mark}")
rp("url-userinfo-user-only", "url_userinfo_endpoint", U(f"https://{R32}@mcp.example.test/mcp"))
rp("url-userinfo-user-only", "url_userinfo_endpoint", U(f"https://{R_GH}@mcp.example.test/mcp"), R_GH)
rp("url-userinfo-user-only", "url_userinfo_endpoint", U(f"https://{R32}:x-oauth-basic@mcp.example.test/mcp"))
rp("url-password", "url_userinfo_env", E("DATABASE_URL", f"postgres://app:{R32[:8]};{R32[8:]}@db.test:5432/app"), R32[8:])
rp("connection-string", "env", E("CONNECTION_STRING", f"Server=db;User Id=sa;Password={R32};"))
rp("connection-string", "env", E("JDBC_URL", f"jdbc:sqlserver://db.test:1433;user=sa;password={R32}"))
rp("url-password", "url_userinfo_env", E("REDIS_URL", f"redis://:{R32}@cache.test:6379/0"))
rp("random-under-credential-name", "arg_flag_eq", A("--token=" + R32))
rp("random-under-credential-name", "arg_flag_sep", A("--token", R32))
rp("random-under-credential-name", "arg_flag_sep", A("--apiKey", R32))
rp("random-under-credential-name", "arg_flag_eq", A("--api-key=" + R32))
rp("random-unmarked-position", "arg_flag_sep", A("-t", R32), note="short flag")
rp("random-under-credential-name", "arg_flag_other", A("--token:" + R32))
rp("random-under-credential-name", "arg_flag_other", A("/token:" + R32))
rp("random-unmarked-position", "arg_positional", A("login", R32), note="positional")
rp("random-under-credential-name", "arg_kv", A("API_TOKEN=" + R32))
rp("random-under-credential-name", "arg_kv", {"command": "docker", "args": ["run", "-e", "API_TOKEN=" + R32, IMG]})
rp("random-under-credential-name", "arg_kv", {"command": "docker", "args": ["run", "-eAPI_TOKEN=" + R32, IMG]})
rp("random-under-credential-name", "arg_kv", {"command": "docker", "args": ["run", "--env", "API_TOKEN=" + R32, IMG]})
rp("random-under-credential-name", "arg_kv", {"command": "docker", "args": ["run", "--env=API_TOKEN=" + R32, IMG]})
_REMOTE = ["-y", "mcp-remote@1.0.0", URL]
for tail in (
    ["--header", "Authorization: Bearer " + R32], ["--header", "Authorization:Bearer " + R32],
    ["--header", "X-Api-Key:" + R32], ["--header=X-Api-Key: " + R32], ["-H", "X-Api-Key: " + R32],
    ["-HX-Api-Key: " + R32], ["--header", "Authorization: " + R32],
):  # fmt: skip
    rp("arg-header-line", "arg_header_line", {"command": "npx", "args": [*_REMOTE, *tail]})
rp("arg-header-line", "arg_header_line", {"command": "npx", "args": [*_REMOTE, "--header", "Authorization: Basic " + b64("svc:" + R32)]}, b64("svc:" + R32))
rp("arg-header-line", "arg_json", {"command": "npx", "args": [*_REMOTE, "--headers", json.dumps({"X-Api-Key": R32})]})
rp("arg-header-line", "arg_header_line", {"command": "npx", "args": ["-y", "x@1.0.0", "--custom-header", "X-Api-Key: " + R32]}, note="--custom-header")
rp("arg-embedded", "arg_embedded", A("--opts", f"retries=3,token={R32},timeout=5"))
rp("arg-embedded", "arg_embedded", A("--opts", f"retries=3,auth={R_GH},timeout=5"), R_GH)
rp("arg-embedded", "arg_json", A("--config", json.dumps({"api_key": R32})))
rp("url-query-token", "url_query_arg", {"command": "npx", "args": ["-y", "mcp-remote@1.0.0", f"{URL}?api_key={R32}"]})
rp("inline-script", "sh_c", SH(f"export API_TOKEN={R32}; exec npx -y some-mcp@1.0.0"))
rp("inline-script", "sh_c", SH(f"API_TOKEN='{R32}' npx -y some-mcp@1.0.0"))
rp("inline-script", "sh_c", SH(f"API_TOKEN = {R32} npx -y some-mcp@1.0.0"), note="spaces around =")
rp("inline-script", "sh_c_flag", SH(f"npx -y some-mcp@1.0.0 --token {R32}"))
rp("inline-script", "sh_c", SH("curl -H 'Authorization: " + f"Bearer {R32}' https://x.test/"))
rp("inline-script", "sh_c", SH(f"curl -H 'X-Api-Key: {R32}' https://x.test/"))
rp("inline-script", "sh_c", SH(f"curl -u admin:{R32} https://x.test/"), note="curl -u user:password")
rp("random-unmarked-position", "sh_c", SH(f"echo {R32} | docker login -u u --password-stdin"), note="echo value | --password-stdin")
rp("inline-script", "cmd_c", {"command": "cmd", "args": ["/c", f"set API_TOKEN={R32}&& npx -y some-mcp@1.0.0"]})
rp("inline-script", "cmd_c", {"command": "cmd", "args": ["/c", f'set "API_TOKEN={R32}" && npx -y some-mcp@1.0.0']})
rp("inline-script", "powershell_c", {"command": "powershell", "args": ["-Command", f"$env:API_TOKEN='{R32}'; npx -y some-mcp@1.0.0"]})
rp("random-under-credential-name", "command", {"command": f"npx -y some-mcp@1.0.0 --password {R32}"})
for name in ("GITHUB_PERSONAL_ACCESS_TOKEN", "API_KEY", "BRAVE_API_KEY", "CLIENT_SECRET", "SECRET_KEY", "GITHUB_TOKEN_PROD", "TOKEN2"):
    rp("random-under-credential-name", "env", E(name, R32))
rp("vendor-token", "env", E("OPENAI_API_KEY", R_OAI), R_OAI)
rp("vendor-token", "env", E("OPENAI_KEY", R_OAI), R_OAI)
rp("random-under-credential-name", "env", E("DB_PASSWORD", R_HEX32), R_HEX32)
rp("uuid-as-token", "env", E("API_TOKEN", UUID_ID), UUID_ID)
rp("random-under-credential-name", "env", E("AUTH_TOKEN", R32 + "\n"), note="trailing newline")
rp("private-key", "env", E("K", PEM_RSA), PEM_RSA.split("\n")[1])
rp("private-key", "env", E("K", PEM_SSH), PEM_SSH.split("\n")[1])
_PEM_ESC = PEM_BEGIN + "\\n" + rnd(64, B64, "pemesc1") + "\\n" + rnd(64, B64, "pemesc2") + "\\n" + PEM_END
rp("private-key", "env", E("K", _PEM_ESC), _PEM_ESC.split("\\n")[1], note="PEM with literal backslash-n")
_PEM28 = PEM_BEGIN + "\n" + "\n".join(rnd(28, B64, f"pem28-{i}") for i in range(8)) + "\n" + PEM_END
rp("private-key", "env", E("K", _PEM28), _PEM28.split("\n")[1], note="PEM in lines of 28")
_PEM_B64 = b64(PEM_BEGIN + "\n" + rnd(64, B64, "pemb64") + "\n" + PEM_END)
rp("private-key", "env", E("SIGNING_PRIVATE_KEY_B64", _PEM_B64), _PEM_B64, note="PEM wrapped in base64")
rp("private-key", "env", E("K", PEM_PGP), PEM_PGP.split("\n")[2], note="PGP private key block")
_PUTTY = "PuTTY-User-Key-File-3: ssh-ed25519\nPrivate-Lines: 1\n" + rnd(64, B64, "putty")
rp("private-key", "env", E("K", _PUTTY), _PUTTY.split("\n")[2], note="PuTTY key file")
rp("vendor-token", "env", E("SUPABASE_KEY", JWT), JWT)
_HOOK = rnd(24, seed="hook")
rp("url-path-token", "env", E("SLACK_WEBHOOK_URL", "https://hooks.slack.test/services/T" + rnd(8, UPNUM, "h1") + "/B" + rnd(8, UPNUM, "h2") + "/" + _HOOK), _HOOK, note="webhook URL with a secret path")
rp("random-under-credential-name", "env", E("API_TOKEN", "  " + R32 + "  "), note="white space around the value")
rp("random-under-credential-name", "env", E("API_TOKEN", '"' + R32 + '"'), note="value in quotes")
rp("scheme-bearer", "header", {"url": URL, "http_headers": {"Authorization": "Bearer " + R32}}, note="http_headers")
rp("scheme-bearer", "header", H("Authorization ", "Bearer " + R32), note="header name with a trailing space")


def rb(shape: str, position: str, value: str, server: dict[str, Any], note: str = "", label: str = "benign", author_label: str | None = None) -> None:
    add("r259", label, shape, position, value, server=server, note=note, author_label=author_label)


def rbe(shape: str, name: str, value: str, note: str = "", **kw) -> None:
    rb(shape, "env", value, E(name, value), note, **kw)


def rbh(shape: str, name: str, value: str, note: str = "", **kw) -> None:
    rb(shape, "header", value, H(name, value), note, **kw)


def rba(shape: str, flag: str, value: str, note: str = "", **kw) -> None:
    rb(shape, "arg_flag_sep", value, A(flag, value), note, **kw)


# --- benign: references ---
for name, value in (
    ("API_TOKEN", "${API_TOKEN:-none}"), ("API_TOKEN", "${API_TOKEN:-dev-token-123}"), ("API_TOKEN", "${API_TOKEN:?must be set}"),
    ("API_KEY", "${API_KEY:-}"), ("TOKEN", "${TOKEN:?missing}"), ("S3_ACCESS_KEY", "${S3_ACCESS_KEY}"),
):  # fmt: skip
    rbe("ref-shell-default" if ":" in value else "ref-client", name, value)
rbh("ref-client", "Authorization", "Bearer ${input:github_token}")
rbh("ref-client", "Authorization", "Bearer ${env:API_TOKEN}")
rbh("ref-client", "Authorization", "Bearer $API_TOKEN")
for name, value in (("GITHUB_TOKEN", "$env:GITHUB_TOKEN"), ("API_KEY", "$env:API_KEY"), ("API_KEY", "%API_KEY%"), ("PRIVATE_KEY", "%USERPROFILE%\\.ssh\\id_ed25519"), ("PRIVATE_KEY", "$HOME/.ssh/id_ed25519")):
    rbe("ref-windows" if "%" in value or "$env" in value else "ref-client", name, value)
rbe("ref-cmd-subst", "API_TOKEN", "$(cat /run/secrets/token1)")
rbe("ref-cmd-subst", "API_TOKEN", "`pass show api/token1`")
for value in (
    "${{ secrets.API_TOKEN_2 }}", "{{ env.API_TOKEN_2 }}", "{{ .Values.apiToken1 }}", "<%= ENV['API_TOKEN_2'] %>",
    "{{ secrets.API_TOKEN_2 }}", "{% vault 'secret/app2' %}", "#{ENV['API_TOKEN_2']}", "__API_TOKEN_2__", "@@API_TOKEN_2@@",
    "%(api_token_2)s", "{api_token_2}", "$api_token_2", "!ENV API_TOKEN_2", "!Ref ApiToken2", "{API_KEY}", "{{TOKEN}}",
    "{{ env.API_KEY }}", "${{ secrets.API_KEY }}", "{{resolve:secretsmanager:MySecret:SecretString:password}}",
):  # fmt: skip
    rbe("ref-template", "API_TOKEN", value)
for name, value in (
    ("API_TOKEN", "op://Engineering/github-bot-2/credential"), ("GITHUB_TOKEN", "op://vault7/item9/token"),
    ("GITHUB_TOKEN", "op://Private/GitHub2/token"), ("DB_PASSWORD", "op://dev/postgres1/password"),
    ("DB_PASSWORD", "vault:secret/data/app2#password"), ("DB_PASSWORD", "vault://secret/data/app2/password"),
    ("DB_PASSWORD", "vault:secret/data/myApp/prod#DB_PASSWORD"), ("DB_PASSWORD", "vault:secret/data/db1#password"),
    ("AWS_SECRET_ACCESS_KEY", "vault:secret/data/accounts/aws#AWS_SECRET_ACCESS_KEY"), ("DB_PASSWORD", "vault:secret/data/mysql#password"),
    ("DB_PASSWORD", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf"),
    ("DB_PASSWORD", "arn:aws:secretsmanager:us-east-1:907812345021:secret:prod/db-QzWxYv"),
    ("DB_PASSWORD", "arn:aws:secretsmanager:us-west-2:111122223333:secret:MyDbPassword"),
    ("API_TOKEN", "arn:aws:ssm:us-east-1:907812345021:parameter/prod/api-token"),
    ("DB_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:907812345021:secret:prod/db-QzWxYv"),
    ("API_TOKEN", "ssm:/prod/app2/api-token"), ("API_TOKEN", "keyring:service2/account"), ("API_TOKEN", "keychain:mcp-github/token"),
    ("API_TOKEN", "env:API_TOKEN_2"), ("GITHUB_TOKEN", "env:GITHUB_TOKEN"), ("API_TOKEN", "file:/run/secrets/token2"),
    ("API_TOKEN", "file:/run/secrets/api_token"), ("API_TOKEN", "@/run/secrets/token2"),
    ("API_TOKEN", "projects/1098765/secrets/api-token/versions/3"), ("API_TOKEN", "projects/my-project/secrets/api-token/versions/latest"),
    ("API_TOKEN", "@Microsoft.KeyVault(SecretUri=https://kv2.vault.test/secrets/tok/)"),
    ("DB_PASSWORD", "@Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret)"),
    ("API_TOKEN", "doppler://proj2/prd/API_TOKEN"), ("API_TOKEN", "infisical://proj2/prod/API_TOKEN"), ("API_TOKEN", "sm://my-project-2/api-token"),
    ("API_TOKEN", "ENC[AES256_GCM,data:9aBc,iv:x,tag:y,type:str]"), ("API_TOKEN", "secretref:api-token-v2"),
    ("DB_PASSWORD", "secretKeyRef:db-credentials-v2/password"), ("DB_PASSWORD", "chamber:prod-app2/db_password"),
    ("DB_PASSWORD", "!vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6231346364"), ("API_TOKEN", "bw:item/9f8e7d6c-5b4a-3f2e-1d0c-9b8a7f6e5d4c/password"),
    ("API_TOKEN", "pass:services/api2/token"), ("OPENAI_API_KEY", "os.environ/OPENAI_API_KEY"), ("API_TOKEN", "secret/data/mcp/github"),
):  # fmt: skip
    rbe("ref-secret-store", name, value)
rbh("ref-secret-store", "Authorization", "Bearer op://Private/GitHub/token")
for name, value in (
    ("API_TOKEN", "process.env.API_TOKEN_2"), ("API_TOKEN", "os.environ['API_TOKEN_2']"), ("OPENAI_API_KEY", "process.env.OPENAI_API_KEY"),
    ("API_KEY", "process.env.API_KEY"), ("OPENAI_API_KEY", "os.getenv('OPENAI_API_KEY')"), ("API_TOKEN", "secrets.SERVICE_API_TOKEN"),
    ("API_TOKEN", 'Deno.env.get("SERVICE_API_TOKEN")'), ("API_TOKEN", 'System.getenv("SERVICE_API_TOKEN")'), ("GITHUB_TOKEN", "env.GITHUB_TOKEN"),
):  # fmt: skip
    rbe("ref-code", name, value)
rbh("ref-code", "Authorization", "Bearer process.env.SERVICE_TOKEN")
rba("ref-code", "--api-key", "process.env.SERVICE_API_KEY")
for command, args in (
    ("node", ["-e", "const token=process.env.GH_TOKEN; require('./srv').start({token})"]),
    ("node", ["-e", "const token=process.env.TOKEN; require('./srv').start({token})"]),
    ("node", ["-e", "const cfg=require('./config'); const secret=cfg.auth.clientSecretValue; require('./srv').start({secret})"]),
    ("python", ["-c", "from app import settings, srv; token=settings.GITHUB_TOKEN; srv.run(token)"]),
    ("python", ["-c", "import os, srv; token=os.environ['GITHUB_TOKEN']; srv.run(token)"]),
    ("bun", ["-e", "const apiKey=Bun.env.RELEASES_API_KEY; (await import('./srv.ts')).serve({apiKey})"]),
    ("node", ["--input-type=module", "-e", "const token=import.meta.env.VITE_SERVICE_TOKEN; (await import('./srv.mjs')).start(token)"]),
):  # fmt: skip
    rb("inline-code-env-read", "inline_code", args[-1], {"command": command, "args": args})
for command, args in (
    ("aws-vault", ["exec", "prod2", "--", "npx", "-y", "some-mcp@1.0.0"]), ("op", ["run", "--env-file=.env.1password", "--", "npx", "-y", "some-mcp@1.0.0"]),
    ("pass", ["show", "mcp/service1/token"]), ("keyring", ["get", "mcp-service1", "api_token"]),
    ("security", ["find-generic-password", "-s", "mcp-service1", "-w"]), ("gcloud", ["secrets", "versions", "access", "latest", "--secret=mcp-api-key-v2"]),
    ("aws", ["secretsmanager", "get-secret-value", "--secret-id", "prod/mcp/api-key-2"]),
    ("openssl", ["pkcs12", "-in", "bundle.p12", "-pass", "env:P12_PASSWORD_2"]), ("docker", ["build", "--secret", "id=github_token,env=GITHUB_TOKEN", "."]),
    ("docker", ["run", "--secret", "id=npm2,src=.npmrc", IMG]), ("docker", ["run", "-e", "API_TOKEN", IMG]), ("docker", ["run", "--env-file", ".env.prod2", IMG]),
    ("docker", ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server:v0.31.0"]),
    ("docker", ["run", "-i", "--rm", "-e", "API_TOKEN=${API_TOKEN}", "-e", "LOG_LEVEL=debug", "mcp/x:1.0.0"]),
    ("psql", ["--no-password", "service1.internal"]), ("gh", ["auth", "login", "--with-token", "github1.example.com"]),
    ("ssh", ["-o", "PasswordAuthentication=no", "-o", "IdentityFile=~/.ssh/id_ed25519", "mcp1.internal", "mcp-server"]),
):  # fmt: skip
    rb("secret-helper-command", "arg_raw", " ".join(args), {"command": command, "args": args})
# --- benign: paths and key files ---
for name, value in (
    ("SSH_PRIVATE_KEY", "/home/ci/.ssh/id_ed25519"), ("SSH_PRIVATE_KEY", "~/.ssh/id_rsa2"), ("GOOGLE_APPLICATION_SECRET", "./secrets/sa-key2.json"),
    ("API_TOKEN", "C:\\Users\\ci2\\token.txt"), ("PWD", "/workspace/app2"), ("API_TOKEN", "/run/secrets/api_token_v2"), ("PRIVATE_KEY", "~/.ssh/id_ed25519"),
    ("PRIVATE_KEY", ".\\keys\\id_ed25519"), ("GITHUB_TOKEN_FILE", "/run/secrets/github_token"), ("TOKEN_PATH", "~/.config/app/token.json"),
    ("GOOGLE_APPLICATION_CREDENTIALS", "/home/dev/.config/gcloud/sa.json"), ("KUBECONFIG", "/home/dev/.kube/config"),
    ("PASSWORD_STORE_DIR", "/home/dev/.password-store"), ("GIT_ASKPASS", "/usr/lib/git-core/git-gui--askpass"),
    ("DB_PASSWORD_FILE", "/run/secrets/db_password"), ("DB_PASSWORD", "/run/secrets/db_password"), ("SSH_PRIVATE_KEY", "C:\\Users\\dev\\.ssh\\id_ed25519"),
    ("SSH_PRIVATE_KEY", "./keys/id_ed25519"), ("INIT_CWD", "/workspace/app1"), ("HF_HOME", "/models/hf-cache-2"),
):  # fmt: skip
    rbe("keyfile-path-abs", name, value)
rba("keyfile-path-abs", "--token-file", "/run/secrets/tok2")
rb("keyfile-path-abs", "arg_flag_eq", "/run/secrets/pw2", A("--password-file=/run/secrets/pw2"))
for name, value in (
    ("TLS_PRIVATE_KEY", "server2.key"), ("JWT_SECRET", "jwt-signing-2.pem"), ("API_TOKEN", "secrets/token2"), ("TOKEN_FILE", "secrets/token2"),
    ("PWD", "packages/app2"), ("OLDPWD", "packages/app2"), ("SSH_PRIVATE_KEY", "id_ed25519"), ("SSH_PRIVATE_KEY", ".ssh/id_ed25519"),
    ("SSH_PRIVATE_KEY", "keys/id_ed25519"), ("GITHUB_APP_PRIVATE_KEY", "secrets/github-app.2024-01-01.private-key"), ("JWT_SECRET", "config/jwt_secret_v2"),
    ("TLS_PRIVATE_KEY", "certs/tls.key"), ("PRIVATE_KEY", "keys\\id_ed25519"), ("API_TOKEN", "secrets/api_token_v2"), ("DB_PASSWORD", "run/secrets/db_password_2"),
    ("SNOWFLAKE_PRIVATE_KEY", "rsa_key.p8"), ("APNS_PRIVATE_KEY", "AuthKey_7QW4RT2ZX9.p8"), ("GITHUB_APP_PRIVATE_KEY", "github-app.2024-05-01.private-key.pem"),
    ("SSH_PRIVATE_KEY", "deploy2.ppk"), ("TLS_PRIVATE_KEY", "server1.der"), ("GOOGLE_OAUTH_TOKEN", "tokens/google-oauth2"), ("SSH_PRIVATE_KEY", "id_rsa"),
    ("SSH_PRIVATE_KEY", "./id_ed25519"), ("TLS_PRIVATE_KEY", "certs/server1/privkey"), ("GOOGLE_SERVICE_ACCOUNT_KEY", "sa-prod1.json"),
    ("SSH_ASKPASS", "ssh-askpass1"), ("SSH_PRIVATE_KEY", "id_ecdsa_sk"), ("TLS_PRIVATE_KEY", "certs/tls.key.der"), ("KEYSTORE_PASS", "keystore.jks"),
    ("DB_PASSWORD", "secrets/db_password"),
):  # fmt: skip
    rbe("keyfile-path-rel", name, value)
for flag, value in (("--private-key", "keys/id_ed25519"), ("--token", "token-cache-2/default"), ("--private-key", "keystore2.jks"), ("--token", "token2.pickle"), ("--private-key", "id_ed25519"), ("--privateKey", "ssh/id_ed25519"), ("--pwd", "apps/api2")):
    rba("keyfile-path-rel", flag, value)
rb("keyfile-path-rel", "arg_flag_eq", "certs/server2-key", A("--private-key=certs/server2-key"))
# --- benign: URLs that hold no credential ---
for name, value in (
    ("API_TOKEN_URL", URL), ("AUTH_TOKEN", "https://auth2.example.test/oauth/token"), ("JWT_ISSUER", "https://issuer2.example.test/"),
    ("FASTMCP_SERVER_AUTH_JWT_JWKS_URI", "https://auth.acme-corp.test/.well-known/jwks.json"), ("HTTPS_PROXY", "http://proxy.corp.example:3128"),
    ("SENTRY_DSN", "https://9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c@o123.ingest.sentry.test/45"), ("PYDANTIC_AI_GATEWAY_BASE_URL", "https://gateway.pydantic.dev/proxy"),
):  # fmt: skip
    rbe("locator-url", name, value)
for url in (
    "http://localhost:8080/mcp", "https://git2@host.example.test/x", URL + "?token=${TOKEN}", URL + "?token=<your-token>", URL + "?page_" + "token=abc123def456",
    URL + "?max_tokens=4096", "https://mcp.example.test/v1/workspaces/ws_8f14e45fceea467f/mcp", "https://mcp.tavily.test/mcp/?tavilyApiKey=<your-api-key>",
    URL + "?api_key=${EXA_API_KEY}", URL + "?pageToken=CAISBAgBEAE9", URL + "?token=true&password=false", URL + "?page_token=CAESBggDEAEYAQ1",
):  # fmt: skip
    rb("locator-url", "url_endpoint", url, U(url))
for arg in ("git+ssh://git@github.com/org/repo.git@v1.2.3", "git+https://github.com/org/repo@8f14e45fceea467fa9f41c0c2a7c1b1100000000"):
    rb("locator-url", "arg_flag_sep", arg, A("--from", arg))
rb("locator-url", "arg_raw", "https://unpkg.com/@scope/pkg@1.2.3/dist/index.js", A("https://unpkg.com/@scope/pkg@1.2.3/dist/index.js"))
# --- benign, debatable: documented defaults and weak passwords ---
for server, value in (
    (E("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/app"), "postgres"), (E("DATABASE_URL", "postgres://app:password@db:5432/app"), "password"),
    (E("DATABASE_URL", "postgres://app:pass1@db:5432/app"), "pass1"), (E("DATABASE_URL", "postgres://dev:devpassword1@localhost:5432/dev"), "devpassword1"),
    (A("postgresql://user:password@localhost:5432/mydb"), "password"), (A("postgresql://app:app_dev_2024@localhost:5432/app"), "app_dev_2024"),
    (A("mongodb://admin:admin@localhost:27017/?authSource=admin"), "admin"), (A("amqp://guest:guest@localhost:5672/"), "guest"),
    (E("ELASTICSEARCH_URL", "http://elastic:changeme@localhost:9200"), "changeme"),
):  # fmt: skip
    rb("weak-or-doc-password", "url_userinfo_env" if "env" in server else "url_userinfo_arg", value, server, "a documented default in URL user information")
rb("placeholder-marked", "url_userinfo_arg", "<password>", A("mongodb+srv://<username>:<password>@cluster0.mongodb.net/"))
for name, value in (
    ("NEO4J_PASSWORD", "password"), ("AWS_SECRET_ACCESS_KEY", "minioadmin"), ("AWS_SECRET_ACCESS_KEY", "test"), ("OPENAI_API_KEY", "token-abc123"),
    ("LITELLM_MASTER_KEY", "sk-1234"), ("KEYCLOAK_ADMIN_PASSWORD", "admin"), ("KEYSTORE_PASSWORD", "changeit"), ("MSSQL_SA_PASSWORD", "yourStrong(!)Password"),
    ("VAULT_TOKEN", "root"), ("VAULT_TOKEN", "dev-only-token"), ("JWT_SECRET", "dev-secret"), ("DB_PASSWORD", "test1234"), ("DB_PASSWORD", "passw0rd"),
    ("DB_PASSWORD", "p@ssw0rd!"), ("JWT_SECRET", "secret123"), ("DB_PASSWORD", "changeme1"), ("ADMIN_PASSWORD", "admin123"),
):  # fmt: skip
    rbe("weak-or-doc-password", name, value, "a documented default or a weak password the reviewers list as benign")
rb("weak-or-doc-password", "arg_kv", "postgres", {"command": "docker", "args": ["run", "-i", "--rm", "-e", "POSTGRES_PASSWORD=postgres", "-e", "POSTGRES_USER=postgres", "postgres:16.4"]})
# --- benign: placeholders ---
for name, value in (
    ("API_TOKEN", "<token>"), ("API_KEY", "<YOUR_API_KEY>"), ("API_KEY", "your-api-key"), ("API_KEY", "CHANGE_ME"), ("DB_PASSWORD", "changeme"),
    ("API_KEY", "********"), ("API_KEY", "..."), ("API_KEY", "TODO: add key"), ("API_KEY", "REPLACE_ME"), ("API_KEY", "insert-key-here"),
    ("API_TOKEN", "my-secret-token"), ("API_TOKEN", "token-goes-here"), ("API_TOKEN", "none"), ("OPENAI_API_KEY", "ollama"), ("OPENAI_API_KEY", "lm-studio"),
    ("OPENAI_API_KEY", "EMPTY"), ("HF_TOKEN", "anonymous"), ("API_TOKEN", "development-token"), ("API_TOKEN", "00000000-0000-0000-0000-000000000000"),
    ("API_TOKEN", "11111111-2222-3333-4444-555555555555"), ("API_KEY", "0123456789abcdef0123456789abcdef"), ("API_KEY", "deadbeef" * 4),
    ("API_KEY", "aaaabbbbccccdddd1111"), ("API_KEY", "1234abcd1234abcd"), ("API_KEY", "TODO-JIRA-4521"), ("API_TOKEN", "Add-Token-Here"),
    ("API_KEY", "dummy"), ("ANTHROPIC_API_KEY", "not-needed"), ("API_KEY", "REQUIRED"), ("SECRET", "<secret>"), ("API_KEY", "your-api-key-here"),
    ("API_KEY", "Enter Token Here"), ("API_KEY", "not-required"), ("API_KEY", "APIKEY"), ("TOKEN", "MYTOKEN"),
):  # fmt: skip
    rbe("placeholder-marked" if value not in ("none", "ollama", "lm-studio", "EMPTY", "anonymous", "dummy", "not-needed", "not-required", "REQUIRED") else "default-word", name, value)
for value in (
    "Bearer <token>", "Bearer YOUR_TOKEN", "Bearer token", "Bearer TOKEN_HERE", "Bearer my-token", "Bearer test", "Bearer test-token", "Bearer dev-token-1",
    "Basic <base64-credentials>", "Bearer <YOUR_TOKEN>", "Bearer YOUR_API_TOKEN", "Bearer TOKEN_GOES_HERE", "Bearer my-secret-token",
    "Bearer 00000000-0000-0000-0000-000000000000", "Bearer 1234567890", "Bearer abc123", "Bearer test-token-1", "Bearer fake-token-for-tests-1",
    "Bearer MOCK_TOKEN_1", "Bearer local-dev-only-1", "Bearer undefined", "Bearer Token Goes Here", "Bearer Personal Access Token",
    "Bearer token from the Acme console", "Basic base64(username:password)", "Basic base64-encoded-credentials", "Basic BASE64_ENCODED_CREDENTIALS",
    "Basic <base64(email:api_token)>", "Basic base64(email:api_token)", "none",
):  # fmt: skip
    rbh("placeholder-after-scheme", "Authorization", value)
for name, value in (
    ("OPENAI_API_KEY", "sk" + "-" + "x" * 32), ("OPENAI_API_KEY", "sk" + "-..."), ("GITHUB_TOKEN", "gh" + "p_" + "x" * 36), ("GITHUB_TOKEN", "gh" + "p_" + "0" * 36),
    ("GITHUB_TOKEN", "gh" + "p_" + "1234567890" * 4), ("GITHUB_TOKEN", "gh" + "p_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"), ("AWS_ACCESS_KEY_ID", AWS_DOC_ID),
    ("AWS_SECRET_ACCESS_KEY", AWS_DOC_SECRET), ("OPENAI_API_KEY", "sk" + "-local-development-key"), ("OPENAI_API_KEY", "sk" + "-no-key-required"),
    ("GITHUB_TOKEN", "gh" + "p_" + "a" * 36), ("GITHUB_TOKEN", "gh" + "p_" + "X" * 36), ("GITHUB_TOKEN", "gh" + "p_" + "<your_token>"),
    ("GITHUB_TOKEN", "gh" + "p_" + "REPLACEWITHYOURPERSONALACCESSTOKEN0000"), ("GITHUB_TOKEN", "github" + "_pat_" + "0" * 30), ("AWS_ACCESS_KEY_ID", "AK" + "IA" + "0" * 16),
    ("AWS_ACCESS_KEY_ID", "AK" + "IA" + "X" * 16), ("ANTHROPIC_API_KEY", "sk" + "-ant-api03-..."), ("ANTHROPIC_API_KEY", "sk" + "-ant-" + "x" * 40),
    ("ANTHROPIC_API_KEY", "sk" + "-ant-api03-" + "0" * 40), ("ANTHROPIC_API_KEY", "sk" + "-ant-api03-" + "A" * 20 + "0" * 20), ("OPENAI_API_KEY", "sk" + "-proj-" + "0000aaaa" * 6),
    ("SLACK_BOT_TOKEN", "xo" + "xb-" + "000000000000-000000000000-000000000000000000000000"), ("SLACK_BOT_TOKEN", "xo" + "xb-" + "111111111111-222222222222-aaaaaaaaaaaaaaaaaaaaaaaa"),
    ("JWT", JWT_SAMPLE), ("GOOGLE_API_KEY", "AI" + "za-not-a-go-setting"),
):  # fmt: skip
    rbe("placeholder-token-format", name, value)
for name, value in (
    ("API_TOKEN", "Enter-Token-Here-Please"), ("BRAVE_API_KEY", "Get-From-Brave-Dashboard"), ("API_TOKEN", "PasteTokenFromSettings"), ("GITHUB_TOKEN", "TokenFromGitHubSettings"),
    ("API_KEY", "API-Key-From-Dashboard"), ("API_KEY", "DEIN_API_SCHLUESSEL"), ("API_KEY", "dein-api-schluessel"), ("API_TOKEN", "token-hier-einfuegen"),
    ("API_KEY", "votre-cle-api"), ("API_KEY", "VOTRE_CLE_API"), ("API_KEY", "tu-clave-api-aqui"), ("API_TOKEN", "TU_TOKEN_AQUI"), ("API_KEY", "sua-chave-aqui"),
    ("API_KEY", "la-tua-chiave-api"), ("API_KEY", "\u3042\u306a\u305f\u306eAPI\u30ad\u30fc\u3092\u3053\u3053\u306b"), ("API_KEY", "\u5728\u6b64\u5904\u586b\u5165\u60a8\u7684\u5bc6\u94a5"),
    ("API_KEY", "\u8bf7\u586b\u51991\u4e2a\u6709\u6548\u7684\u5bc6\u94a5"), ("API_KEY", "\u0432\u0430\u0448-\u043a\u043b\u044e\u0447-api"), ("API_KEY", "Hier-API-Schluessel-eintragen"),
    ("API_KEY", "DeinApiSchluesselHier"), ("API_KEY", "Votre-Cle-API-Ici-SVP"), ("API_KEY", "Tu-Clave-De-API-Aqui"), ("API_KEY", "Sua-Chave-De-API-Aqui"),
    ("API_KEY", "La-Tua-Chiave-API-Qui"), ("API_KEY", "Jouw-API-Sleutel-Hier"), ("API_KEY", "API-Anahtarinizi-Girin"),
    ("API_KEY", "\u0412\u0441\u0442\u0430\u0432\u044c\u0442\u0435-\u0412\u0430\u0448-\u041a\u043b\u044e\u0447-API-\u0421\u044e\u0434\u0430"), ("API_KEY", "API\u30ad\u30fc\u3092\u3053\u3053\u306b1\u3064\u5165\u529b"),
    ("API_KEY", "\u8bf7\u5728\u6b64\u5904\u586b\u51992\u6b21\u5bc6\u94a5"), ("API_KEY", "\uc5ec\uae30\uc5d0-API-\ud0a4-\uc785\ub825-1"),
):  # fmt: skip
    rbe("placeholder-phrase", name, value)
# --- benign: explanatory text ---
for name, value in (
    ("API_KEY", "Get this from the Acme dashboard"), ("API_TOKEN", "Injected by CI at build time"), ("DB_PASSWORD", "Provided by Vault Agent"),
    ("API_KEY", "Not required for local use"), ("API_KEY", "not required for local use"), ("SLACK_BOT_TOKEN", "Bot User OAuth Token"),
    ("APP_PASSWORD", "Generate an app password in account settings"), ("API_KEY", "see 1Password vault"), ("API_TOKEN", "set in step 2"),
    ("API_TOKEN", "TODO: add the token before the first run"), ("GITHUB_TOKEN", "Optional. Raises the GitHub rate limit."),
    ("API_KEY", "Read from the macOS Keychain at startup"), ("API_KEY", "Paste the key here"), ("CLIENT_SECRET", "oauth2-client-secret"),
    ("API_KEY", "s3-access-key"), ("TOKEN", "oauth2-token"), ("PRIVATE_KEY", "base64-encoded-pem"), ("API_KEY", "base64 encoded key"),
    ("SIGNING_SECRET", "hmac-sha256-secret"), ("WEBHOOK_SECRET", "k8s-webhook-secret"),
):  # fmt: skip
    rbe("explanatory-text", name, value)
rbh("explanatory-text", "X-Api-Key", "Issued per workspace by the Admin team")
rb("explanatory-text", "url_query_endpoint", "Workspace Key From Admin Console", U("https://mcp.acme-corp.test/mcp?api_key=Workspace%20Key%20From%20Admin%20Console"))
rba("explanatory-text", "--api-key", "Ask the Platform team for a key")
rb("explanatory-text", "arg_kv", "Set In Your Shell", {"command": "docker", "args": ["run", "-i", "--rm", "-e", "API_TOKEN=Set In Your Shell", "mcp/x:1.0.0"]})
# --- benign: identifiers, settings and names that only look like credential names ---
for name, value in (
    ("API_VERSION", "2024-10-01-preview"), ("TOKEN_VERSION", "v2.14.3"), ("API_KEY_ID", UUID_ID), ("AZURE_TENANT_ID", UUID_ID), ("AZURE_CLIENT_ID", UUID_ID),
    ("AWS_PROFILE", "prod-account-2"), ("USE_TOKEN", "true"), ("REQUIRE_TOKEN", "false"), ("MAX_TOKENS", "4096"), ("TOKEN_LIMIT", "128000"),
    ("SESSION_TOKEN", "1700000000"), ("TOKEN_TTL", "3600"), ("TOKEN_TYPE", "Bearer"), ("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929"),
    ("TOKENIZER", "cl100k_base"), ("OPENAI_MODEL", "gpt-4o-2024-08-06"), ("THEME_COLOR", "#1a2b3c"), ("AWS_REGION", "us-east-1"),
    ("ADMIN_EMAIL", "ops2@example.test"), ("CACHE_KEY", "build-cache-v2-linux"), ("PAT_SCOPE", "repo:read2"), ("MIN_PASS", "12 characters"),
    ("OAUTH_SCOPES", "repo read:org user:email"), ("JWT_ALGORITHM", "RS256"), ("KMS_KEY_ID", UUID_ID), ("VAULT_SECRET", "kv-v2"), ("VAULT_SECRET", "kv-v2-prod"),
    ("K8S_SECRET", "app-secrets-v2"), ("CONTEXT_TOKEN", "200k-context-1"), ("API_KEY_NAME", "prod-key-2"), ("TOKEN_ENDPOINT", "auth2.example.test:8443"),
    ("SECRET_NAME", "app-secret-2"), ("STORAGE_ACCOUNT_KEY_NAME", "key1"), ("PASSWORD_MIN_LENGTH", "12"), ("PASSWORD_POLICY", "min12-upper1-digit1"),
    ("TOKEN_AUDIENCE", "api2.example.test"), ("LOG_PAT", "app-2024*.log"), ("IGNORE_PAT", "^tmp_[0-9]+$"), ("FIRST_PASS", "enabled-v2-mode"),
    ("SESSION_TOKEN", "disabled"), ("USE_API_KEY", "true"), ("AWS_ACCOUNT_ID", "210987654321"), ("CLIENT_ID", "3f2a9c1e7b4d4c6a9e1f"),
    ("SLACK_TEAM_ID", "T01ABCDEFG2"), ("GOOGLE_SERVICE_ACCOUNT", "mcp-reader@acme-prod-1.iam.gserviceaccount.com"), ("KUBE_CONTEXT", "gke_acme-prod-1_europe-west1_main"),
    ("TOKEN_BUDGET", "200000"), ("TOKENS_PER_MINUTE", "400000"), ("MAX_COMPLETION_TOKENS", "16384"), ("TOKENIZERS_PARALLELISM", "false"),
    ("PASSWORD_MANAGER", "1password-cli-v2"), ("TIKTOKEN_ENCODING", "o200k_base"), ("HF_TOKENIZER", "bert-base-uncased"), ("K8S_SECRET", "mcp-server-tls-2024"),
    ("TLS_SECRET", "wildcard-cert-v2"), ("BEARER_TOKEN_ENV_VAR", "GITHUB_TOKEN"), ("API_TOKEN", "MY_SERVICE_TOKEN"), ("GITHUB_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN"),
    ("FASTMCP_SERVER_AUTH", "fastmcp.server.auth.providers.github.GitHubProvider"), ("FASTMCP_SERVER_AUTH_GITHUB_CLIENT_ID", "Ov23liAbCdEfGhIjKlMn"),
    ("FASTMCP_SERVER_AUTH_JWT_AUDIENCE", "mcp-production-api"), ("FASTMCP_SERVER_AUTH_JWT_REQUIRED_SCOPES", "read:data,write:data"),
    ("LOGFIRE_SEND_TO_LOGFIRE", "if-token-present"), ("GOOGLE_CLIENT_ID", "1098765-abc0def1ghi2.apps.googleusercontent.test"),
):  # fmt: skip
    shape = "var-name-as-value" if value in ("GITHUB_TOKEN", "MY_SERVICE_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN") else "identifier-or-setting"
    rbe(shape, name, value)
for name, value in (("anthropic-version", "2023-06-01"), ("X-Api-Key-Id", UUID_ID), ("X-Auth-Type", "oauth2"), ("User-Agent", "acme-agent/2.1 (+https://acme.example.test)"), ("Accept", "application/json, text/event-stream"), ("X-Request-Id", "req_9f8e7d6c5b4a3f2e"), ("anthropic-beta", "mcp-client-2025-04-04"), ("OpenAI-Organization", "org-9f8e7d6c5b4a3f2e1d0c9b8a"), ("X-Api-Version", "2024-10-01"), ("X-Tenant-Id", "acme-prod-01"), ("X-GitHub-Api-Version", "2022-11-28")):
    rbh("identifier-or-setting", name, value)
for flag, value in (
    ("--sort-key", "created_at2"), ("--secret-name", "app-secret-2"), ("--token-env", "GITHUB_TOKEN_2"), ("--api-key-env", "MY_API_KEY_2"), ("--password", "prompt"),
    ("--token-format", "base64url2"), ("--csrf-token", "disabled-in-dev-1"), ("--token-type", "bearer"), ("--secret-key-ref", "db-creds-2"), ("--tiktoken", "cl100k_base"),
    ("--tokenizer", "cl100k_base"), ("--secret", "app-secret-2"), ("--first-pass", "analysis2024"), ("--key", "8f14e45f-ceea-467f-a9f4-1c0c2a7c1b11"),
    ("--ref", "8f14e45fceea467fa9f41c0c2a7c1b1100000000"),
):  # fmt: skip
    rba("var-name-as-value" if flag.endswith("-env") else "identifier-or-setting", flag, value)
rb("identifier-or-setting", "field", "API_TOKEN_2", {"url": URL, "bearer_token_env_var": "API_TOKEN_2"}, "Codex bearer_token_env_var names a variable")
rb("identifier-or-setting", "field", "API_TOKEN_2", {"url": URL, "env_http_headers": {"Authorization": "API_TOKEN_2"}}, "Codex env_http_headers names a variable")
rb("identifier-or-setting", "arg_raw", "@scope/pkg-with-token2@1.2.3", A("@scope/pkg-with-token2@1.2.3"))
rb("package-requirement", "arg_raw", "pkg==1.2.3", {"command": "uvx", "args": ["--from", "pkg==1.2.3", "pkg"]})
add("r259", "credential", "random-under-credential-name", "env", UUID_ID, name="VAULT_SECRET_ID", server=E("VAULT_SECRET_ID", UUID_ID), note="break/tools/fp2.py lists it as an identifier; a Vault AppRole secret id is the credential of the role", author_label="benign")
# --- benign: public material and digests ---
for name, value in (
    ("JWT_PUBLIC_KEY", PUBKEY), ("TLS_CERT", CERT), ("CA_BUNDLE", CERT), ("DEPLOY_KEY_PUB", SSHPUB), ("SSH_PUBLIC_KEY", SSHPUB),
    ("AGE_RECIPIENT", "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"), ("STRIPE_PUBLISHABLE_KEY", "pk_" + "live_" + "51Hq" + "Zq8vLm2pXr7tKw4nBv6y"),
    ("POSTHOG_API_KEY", "phc_" + "Zq8vLm2pXr7tKw4nBv6yCd1fGh3jMn5pQs7uWx9z"), ("R2_ACCESS_KEY_ID", "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"),
):  # fmt: skip
    rbe("public-material", name, value)
for name, value in (("GIT_COMMIT", "9fceb02d0ae598e95dc970b74767f19372d61af8"), ("ADMIN_PASSWORD_HASH", "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234")):
    rbe("hash-not-secret", name, value)
rba("hash-not-secret", "--integrity", "sha512-" + base64.b64encode(bytes(range(64))).decode())
for command, args in (
    ("docker", ["run", "-i", "--rm", "mcp/x@sha256:" + "ab12" * 16]), ("apptainer", ["run", "docker://python:3.12.7-slim-bookworm"]),
    ("apptainer", ["run", "docker://python@sha256:" + "3a7c" * 16]), ("apptainer", ["run", "docker://python:3.12.7-slim-bookworm@sha256:" + "3a7c" * 16]),
    ("apptainer", ["run", "docker://ghcr.io/acme/tool:1.4.2@sha256:" + "3a7c" * 16]), ("apptainer", ["run", "docker://alpine:3.20.3@sha256:" + "3a7c" * 16]),
    ("skopeo", ["copy", "docker://redis:7.4.1-alpine@sha256:" + "9be1" * 16, "oci:cache:redis"]), ("podman", ["run", "--rm", "-i", "docker://node:22.11.0-alpine3.20@sha256:" + "9be1" * 16]),
    ("docker", ["run", "--rm", "-i", "python:3.12.7-slim-bookworm@sha256:" + "3a7c" * 16]), ("apptainer", ["exec", "docker://node:22.11.0-alpine3.20@sha256:" + "b" * 64, "node", "server.js"]),
):  # fmt: skip
    rb("image-digest", "arg_raw", next(a for a in args if "sha256" in a or "docker://" in a), {"command": command, "args": args})
# --- benign: prose that holds a scheme word ---
rb("prose-with-scheme-word", "field", "Send Authorization: Bearer token123456 with each call", {"type": "http", "url": URL, "description": "Send Authorization: Bearer token123456 with each call"}, "description field")
rba("prose-with-scheme-word", "--note", "uses bearer authentication2 only")
rba("prose-with-scheme-word", "--help-text", "Bearer tokens are read from the keychain")
rba("prose-with-scheme-word", "--challenge", "Bearer realm=api1.example.com")
# --- benign: launches of SDK servers that hold no credential (regress/probe/cases5.py) ---
for command, args in (
    ("fastmcp", ["run", "server.py:mcp", "--transport", "stdio"]), ("uv", ["run", "--with", "fastmcp", "fastmcp", "run", "/srv/tools/server.py"]),
    ("uvx", ["--from", "fastmcp==2.12.4", "fastmcp", "run", "server.py"]), ("deno", ["run", "-N", "-R=node_modules", "-W=node_modules", "--node-modules-dir=auto", "jsr:@pydantic/mcp-run-python", "stdio"]),
    ("uv", ["--directory", "/srv/weather", "run", "weather.py"]), ("node", ["/srv/weather/build/index.js"]),
    ("uvx", ["--from", "git+https://github.com/acme/smol-tools@v0.4.2", "smol-tools-mcp"]),
):  # fmt: skip
    rb("plain-launch", "arg_raw", " ".join(args), {"command": command, "args": args}, "regress/probe/cases5.py")

# =====================================================================================
# own: cases neither author is likely to have thought of
# =====================================================================================
def oc(shape: str, position: str, server: dict[str, Any], secret: str, value: str | None = None, note: str = "", **kw) -> None:
    add("own", "credential", shape, position, secret if value is None else value, secret=secret, server=server, note=note, **kw)


def ob(shape: str, position: str, value: str, server: dict[str, Any], note: str = "", **kw) -> None:
    add("own", "benign", shape, position, value, server=server, note=note, **kw)


_UNI = "Zür" + "ich-Gehe" + "imnis-48-äöü"
oc("password-non-ascii", "env", E("DB_PASSWORD", _UNI), _UNI, note="a password with non-ASCII letters")
oc("password-punctuation", "env", E("DB_PASSWORD", PW_DOLLAR), PW_DOLLAR, note="a generated password that holds $ before a letter")
_PW_BT = "g7`Rk2" + "#Lp9wQz4"
oc("password-punctuation", "env", E("DB_PASSWORD", _PW_BT), _PW_BT, note="a generated password that holds a backquote")
_PW_PCT = "aB3%XY%" + "9kLm2Qw7"
oc("password-punctuation", "env", E("DB_PASSWORD", _PW_PCT), _PW_PCT, note="a generated password that holds %XY%")
_PW_DLR0 = "$" + "ecretPa55" + "w0rd-Kx9"
oc("password-punctuation", "env", E("ADMIN_PASSWORD", _PW_DLR0), _PW_DLR0, note="a password that starts with $ and a lower-case letter")
_PW_UP = "PROD_DB_R00T_" + "PW_2024"
oc("password-uppercase-underscore", "env", E("DB_PASSWORD", _PW_UP), _PW_UP, note="a password written in upper case with underscores, as a variable name is")
_PW_DUP = "$" + "PR0D_ROOT_" + "PW_2024"
oc("password-uppercase-underscore", "env", E("DB_PASSWORD", _PW_DUP), _PW_DUP, note="a password that reads as $NAME")
_B64_SLASH = "/" + rnd(39, B64, "aws-secret-slash")
oc("random-starts-with-slash", "env", E("AWS_SECRET_ACCESS_KEY", _B64_SLASH), _B64_SLASH, note="a 40-character base64 secret that starts with /, as 1 in 64 does")
_B64_MID = rnd(20, ALNUM, "aws-s1") + "/" + rnd(9, ALNUM, "aws-s2") + "+" + rnd(9, ALNUM, "aws-s3")
oc("random-under-credential-name", "env", E("AWS_SECRET_ACCESS_KEY", _B64_MID), _B64_MID, note="a 40-character base64 secret with / and + inside")
for name in ("ENCRYPTION_KEY", "SIGNING_KEY", "MASTER_KEY", "HMAC_KEY", "LICENSE_KEY", "COOKIE_SECRET_KEY_BASE", "SESSION_SECRET", "WEBHOOK_SIGNING_SECRET", "DB_PASS_RO", "STRIPE_SECRET_LIVE", "api_token", "authToken", "TOTP_SEED"):
    oc("random-under-key-like-name", "env", E(name, HEX64), HEX64, note="64 hex characters under a name whose credential word does not end it, or a bare KEY")
_TOTP = rnd(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "totp")
oc("random-under-credential-name", "env", E("TOTP_SECRET", _TOTP), _TOTP, note="a base32 TOTP seed")
_TG = rnd(9, string.digits, "tg1") + ":" + "AA" + rnd(33, ALNUM + "_-", "tg2")
oc("vendor-token-unlisted", "env", E("TELEGRAM_BOT_TOKEN", _TG), _TG.split(":")[1], value=_TG, note="a Telegram bot token: digits, a colon and 35 characters")
_AZ = rnd(86, B64, "azkey") + "=="
_AZ_CS = f"DefaultEndpointsProtocol=https;AccountName=acmeprod;AccountKey={_AZ};EndpointSuffix=core.windows.net"
oc("connection-string", "env", E("AZURE_STORAGE_CONNECTION_STRING", _AZ_CS), _AZ, value=_AZ_CS, note="AccountKey= inside a storage connection string")
oc("connection-string", "env", E("STORAGE_CONFIG", _AZ_CS), _AZ, value=_AZ_CS, note="the same connection string under a name that marks no credential")
_SA = json.dumps({"type": "service_account", "project_id": "acme-prod-1", "private_key_id": HEX32[:20], "private_key": PEM + "\n", "client_email": "mcp@acme-prod-1.iam.gserviceaccount.com"})
oc("private-key", "env", E("GOOGLE_CREDENTIALS_JSON", _SA), PEM.split("\n")[1], value=_SA, note="a service-account JSON document with a private key")
oc("private-key", "env", E("GOOGLE_SERVICE_ACCOUNT", b64(_SA)), b64(_SA)[40:120], value=b64(_SA), note="the same document in base64 under a name that marks no credential")
_OJ = json.dumps({"clientId": "mcp-reader", "clientSecret": B62_40})
oc("arg-embedded", "arg_json", A("--oauth", _OJ), B62_40, value=_OJ, note="a JSON argument with a camel-case clientSecret")
oc("arg-embedded", "env", E("OAUTH_CONFIG", _OJ), B62_40, value=_OJ, note="a JSON env value with a camel-case clientSecret")
oc("url-query-token", "url_query_env", E("DATABASE_URL", f"postgres://db.example.test:5432/app?user=app&password={B62_20}&sslmode=require"), B62_20, note="a password as a URL query parameter")
oc("url-password", "url_userinfo_arg", {"command": "uvx", "args": ["--from", f"git+https://x-access-token:{GH2}@github.example.test/acme/tools.git@v1.2.3", "tools-mcp"]}, GH2, note="a token in the user information of a pip VCS requirement")
oc("vendor-token", "arg_positional", A(GH2), GH2, note="a vendor token as a bare positional argument")
oc("vendor-token", "header", H("X-Trace", GH2), GH2, note="a vendor token under a header name that marks no credential")
oc("vendor-token", "env", E("STRIPE_KEY", STRIPE_RK), STRIPE_RK, note="a Stripe restricted key")
oc("vendor-token", "env", E("SENDGRID", SENDGRID), SENDGRID, note="a SendGrid key under a bare name")
oc("vendor-token", "env", E("NODE_AUTH", NPM), NPM, note="an npm token")
oc("vendor-token", "env", E("SLACK", SLACK), SLACK, note="a Slack bot token under a bare name")
oc("vendor-token", "env", E("G", GOOG), GOOG, note="a Google API key under a one-letter name")
oc("vendor-token", "env", E("CLAUDE", ANT), ANT, note="an Anthropic key under a bare name")
_PASSPHRASE = "purple monkey " + "dishwasher lamp"
oc("passphrase-words", "env", E("SSH_PASSPHRASE", _PASSPHRASE), _PASSPHRASE, note="a lower-case passphrase of four words without a digit")
oc("passphrase-words", "arg_flag_sep", A("--passphrase", _PASSPHRASE), _PASSPHRASE, note="the same as an option value")
_HEXMARK = rnd(13, HEX, "hm1") + "abc" + "def" + rnd(13, HEX, "hm2")
oc("random-with-chance-mark", "env", E("API_TOKEN", _HEXMARK), _HEXMARK, note="32 hex characters that hold abcdef by chance")
oc("password-short", "env", E("DB_PASSWORD", "aB3" + "x9Q"), "aB3" + "x9Q", note="a six-character password, under both rules' eight-character floor")
oc("password-short", "env", E("PIN", "48" + "2193"), "48" + "2193", note="a six-digit PIN")
oc("scheme-bearer", "header", H("authorization", "bearer " + B62_40), B62_40, note="lower-case header name and scheme word")
oc("scheme-bearer", "header", H("X-Upstream-Authorization", "Bearer " + B62_40), B62_40, note="a prefixed Authorization header name")
oc("scheme-bearer", "env", E("MCP_HEADERS", "Authorization: Bearer " + B62_40), B62_40, note="a header line as an env value")
oc("scheme-basic", "sh_c", SH(f"exec npx -y mcp-remote@1.0.0 {URL} --header 'Authorization: Basic {b64('svc:' + B62_20)}'"), b64("svc:" + B62_20), note="a Basic header line inside an inline script")
_NETRC = f"machine api.example.test login svc password {B62_20}"
oc("connection-string", "env", E("NETRC", _NETRC), B62_20, value=_NETRC, note="netrc text: the word password, a space and the value")
oc("random-under-credential-name", "arg_kv", {"command": "docker", "args": ["run", "-i", "--rm", "--env", f"API_TOKEN={B62_40}", "-e", "LOG_LEVEL=debug", DIGEST]}, B62_40, note="--env NAME=value beside a benign -e")
oc("random-under-credential-name", "arg_flag_sep", {"command": "npx", "args": [*PIN, "--", "--api-key", B62_40]}, B62_40, note="an option after --")
oc("random-under-credential-name", "arg_flag_sep", {"command": "uvx", "args": ["some-mcp==1.0.0", "--password", B62_20]}, B62_20, note="uvx launch with --password")
oc("random-under-credential-name", "env", {"command": "npx", "args": list(PIN), "env": {"api-key": B62_32}}, B62_32, note="a lower-case env name with a hyphen")
oc("cookie-session", "header", H("Cookie", f"sid={B62_40}; theme=dark"), B62_40, note="a session cookie beside a harmless pair")
oc("random-under-credential-name", "header", H("X-Vault-Token", "hvs." + rnd(90, ALNUM, "hvs")), "hvs." + rnd(90, ALNUM, "hvs"), note="a Vault service token")
oc("random-under-credential-name", "header", H("DD-API-KEY", HEX32B), HEX32B, note="an upper-case vendor header")
oc("random-under-credential-name", "header", H("X-Figma-Token", "fig" + "d_" + rnd(40, ALNUM + "_-", "figd")), "fig" + "d_" + rnd(40, ALNUM + "_-", "figd"), note="a Figma token")

for name, value in (
    ("SSH_AUTH_SOCK", "/run/user/1000/keyring/ssh"), ("GIT_AUTHOR_NAME", "Jane Developer"), ("GIT_AUTHOR_EMAIL", "jane.developer@example.test"),
    ("KEYBOARD_LAYOUT", "us-international"), ("KEYCLOAK_REALM", "engineering-prod"), ("PASSTHROUGH_HEADERS", "x-request-id,x-trace-id"),
    ("TMUX_SESSION", "workspace-main"), ("SESSION_AFFINITY", "ClientIP-sticky"), ("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt"),
    ("NODE_EXTRA_CA_CERTS", "/etc/ssl/corp-ca.pem"), ("CERT_FINGERPRINT", "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"),
    ("SSH_KEY_FINGERPRINT", "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"), ("HEADER_PREFIX", "X-Acme-Internal"), ("COOKIE_NAME", "acme_session_id"),
    ("JWT_AUDIENCE", "mcp-production-api"), ("KEYSPACE", "analytics_prod"), ("PARTITION_KEY", "tenant_id,created_at"), ("PRIMARY_KEY_COLUMN", "customer_id"),
    ("CACHE_KEY_PREFIX", "mcp:v2:prod:"), ("IDEMPOTENCY_KEY_HEADER", "Idempotency-Key"), ("KEY_VAULT_NAME", "acme-prod-keyvault"), ("S3_KEY_PREFIX", "uploads/2024/reports/"),
    ("AUTH_MODE", "passthrough"), ("AUTH_PROVIDER", "github-oauth"), ("AUTH_STRATEGY", "client-credentials"),
    ("AUTHENTICATION_BACKEND", "django.contrib.auth.backends.ModelBackend"), ("TOKEN_ENDPOINT_AUTH_METHOD", "client_secret_basic"),
    ("SECRET_BACKEND", "aws-secrets-manager"), ("SECRETS_PROVIDER", "hashicorp-vault"), ("SECRET_MOUNT_PATH", "/mnt/secrets-store"),
    ("PRIVATE_SUBNET_IDS", "subnet-0abc123def,subnet-0def456abc"), ("PRIVATE_REGISTRY", "registry.internal.example.test"), ("SIGNATURE_ALGORITHM", "ed25519-sha512"),
    ("CREDENTIAL_PROCESS", "aws-vault exec prod --json"), ("AWS_SHARED_CREDENTIALS_FILE", "/home/dev/.aws/credentials"), ("CONNECTION_STRING_NAME", "DefaultConnection"),
    ("BYPASS_PROXY_HOSTS", "localhost,127.0.0.1,.internal"), ("COMPASS_HEADING", "north-north-east"), ("PASSENGER_APP_ENV", "production"),
    ("DSN_NAME", "analytics-warehouse"), ("MONKEY_PATCH_MODE", "disabled-for-tests"), ("TOKENIZER_MODEL", "sentence-transformers/all-MiniLM-L6-v2"),
    ("MODEL_SHA256", "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"), ("PUBLIC_KEY_URL", "https://keys.example.test/.well-known/jwks.json"),
    ("OPENAI_API_KEY_PATH", "/run/secrets/openai"), ("REQUIRE_AUTH", "disabled-in-dev"), ("SESSION_STORE", "redis-cluster"), ("HOTKEY_TOGGLE", "ctrl+shift+space"),
):  # fmt: skip
    ob("noncredential-name", "env", value, E(name, value), "a setting whose name only contains a credential word")
for flag, value in (
    ("--auth-mode", "device-code-flow"), ("--session-name", "nightly-build"), ("--key-file", "/etc/keys/server.pem"), ("--private-key-path", "/etc/keys/server.pem"),
    ("--passive-mode", "enabled-always"), ("--cert-dir", "/etc/ssl/certs"), ("--keyspace", "analytics_prod"), ("--auth-url", "https://auth.example.test/oauth/authorize"),
    ("--token-endpoint", "auth.example.test:8443"), ("--header-prefix", "X-Acme-Internal"), ("--credential-source", "instance-metadata"), ("--password-policy", "min12-upper1-digit1"),
):  # fmt: skip
    ob("noncredential-name", "arg_flag_sep", value, A(flag, value), "an option whose name only contains a credential word")
for name, value in (("X-Session-Affinity", "sticky-route-a"), ("X-Authenticated-Scope", "read-only-reports"), ("X-Forwarded-Authority", "mcp.example.test"), ("X-Cert-Fingerprint", "AA:BB:CC:DD:EE:FF:00:11:22:33"), ("Idempotency-Key", "order-2024-10-01-0001"), ("X-Header-Version", "2024-10-01"), ("Cookie-Policy", "strict-origin")):
    ob("noncredential-name", "header", value, H(name, value), "a header whose name only contains a credential word")
for query in ("session_mode=stateless-readonly", "sort_key=created_at_desc", "authority=readonly-replica", "keyspace=analytics_prod", "auth_type=oauth2-device"):
    ob("noncredential-name", "url_query_endpoint", query.split("=", 1)[1], U(f"{URL}?{query}"), "a query parameter whose name only contains a credential word")
ob("noncredential-name", "arg_kv", "tenant_id,created_at", D("-e", "PARTITION_KEY=tenant_id,created_at"), "a container env assignment that marks no credential")
ob("noncredential-name", "sh_c", "workspace-main", SH("TMUX_SESSION=workspace-main exec npx -y some-mcp@1.0.0"), "an inline assignment that marks no credential")
ob("public-material", "env", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo", E("JWT_VERIFY_KEY", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo"), "a public key body without its PEM lines")
ob("ref-client", "env", "${API_TOKEN}", E("API_TOKEN", " ${API_TOKEN} "), "a reference with white space around it")
ob("ref-client", "header", "Bearer  ${API_TOKEN}", H("Authorization", "Bearer  ${API_TOKEN}"), "a reference after Bearer and two spaces")
ob("ref-client", "header", "bearer ${API_TOKEN}", H("authorization", "bearer ${API_TOKEN}"), "a reference after a lower-case scheme word")
ob("ref-client", "env", "${API_TOKEN}${API_TOKEN_SUFFIX}", E("API_TOKEN", "${API_TOKEN}${API_TOKEN_SUFFIX}"), "two references joined")
ob("ref-client", "env", "${workspaceFolder}/.secrets/token", E("TOKEN_FILE", "${workspaceFolder}/.secrets/token"), "a VS Code path variable")
ob("ref-client", "env", "${userHome}/.config/acme/token", E("API_TOKEN_FILE", "${userHome}/.config/acme/token"), "a VS Code path variable")
ob("ref-in-url", "url_userinfo_env", "$DB_USER:$DB_PASSWORD", E("DATABASE_URL", "postgres://$DB_USER:$DB_PASSWORD@db.example.test:5432/app"), "both parts of the user information are references")
ob("ref-in-url", "url_query_endpoint", "${API_KEY}", U(f"{URL}?api_key=${{API_KEY}}&mode=readonly"), "a reference as a query parameter")
ob("ref-in-url", "url_userinfo_endpoint", "${MCP_USER}:${MCP_PASSWORD}", U("https://${MCP_USER}:${MCP_PASSWORD}@mcp.example.test/mcp"), "both parts of the endpoint user information are references")
ob("ref-cmd-subst", "sh_c", "$(op read op://Private/GitHub/token)", SH('API_TOKEN="$(op read op://Private/GitHub/token)" exec npx -y some-mcp@1.0.0'), "a command substitution that reads a secret store")
ob("ref-cmd-subst", "sh_c", "$(cat ~/.config/acme/token)", SH("exec npx -y some-mcp@1.0.0 --token \"$(cat ~/.config/acme/token)\""), "a command substitution as an option value")
ob("ref-windows", "cmd_c", "%API_TOKEN%", {"command": "cmd", "args": ["/c", "npx -y some-mcp@1.0.0 --token %API_TOKEN%"]}, "cmd expands %NAME% in its own script")
ob("ref-windows", "powershell_c", "$env:API_TOKEN", {"command": "powershell", "args": ["-Command", "npx -y some-mcp@1.0.0 --token $env:API_TOKEN"]}, "PowerShell expands $env:NAME in its own script")

# =====================================================================================
# files: the same value in each client file both collectors read
# =====================================================================================
_FILES = (
    ".mcp.json", "mcp.json", "claude_desktop_config.json", ".cursor/mcp.json", ".claude/mcp.json", ".vscode/mcp.json", ".gemini/settings.json",
    ".roo/mcp.json", ".kiro/settings/mcp.json", ".amazonq/mcp.json", ".windsurf/mcp.json", ".cline/mcp.json", ".codex/config.toml",
    "packages/api/.mcp.json", "config/claude_desktop_config.json", ".windsurf/mcp_config.json", "cline_mcp_settings.json",
)  # fmt: skip
for file in _FILES:
    add("files", "credential", "vendor-token", "env", GH, name="GITHUB_TOKEN", server=E("GITHUB_TOKEN", GH), file=file, note="client file")
    add("files", "credential", "password-wordy", "env", WORDY, name="DB_PASSWORD", server=E("DB_PASSWORD", WORDY), file=file, note="client file")
    add("files", "benign", "ref-client", "env", "${GITHUB_TOKEN}", name="GITHUB_TOKEN", server=E("GITHUB_TOKEN", "${GITHUB_TOKEN}"), file=file, note="client file")
add("files", "credential", "vendor-token", "gemini_server_command", GH, file=".gemini/settings.json", content=json.dumps({"mcpServerCommand": f"npx -y some-mcp@1.0.0 --github-token={GH}"}), note="Gemini mcpServerCommand")
add("files", "benign", "ref-client", "gemini_server_command", "$GITHUB_TOKEN", file=".gemini/settings.json", content=json.dumps({"mcpServerCommand": "npx -y some-mcp@1.0.0 --github-token=$GITHUB_TOKEN"}), note="Gemini mcpServerCommand")
for path in (".claude/settings.json", ".claude/settings.local.json", "packages/app/.claude/settings.json"):
    add("files", "credential", "vendor-token", "claude_settings_env", ANT, name="ANTHROPIC_API_KEY", file=path, content=json.dumps({"env": {"ANTHROPIC_API_KEY": ANT}}), note="Claude Code settings env")
    add("files", "credential", "url-password", "claude_settings_env", T_MIXED, name="HTTPS_PROXY", file=path, content=json.dumps({"env": {"HTTPS_PROXY": f"http://svc:{T_MIXED}@proxy.example.test:8080"}}), note="Claude Code settings env")
    add("files", "benign", "ref-client", "claude_settings_env", "${ANTHROPIC_API_KEY}", name="ANTHROPIC_API_KEY", file=path, content=json.dumps({"env": {"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"}}), note="Claude Code settings env")
add("files", "credential", "vendor-token", "oauth_object", GH, file=".mcp.json", server={"type": "http", "url": URL, "oauth": {"clientId": "mcp-reader", "clientSecret": GH}}, note="oauth object")
add("files", "credential", "random-under-credential-name", "oauth_object", B62_40, file=".mcp.json", server={"type": "http", "url": URL, "oauth": {"clientId": "mcp-reader", "clientSecret": B62_40}}, note="oauth object")
add("files", "credential", "random-under-credential-name", "auth_object", B62_40, file=".mcp.json", server={"type": "http", "url": URL, "auth": {"type": "bearer", "token": B62_40}}, note="auth object")
add("files", "benign", "ref-client", "oauth_object", "${CLIENT_SECRET}", file=".mcp.json", server={"type": "http", "url": URL, "oauth": {"clientId": "mcp-reader", "clientSecret": "${CLIENT_SECRET}"}}, note="oauth object")


# =====================================================================================
# own, second batch: appended after the first run, so that earlier case ids stay as they were
# =====================================================================================
for flag, value in (
    ("--description", "Basic calculator tools"), ("--title", "Token usage dashboard"), ("--mode", "Digest verification enabled"),
    ("--greeting", "Bot ready to help with tickets"), ("--project-name", "Basic Memory Notes"),
):  # fmt: skip
    ob("prose-with-scheme-word", "arg_flag_sep", value, A(flag, value), "prose that starts with an authentication scheme word, under a name that marks nothing")
for name, value in (("APP_TITLE", "Token Counter Service"), ("SERVER_DESCRIPTION", "Basic file tools for the notes folder"), ("WELCOME", "Bearer of good news edition")):
    ob("prose-with-scheme-word", "env", value, E(name, value), "prose that starts with an authentication scheme word, under a name that marks nothing")
ob("prose-with-scheme-word", "header", "Bot acme-crawler/2.1 (+https://acme.example.test/bot)", H("User-Agent", "Bot acme-crawler/2.1 (+https://acme.example.test/bot)"), "a User-Agent that starts with Bot")
for flag, value in (("--note", "Authentication: handled by the gateway"), ("--label", "Session: nightly batch run"), ("--upstream", "auth-service:8443/api/v2"), ("--otel-endpoint", "collector-auth:4318/v1/traces")):
    ob("colon-text-under-plain-name", "arg_flag_sep", value, A(flag, value), "text of the form Word: rest, where the word contains a credential word")
ob("colon-text-under-plain-name", "env", "Keywords: search, retrieval, notes", E("MOTD", "Keywords: search, retrieval, notes"), "text of the form Word: rest")
ob("colon-text-under-plain-name", "env", "token-broker:50051/v1/exchange", E("SIDECAR", "token-broker:50051/v1/exchange"), "host:port/path whose host name contains a credential word")
for image in ("secrets-" + "manager-mcp:1.4.2-alpine3.20", "keycloak-mcp:26.0.5-bookworm", "vault-" + "token-helper:0.9.12-alpine"):
    ob("image-tag", "arg_raw", image, {"command": "docker", "args": ["run", "-i", "--rm", image]}, "an image name that contains a credential word, with its tag")
ob("ref-cmd-subst", "sh_c", "$(gh auth token)", SH("GITHUB_TOKEN=$(gh auth token) exec npx -y @modelcontextprotocol/server-github@2025.4.8"), "the token is read from the gh CLI when the script runs")
ob("ref-client", "sh_c", "${API_TOKEN}", SH("export API_TOKEN=${API_TOKEN}; exec npx -y some-mcp@1.0.0"), "export of a reference")
ob("ref-client", "sh_c", "${API_TOKEN}", SH("NODE_ENV=production API_TOKEN=${API_TOKEN} exec npx -y some-mcp@1.0.0"), "a reference after a first assignment that marks nothing")
ob("ref-client", "sh_c", "$API_TOKEN", SH("exec npx -y some-mcp@1.0.0 --token $API_TOKEN"), "a reference as an option value in a script")
ob("ref-client", "sh_c", "$API_TOKEN", SH('exec npx -y mcp-remote@1.0.0 https://mcp.example.test/mcp --header "Authorization: Bearer $API_TOKEN"'), "a reference in a header line in a script")
ob("noncredential-name", "sh_c", "debug", SH("LOG_LEVEL=debug exec npx -y some-mcp@1.0.0"), "an inline assignment that marks no credential, control")
ob("ref-client", "arg_json", "${API_KEY}", A("--config", json.dumps({"apiKey": "${API_KEY}", "region": "eu-west-1"})), "a reference inside a JSON argument")
ob("ref-client", "command", "$API_TOKEN", {"command": "npx -y some-mcp@1.0.0 --token $API_TOKEN"}, "a reference in a command line in the command field")
oc("random-under-credential-name", "sh_c", SH(f"NODE_ENV=production API_TOKEN={B62_40} exec npx -y some-mcp@1.0.0"), B62_40, note="a literal after a first assignment that marks nothing")
oc("random-under-credential-name", "sh_c", SH(f"GITHUB_TOKEN={B62_40} exec npx -y @modelcontextprotocol/server-github@2025.4.8"), B62_40, note="a literal where the benign twin reads the gh CLI")
oc("private-key", "env", E("GITHUB_APP_PEM", PEM), PEM.split("\n")[1], value=PEM, note="a PEM private key under a name that holds no credential word")
oc("private-key", "arg_flag_sep", A("--signing-pem", PEM), PEM.split("\n")[1], value=PEM, note="a PEM private key as an option value")
oc("private-key", "env", E("TLS_BUNDLE", CERT + "\n" + PEM), PEM.split("\n")[1], value=CERT + "\n" + PEM, note="a certificate followed by its private key")
oc("random-under-credential-name", "arg_kv", D(f"--env=API_TOKEN={B62_40}"), B62_40, note="container --env=NAME=value with a 40-character value")
oc("random-under-credential-name", "arg_kv", {"command": "podman", "args": ["run", "-i", "--rm", f"--env=DB_PASSWORD={WORDY}", DIGEST]}, WORDY, note="podman --env=NAME=value")
oc("url-query-token", "url_query_endpoint", {"type": "sse", "url": f"https://mcp.example.test/sse?token={B62_40}"}, B62_40, note="an SSE endpoint with ?token=")
oc("url-query-token", "url_query_endpoint", {"type": "http", "httpUrl": f"https://mcp.example.test/mcp?access_token={GH2}"}, GH2, note="a Gemini httpUrl with a vendor token in its query")


# =====================================================================================
def toml_server(name: str, server: dict[str, Any]) -> str:
    lines = [f"[mcp_servers.{name}]"]
    tables = []
    for key, value in server.items():
        if isinstance(value, dict):
            tables.append((key, value))
        elif isinstance(value, list):
            lines.append(f"{key} = [" + ", ".join(json.dumps(item) for item in value) + "]")
        else:
            lines.append(f"{key} = {json.dumps(value)}")
    for key, value in tables:
        lines += ["", f"[mcp_servers.{name}.{key}]"]
        lines += [f"{json.dumps(k)} = {json.dumps(v)}" for k, v in value.items()]
    return "\n".join(lines) + "\n"


def file_text(case: dict[str, Any]) -> str:
    if case["content"] is not None:
        return case["content"]
    file, server = case["file"], case["server"]
    if file.endswith(".toml"):
        return toml_server("svc", server)
    if file.endswith(".vscode/mcp.json"):
        return '{\n  // VS Code reads comments.\n  "servers": {"svc": ' + json.dumps(server) + "},\n}"
    return json.dumps({"mcpServers": {"svc": server}}, ensure_ascii=False)


def build(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for case in CASES:
        path = out / case["id"] / case["file"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(file_text(case), encoding="utf-8")
    manifest = [{k: v for k, v in case.items() if k not in ("server", "content")} for case in CASES]
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=0), encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "build":
        build(Path(sys.argv[2]))
        counts: dict[tuple[str, str], int] = {}
        for case in CASES:
            counts[(case["origin"], case["label"])] = counts.get((case["origin"], case["label"]), 0) + 1
        print(len(CASES), "cases")
        for (origin, label), count in sorted(counts.items()):
            print(f"  {origin:7s} {label:10s} {count}")
    else:
        for case in CASES:
            print(case["id"], case["origin"], case["label"], case["shape"], case["position"], case["file"], sep="\t")
