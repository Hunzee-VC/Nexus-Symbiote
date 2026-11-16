"""A lockfile record's locator holds no credential, signed parameter or URL from its key."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners import registry
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.registry import RegistryScanner

SHA512 = "sha512-" + base64.b64encode(b"v" * 64).decode()
PUBLIC = "https://registry.yarnpkg.com/openai/-/openai-4.0.0.tgz"
# Assembled at run time so the source holds no token-shaped literal. Every value is fake.
NPM_TOKEN = "".join(("np", "m_", "FAKE" * 9))
KEY_ID = "".join(("AK", "IA", "FAKE" * 4))
PASSWORD = "not-a-real-password"  # noqa: S105 - synthetic fixture
SIGNATURE = "X-Amz-Signature=" + "0f" * 32
CREDENTIAL = "X-Amz-Credential=FAKEKEYID%2F20260101%2Fus-east-1%2Fs3%2Faws4_request"
QUERY = f"{CREDENTIAL}&X-Amz-Expires=300&{SIGNATURE}"
TOKEN_URL = f"https://fakeuser:{NPM_TOKEN}@npm.example.com/openai-4.0.0.tgz?{QUERY}"
SIGNED_URL = f"https://bucket.example.com/zod.tgz?{QUERY}"
CANARIES = (
    NPM_TOKEN,
    "FAKEFAKE",
    PASSWORD,
    "fakeuser",
    "X-Amz",
    "FAKEKEYID",
    "0f0f0f",
    "npm.example.com",
    "bucket.example.com",
    "FAKEPATHSECRET",
)


def _exported(result: ScanResult) -> str:
    return json.dumps(
        [c.model_dump(mode="json") for c in result.components]
        + result.scan_failures
        + result.surfaces_excluded
        + result.surfaces_scanned
    )


def _assert_clean(result: ScanResult) -> None:
    text = _exported(result)
    leaked = [canary for canary in CANARIES if canary in text]
    assert not leaked, leaked


def _bound(result: ScanResult) -> tuple[str, str | None]:
    assert result.scan_failures == [] and result.surfaces_excluded == []
    (component,) = result.components
    claim = component.claims["package_resolution"]
    record = component.properties["lockfile_record"]
    assert claim.locator == record
    return record, component.version


def _project(root: Path, spec: str, lock_name: str, lock: str) -> ScanResult:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({"dependencies": {"openai": spec}}))
    (root / lock_name).write_text(lock, newline="")
    return RegistryScanner().scan(root)


def _yarn_v1(header: str) -> str:
    return (
        "# yarn lockfile v1\n\n\n"
        f"{header}:\n"
        '  version "4.0.0"\n'
        f'  resolved "{PUBLIC}"\n'
        f"  integrity {SHA512}\n"
    )


def _berry(key: str) -> str:
    return (
        "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"
        f"{json.dumps(key)}:\n"
        "  version: 4.0.0\n"
        '  resolution: "openai@npm:4.0.0"\n'
        "  checksum: 10c0/abc\n"
        "  languageName: node\n"
        "  linkType: hard\n"
    )


@pytest.mark.parametrize(
    "header",
    [
        f'"openai@{TOKEN_URL}", openai@4.0.0',
        f'"openai@{TOKEN_URL}", "openai@4.0.0"',
        # JSON escapes that Yarn 1 decodes: the selector it reads holds the URL.
        '"openai@' + TOKEN_URL.replace("/", "\\/") + '", openai@4.0.0',
        '"openai@' + TOKEN_URL.replace("@", "\\u0040", 2) + '", openai@4.0.0',
        f'"openai@git+https://x-access-token:{PASSWORD}@github.example/o/r.git", openai@4.0.0',
        f'"openai@{SIGNED_URL}", openai@4.0.0',
        f'"openai@https://fakeuser:{PASSWORD}@npm.example.com/FAKEPATHSECRET/o.tgz", openai@4.0.0',
        # A selector of another package listed first in the stanza.
        f'"mcp-helper@{TOKEN_URL}", openai@4.0.0',
        f'"openai@^4.0.0", "openai@{TOKEN_URL}", openai@4.0.0',
        f'openai@4.0.0, "openai@{TOKEN_URL}"',
    ],
    ids=[
        "url-first",
        "url-first-quoted-spec",
        "escaped-slashes",
        "escaped-at",
        "git-userinfo",
        "signed-query",
        "path-secret",
        "other-package-first",
        "url-middle",
        "url-last",
    ],
)
def test_a_yarn_v1_locator_is_the_selector_package_json_matched(tmp_path, header):
    result = _project(tmp_path, "4.0.0", "yarn.lock", _yarn_v1(header))
    record, version = _bound(result)
    assert (record, version) == ("yarn.lock#/openai@4.0.0", "4.0.0")
    _assert_clean(result)


@pytest.mark.parametrize(
    "key",
    [
        f"openai@{TOKEN_URL}, openai@npm:4.0.0",
        f"openai@npm:4.0.0, openai@{TOKEN_URL}",
        f"openai@https://x-access-token:{PASSWORD}@github.example/o/r.git#commit=abc,"
        " openai@npm:4.0.0",
        f"openai@{SIGNED_URL}, openai@npm:^4.0.0, openai@npm:4.0.0",
    ],
    ids=["url-first", "url-last", "git-userinfo", "url-and-range-first"],
)
def test_a_yarn_berry_locator_is_the_descriptor_package_json_matched(tmp_path, key):
    result = _project(tmp_path, "4.0.0", "yarn.lock", _berry(key))
    record, version = _bound(result)
    assert (record, version) == ("yarn.lock#/openai@npm:4.0.0", "4.0.0")
    _assert_clean(result)


@pytest.mark.parametrize(
    ("header", "spec", "expected"),
    [
        ("openai@4.0.0", "4.0.0", "openai@4.0.0"),
        ('"openai@^4.0.0", "openai@4.0.0"', "4.0.0", "openai@4.0.0"),
        ('"openai@^4.0.0", "openai@4.0.0"', "^4.0.0", "openai@^4.0.0"),
        ('"openai@^4.0.0", "openai@~4.0.0"', "~4.0.0", "openai@~04.0.0"),
        ('"openai@npm:4.0.0"', "4.0.0", "openai@npm:4.0.0"),
        ('"openai@~4.0.0", "openai@>=4.0.0 <5"', ">=4.0.0 <5", "openai@>=4.0.0 <5"),
    ],
)
def test_an_ordinary_yarn_selector_is_kept_as_its_pointer(tmp_path, header, spec, expected):
    result = _project(tmp_path, spec, "yarn.lock", _yarn_v1(header))
    record, _ = _bound(result)
    assert record == "yarn.lock#/" + expected


def _pnpm_v6(peers: str) -> str:
    key = json.dumps(f"/openai@4.0.0{peers}")
    return (
        "lockfileVersion: '6.0'\n"
        "dependencies:\n"
        "  openai:\n"
        "    specifier: 4.0.0\n"
        f"    version: {json.dumps('4.0.0' + peers)}\n"
        "packages:\n"
        f"  {key}:\n"
        f"    resolution: {{integrity: {SHA512}}}\n"
    )


def _pnpm_unlisted(peers: str) -> str:
    """A lockfile with no root importer, so the record is found by its key and, since
    pnpm writes one in every lockfile format, is stale and not bound."""
    return (
        "lockfileVersion: '5.4'\n"
        "packages:\n"
        f"  {json.dumps('openai@4.0.0' + peers)}:\n"
        f"    resolution: {{integrity: {SHA512}}}\n"
    )


def _pnpm_slash(peers: str) -> str:
    """A lockfile with no root importer whose key spells the version after a slash."""
    return (
        "lockfileVersion: '5.4'\n"
        "packages:\n"
        f"  {json.dumps('/openai/4.0.0' + peers)}:\n"
        f"    resolution: {{integrity: {SHA512}}}\n"
    )


UNPLAIN_PEERS = {
    "token-url": f"(zod@{TOKEN_URL})",
    "signed-url": f"(zod@{SIGNED_URL})",
    "plain-then-url": f"(react@18.2.0)(zod@{TOKEN_URL})",
    "url-then-plain": f"(zod@{TOKEN_URL})(react@18.2.0)",
    "nested-url": f"(langchain@0.1.0(zod@{TOKEN_URL}))",
    "parens-in-url": f"(zod@https://bucket.example.com/a(b)c.tgz?{SIGNATURE})",
    "upper-scheme": f"(zod@HTTPS://fakeuser:{PASSWORD}@npm.example.com/z.tgz)",
    "encoded-slashes": f"(zod@https:%2F%2Ffakeuser:{PASSWORD}@npm.example.com%2Fz.tgz)",
    "schemeless-path": "(zod@npm.example.com/FAKEPATHSECRET/zod.tgz)",
    "file-path": "(zod@file:../FAKEPATHSECRET/zod)",
    "link-path": "(zod@link:../FAKEPATHSECRET)",
    "git-host": f"(zod@git+https://fakeuser:{PASSWORD}@github.example/o/r.git)",
    "token-name": f"({NPM_TOKEN}@1.0.0)",
    "token-prerelease": f"(zod@1.0.0-{KEY_ID})",
    "unbalanced": f"(zod@1.0.0(react@18.2.0)fakeuser:{PASSWORD}",
    "unclosed-group": "(react-dom@18.2.0(react@18.2.0)",
    "close-before-open": "(react@18.2.0))(react-dom@18.2.0(react@18.2.0)",
    "text-after": f"(zod@1.0.0)fakeuser:{PASSWORD}",
    # In a peer's group: a hash on the package itself unbinds it (see below).
    "patch-hash-with-text": f"(zod@1.0.0(patch_hash=abc fakeuser:{PASSWORD}))",
}


@pytest.mark.parametrize("peers", list(UNPLAIN_PEERS.values()), ids=list(UNPLAIN_PEERS))
@pytest.mark.parametrize(
    ("lock", "pointer"),
    [(_pnpm_v6, "~1openai@4.0.0(***)")],
    ids=["importer"],
)
def test_a_pnpm_key_whose_peers_hold_other_text_is_recorded_redacted(
    tmp_path, peers, lock, pointer
):
    result = _project(tmp_path, "4.0.0", "pnpm-lock.yaml", lock(peers))
    record, version = _bound(result)
    assert (record, version) == ("pnpm-lock.yaml#/packages/" + pointer, "4.0.0")
    _assert_clean(result)


@pytest.mark.parametrize("peers", list(UNPLAIN_PEERS.values()), ids=list(UNPLAIN_PEERS))
@pytest.mark.parametrize("lock", [_pnpm_unlisted, _pnpm_slash], ids=["unlisted", "slash"])
def test_a_pnpm_key_found_by_name_binds_nothing_and_leaks_nothing(tmp_path, peers, lock):
    result = _project(tmp_path, "4.0.0", "pnpm-lock.yaml", lock(peers))
    # pnpm writes a root importer in every lockfile format, so the record is stale.
    assert result.scan_failures == [
        "pnpm-lock.yaml: selected package version disagrees with package.json"
    ]
    assert result.surfaces_excluded == []
    (component,) = result.components
    assert "lockfile_record" not in component.properties
    assert "package_resolution" not in component.claims
    _assert_clean(result)


@pytest.mark.parametrize(
    "lock", [_pnpm_v6, _pnpm_unlisted, _pnpm_slash], ids=["importer", "unlisted", "slash"]
)
def test_a_pnpm_key_patched_with_text_is_unbound_and_leaks_nothing(tmp_path, lock):
    result = _project(
        tmp_path, "4.0.0", "pnpm-lock.yaml", lock(f"(patch_hash=abc fakeuser:{PASSWORD})")
    )
    assert "pnpm-lock.yaml: patched dependency is unverified" in result.surfaces_excluded
    (component,) = result.components
    assert "lockfile_record" not in component.properties
    _assert_clean(result)


PLAIN_PEERS = [
    "",
    "(react@18.2.0)",
    "(@types/react@18.2.0)(react@18.2.0)",
    "(react-dom@18.2.0(react@18.2.0))(react@18.2.0)",
    "(typescript@5.4.0-beta.1+build.5)",
    # A peer's own patch hash: one on the package itself patches what pnpm installs.
    "(react-dom@18.2.0(patch_hash=jcn7aabp3ugwbyzlpr6lvbvnju)(react@18.2.0))",
    "(JSONStream@1.3.5)",
    "(eslint-token@1.0.0)",
]


@pytest.mark.parametrize("peers", PLAIN_PEERS)
@pytest.mark.parametrize(
    ("lock", "head"),
    [(_pnpm_v6, "~1openai@4.0.0")],
    ids=["importer"],
)
def test_a_pnpm_key_of_packages_and_exact_versions_is_kept_as_its_pointer(
    tmp_path, peers, lock, head
):
    result = _project(tmp_path, "4.0.0", "pnpm-lock.yaml", lock(peers))
    record, _ = _bound(result)
    expected = head + peers.replace("~", "~0").replace("/", "~1")
    assert record == "pnpm-lock.yaml#/packages/" + expected


@pytest.mark.parametrize("peers", [*PLAIN_PEERS, "(patch_hash=jcn7aabp3ugwbyzlpr6lvbvnju)"])
def test_plain_pnpm_peers(peers):
    assert registry._plain_pnpm_peers(peers)


@pytest.mark.parametrize(
    "peers",
    [
        *UNPLAIN_PEERS.values(),
        "()",
        "(zod)",
        "(zod@)",
        "(@zod@1.0.0)",
        "(zod@1.0)",
        "(zod@1.0.0",
        "zod@1.0.0)",
        "(zod@1.0.0))",
        "(zod@1.0.0)(",
        "(patch_hash=abc(react@18.2.0))",
        "(zod@1.0.0 )",
        "(zod@1.0.0)\n",
    ],
)
def test_other_pnpm_peers_are_not_plain(peers):
    assert not registry._plain_pnpm_peers(peers)


def test_an_npm_lockfile_key_is_recorded_as_the_inventory_redacts_the_name(tmp_path):
    name = "mcp-" + NPM_TOKEN
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {name: "1.0.0"}}))
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {name: "1.0.0"}},
            f"node_modules/{name}": {"version": "1.0.0", "integrity": SHA512},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    result = RegistryScanner().scan(tmp_path)
    record, version = _bound(result)
    (component,) = result.components
    assert component.name == "mcp-***"
    assert (record, version) == ("package-lock.json#/packages/node_modules~1mcp-***", "1.0.0")
    _assert_clean(result)


def test_an_ordinary_npm_lockfile_key_is_kept_as_its_pointer(tmp_path):
    name = "@modelcontextprotocol/sdk"
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {name: "1.0.0"}}))
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {name: "1.0.0"}},
            f"node_modules/{name}": {"version": "1.0.0", "integrity": SHA512},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    record, _ = _bound(RegistryScanner().scan(tmp_path))
    assert record == "package-lock.json#/packages/node_modules~1@modelcontextprotocol~1sdk"


@pytest.mark.parametrize("fmt", ["json", "cyclonedx", "spdx", "sarif"])
@pytest.mark.parametrize(
    ("lock_name", "lock"),
    [
        ("yarn.lock", _yarn_v1(f'"openai@{TOKEN_URL}", openai@4.0.0')),
        ("yarn.lock", _berry(f"openai@{TOKEN_URL}, openai@npm:4.0.0")),
        ("pnpm-lock.yaml", _pnpm_v6(f"(zod@{TOKEN_URL})")),
        ("pnpm-lock.yaml", _pnpm_unlisted(f"(zod@{SIGNED_URL})")),
    ],
    ids=["yarn-v1", "yarn-berry", "pnpm-importer", "pnpm-unlisted"],
)
def test_no_export_carries_a_lockfile_key_credential(tmp_path, fmt, lock_name, lock):
    project = tmp_path / "project"
    _project(project, "4.0.0", lock_name, lock)
    out = tmp_path / f"out.{fmt}"
    invoked = CliRunner().invoke(
        main,
        ["scan", str(project), "--no-project-policy", "--report-only", "-f", fmt, "-o", str(out)],
    )
    assert invoked.exit_code == 0, invoked.output
    text = out.read_text(encoding="utf-8") + invoked.output
    leaked = [canary for canary in CANARIES if canary in text]
    assert not leaked, leaked
