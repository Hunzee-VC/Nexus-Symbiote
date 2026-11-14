"""yarn.lock is read as Yarn reads it, or not at all."""

import base64
import json

import pytest

from nexus_symbiote.scanners.registry import RegistryScanner

SHA512 = "sha512-" + base64.b64encode(b"w" * 64).decode()
PUBLIC = "https://registry.yarnpkg.com/openai/-/openai-4.0.0.tgz"
EVIL = "https://evil.example/openai.tgz"
UNREAD = ["yarn.lock: invalid or unsupported lockfile"]
AMBIGUOUS = ["yarn.lock: multiple package resolutions for openai are ambiguous"]


def scan(tmp_path, lock):
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"4.0.0"}}')
    (tmp_path / "yarn.lock").write_text(lock, newline="")
    result = RegistryScanner().scan(tmp_path)
    (comp,) = result.components
    return result, comp


def stanza(header, resolved, integrity=True):
    lines = [f"{header}:", '  version "4.0.0"', f'  resolved "{resolved}"']
    if integrity:
        lines.append(f"  integrity {SHA512}")
    return "\n".join(lines) + "\n"


def assert_unbound(comp):
    assert comp.package_url is None and comp.registry_uri is None
    assert "package_resolution" not in comp.claims


@pytest.mark.parametrize(
    "lock",
    [
        # Yarn 1 keeps the last stanza of a repeated selector and installs from it.
        stanza("openai@4.0.0", PUBLIC) + "\n" + stanza("openai@4.0.0", EVIL, integrity=False),
        stanza("openai@4.0.0", EVIL, integrity=False) + "\n" + stanza("openai@4.0.0", PUBLIC),
        stanza('"openai@4.0.0", "openai@^4.0.0"', PUBLIC)
        + "\n"
        + stanza('"openai@4.0.0"', EVIL, integrity=False),
        stanza("openai@4.0.0", PUBLIC) + "\n" + stanza('"openai@4.0.0"', EVIL),
        stanza("openai@4.0.0", PUBLIC) + "\n" + stanza('"\\u006fpenai@4.0.0"', EVIL),
    ],
    ids=["legit-first", "legit-last", "multi-selector", "quoted-repeat", "escaped-repeat"],
)
def test_a_selector_in_more_than_one_stanza_binds_neither(tmp_path, lock):
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert result.scan_failures == []
    assert result.surfaces_excluded == AMBIGUOUS
    assert_unbound(comp)


def test_a_repeated_selector_of_another_spec_does_not_block_the_declared_one(tmp_path):
    lock = (
        stanza("openai@4.0.0", PUBLIC)
        + "\n"
        + stanza("openai@^3.0.0", PUBLIC)
        + "\n"
        + stanza("openai@^3.0.0", PUBLIC)
    )
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"


@pytest.mark.parametrize(
    "other",
    [
        stanza("openai@^4.0.0", EVIL, integrity=False),
        stanza("openai@^4.0.0", EVIL),
        stanza("openai@^4.0.0", PUBLIC, integrity=False),
        stanza('"openai@npm:^4.0.0"', EVIL),
    ],
    ids=["evil-url", "evil-url-with-integrity", "no-integrity", "npm-range"],
)
def test_another_range_with_the_same_version_and_another_source_binds_neither(tmp_path, other):
    # Yarn 1 reuses the first pattern it resolved with that version, so a dependency
    # earlier in package.json on `openai@^4.0.0` makes it install the other stanza.
    for lock in (
        stanza("openai@4.0.0", PUBLIC) + "\n" + other,
        other + "\n" + stanza("openai@4.0.0", PUBLIC),
    ):
        result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
        assert result.scan_failures == []
        assert result.surfaces_excluded == AMBIGUOUS
        assert_unbound(comp)


def test_another_range_with_another_version_does_not_block_the_declared_one(tmp_path):
    lock = (
        stanza("openai@4.0.0", PUBLIC)
        + "\n"
        + stanza("openai@^4.0.0", EVIL).replace('"4.0.0"', '"4.1.0"')
    )
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"
    assert comp.registry_uri == "https://registry.yarnpkg.com"


def test_a_yarn_1_checksum_is_not_integrity(tmp_path):
    lock = stanza("openai@4.0.0", PUBLIC, integrity=False) + '  checksum "x"\n'
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert comp.package_url == "pkg:npm/openai@4.0.0"
    assert [r.category for r in comp.risks] == ["missing_lockfile_integrity"]


@pytest.mark.parametrize(
    "lock",
    [
        # Yarn decodes quoted keys and selectors as JSON strings.
        f'openai@4.0.0:\n  version "4.0.0"\n  "resolved" "{EVIL}"\n  integrity {SHA512}\n',
        f'openai@4.0.0:\n  "version" "4.0.0"\n  "resolved": "{EVIL}"\n',
        f'"\\u006fpenai@4.0.0":\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'"openai@^3.0.0", "openai@4.0.0":\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'openai@^3.0.0,openai@4.0.0:\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        'openai@4.0.0:\n  version "4.0.0"\n  resolved "https:\\/\\/evil.example/openai.tgz"\n',
        f'openai@4.0.0:\r\n  version "4.0.0"\r\n  resolved "{EVIL}"\r\n',
    ],
    ids=[
        "quoted-key",
        "quoted-keys-colon",
        "escaped-selector",
        "quoted-list",
        "unspaced-list",
        "escaped-value",
        "crlf",
    ],
)
def test_the_record_yarn_installs_is_the_one_bound(tmp_path, lock):
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.registry_uri == "https://evil.example"
    assert comp.package_url == "pkg:npm/openai@4.0.0?repository_url=https://evil.example"
    assert "registry_origin" in [r.category for r in comp.risks]


@pytest.mark.parametrize(
    "lock",
    [
        # Each is a line the tokenizer reads differently, or not at all.
        f"openai@4.0.0:\n  version '4.0.0'\n  resolved \"{EVIL}\"\n",
        f'openai@4.0.0:\n  version "4.0.0"\n\t"resolved" "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n   resolved "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n    resolved "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n\n  resolved "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n# c\n  resolved "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  # c\n  resolved "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n    \n  resolved "{EVIL}"\n',
        f'openai@4.0.0:\n  version 4.0.0\n  resolved "{EVIL}"\n',
        'openai@4.0.0:\n  version "4.0.0"\n  resolved "https://evil.example\\@x/o.tgz"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  resolved "{EVIL}" "x"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  resolved "{EVIL}" # c\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  resolved\n  integrity {SHA512}\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  resolved, integrity "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  "" "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  resolved:\n    url "{EVIL}"\n',
        f'"openai@4.0.0:\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'@scope/x@1, openai@4.0.0:\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'" openai@4.0.0":\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'openai@4.0.0 "x":\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  resolved "{EVIL}"\u2028x\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  truex "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  resolved:"{EVIL}"\n',
        # Yarn 1 ends a line at a lone CR and reads the next line as a top-level key.
        stanza("openai@4.0.0", PUBLIC)
        + "\nzzpad@1.0.0:\r  openai@4.0.0:\n"
        + f'  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'zzpad@1.0.0:\r  openai@4.0.0:\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'openai@4.0.0:\r  version "4.0.0"\r  resolved "{EVIL}"\r',
    ],
    ids=[
        "single-quote",
        "tab",
        "odd-indent",
        "over-indent",
        "blank-then-field",
        "comment-then-field",
        "indented-comment",
        "whitespace-line",
        "bare-dotted-number",
        "invalid-escape",
        "extra-token",
        "trailing-comment",
        "key-without-value",
        "key-list",
        "empty-key",
        "object-field",
        "unterminated-header",
        "bare-at-selector",
        "padded-selector",
        "header-value",
        "line-separator",
        "boolean-prefix",
        "unspaced-colon",
        "lone-cr-hides-repeat",
        "lone-cr-hides-stanza",
        "lone-cr-only",
    ],
)
def test_a_line_the_parser_does_not_understand_fails_the_lockfile(tmp_path, lock):
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert result.scan_failures == UNREAD
    assert_unbound(comp)


def test_an_ordinary_yarn_lockfile_with_dependencies_is_bound(tmp_path):
    lock = (
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n"
        "# yarn lockfile v1\n\n\n"
        '"@types/node@*", "@types/node@^18.0.0":\n'
        '  version "18.19.0"\n'
        '  resolved "https://registry.yarnpkg.com/@types/node/-/node-18.19.0.tgz"\n'
        f"  integrity {SHA512}\n"
        "  dependencies:\n"
        '    undici-types "~5.26.4"\n\n'
        "openai@4.0.0:\n"
        '  version "4.0.0"\n'
        f'  resolved "{PUBLIC}#0123abc"\n'
        f"  integrity {SHA512}\n"
        "  dependencies:\n"
        '    "@types/node" "^18.0.0"\n'
        '    abort-controller "^3.0.0"\n'
        "  optionalDependencies:\n"
        '    fsevents "~2.3.2"\n'
    )
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"
    assert comp.properties["lockfile_record"] == "yarn.lock#/openai@4.0.0"


def test_a_berry_lockfile_with_nested_metadata_is_bound(tmp_path):
    lock = (
        '# This file is generated by running "yarn install" inside your project.\n'
        "# Manual changes might be lost - proceed with caution!\n\n"
        "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"
        '"openai@npm:4.0.0, openai@npm:^4.0.0":\n'
        "  version: 4.0.0\n"
        '  resolution: "openai@npm:4.0.0"\n'
        "  dependencies:\n"
        '    "@types/node": "npm:^18.11.18"\n'
        "  dependenciesMeta:\n"
        "    fsevents:\n"
        "      optional: true\n"
        "  checksum: 10c0/" + "ab" * 16 + "\n"
        "  languageName: node\n"
        "  linkType: hard\n"
    )
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"


BERRY_HEAD = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"
BERRY_OPENAI = (
    '"openai@npm:4.0.0":\n  version: 4.0.0\n  resolution: "openai@npm:4.0.0"\n'
    "  checksum: 10c0/abab\n  languageName: node\n  linkType: hard\n"
)


@pytest.mark.parametrize(
    "extra",
    [
        '"use-sync-external-store@npm:^1.2.0":\n  version: 1.2.0\n'
        "  peerDependencies:\n    react: ^16.8.0 || ^17.0.0 || ^18.0.0\n",
        '"@rollup/rollup-linux-x64-gnu@npm:4.24.0":\n  version: 4.24.0\n'
        "  conditions: os=linux & cpu=x64 & libc=glibc\n",
        '"x@npm:1.0.0":\n  version: 1.0.0\n  peerDependencies:\n    react: ">=16"\n',
    ],
    ids=["peer-range", "conditions", "quoted-range"],
)
def test_berry_plain_scalars_with_spaces_are_read(tmp_path, extra):
    result, comp = scan(tmp_path, BERRY_HEAD + BERRY_OPENAI + "\n" + extra)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"


@pytest.mark.parametrize(
    "line",
    [
        # Each is a value a YAML reader reads differently, or not as one string.
        "    react: >=16",
        "    react: ^16 # c",
        "    react: a: b",
        "    react: ^16 ",
        "    react: [16]",
        "    react: |16",
        "    react: ",
        "    react:^16",
    ],
    ids=[
        "block-indicator",
        "comment",
        "nested-colon",
        "trailing-space",
        "flow",
        "pipe",
        "empty",
        "unspaced",
    ],
)
def test_a_berry_value_yaml_reads_otherwise_fails_the_lockfile(tmp_path, line):
    extra = '"x@npm:1.0.0":\n  version: 1.0.0\n  peerDependencies:\n' + line + "\n"
    result, comp = scan(tmp_path, BERRY_HEAD + BERRY_OPENAI + "\n" + extra)
    assert result.scan_failures == UNREAD
    assert_unbound(comp)


@pytest.mark.parametrize(
    "lock",
    [
        # Without __metadata, Yarn 1 reads a quoted list as one selector.
        f'"openai@^3.0.0, openai@4.0.0":\n  version "4.0.0"\n  resolved "{EVIL}"\n',
    ],
)
def test_a_quoted_comma_list_is_one_yarn_v1_selector(tmp_path, lock):
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.registry_uri is None and comp.source_path == "package.json"


def test_a_berry_field_line_without_a_colon_fails_the_lockfile(tmp_path):
    lock = (
        "__metadata:\n  version: 8\n\n"
        '"openai@npm:4.0.0":\n  version: 4.0.0\n  resolution "openai@npm:4.0.0"\n'
    )
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == UNREAD
    assert_unbound(comp)


def test_a_json_string_is_decoded_as_json(tmp_path):
    header = json.dumps("openai@4.0.0")
    lock = f'{header}:\n  version "4.0.0"\n  resolved {json.dumps(PUBLIC)}\n'
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"


# The first stanza as one folded YAML plain scalar: the key a string alias points to.
# Its `uid` gives the alias target a package name, which the version check alone refuses.
FOLDED = json.dumps(f'version "4.0.0" resolved "{PUBLIC}" integrity {SHA512} uid "x@y"')


@pytest.mark.parametrize(
    "comment",
    ["# yarn lockfile v9", "#yarn lockfile v2", "#   yarn lockfile v0010  "],
)
def test_a_version_comment_above_1_fails_the_lockfile(tmp_path, comment):
    # Yarn 1 refuses it and re-reads the file as YAML, where the first stanza is a
    # string that aliases the second stanza's key.
    lock = (
        stanza("openai@4.0.0", PUBLIC)
        + '  uid "x@y"\n'
        + f"\n{comment}\n\n{FOLDED}:\n"
        + f'  version: "4.0.0"\n  resolved: "{EVIL}"\n'
    )
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert result.scan_failures == UNREAD
    assert_unbound(comp)


@pytest.mark.parametrize("comment", ["# yarn lockfile v1", "# yarn lockfile v0", "# lockfile v9"])
def test_a_version_comment_yarn_accepts_is_read(tmp_path, comment):
    result, comp = scan(tmp_path, f"{comment}\n\n" + stanza("openai@4.0.0", PUBLIC))
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"


@pytest.mark.parametrize("header", ["foo", '"version \\"4.0.0\\""', '"@scope"', "openai@4.0.0, x"])
def test_a_selector_without_a_package_name_fails_the_lockfile(tmp_path, header):
    lock = stanza("openai@4.0.0", PUBLIC) + "\n" + stanza(header, EVIL)
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert result.scan_failures == UNREAD
    assert_unbound(comp)


@pytest.mark.parametrize(
    "lock",
    [
        # Yarn 1 looks up `openai@4.0.0` as package.json spells it.
        "# yarn lockfile v1\n\n"
        + stanza('"openai@npm:4.0.0"', PUBLIC)
        + "\n"
        + stanza("openai@4.0.0", EVIL, integrity=False),
        "# yarn lockfile v1\n\n"
        + stanza("openai@4.0.0", PUBLIC)
        + "\n"
        + stanza('"openai@npm:4.0.0"', EVIL, integrity=False),
        # Berry normalizes the declared `4.0.0` to `openai@npm:4.0.0`.
        BERRY_HEAD
        + '"openai@4.0.0":\n  version: 4.0.0\n  resolution: "openai@npm:4.0.0"\n'
        + "  checksum: 10c0/abab\n  languageName: node\n  linkType: hard\n\n"
        + '"openai@npm:4.0.0":\n  version: 4.0.0\n'
        + f'  resolution: "openai@{EVIL}"\n  languageName: node\n  linkType: hard\n',
    ],
    ids=["v1-npm-first", "v1-bare-first", "berry-bare-first"],
)
def test_a_spec_and_its_npm_spelling_in_two_stanzas_bind_neither(tmp_path, lock):
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == []
    assert result.surfaces_excluded == AMBIGUOUS
    assert_unbound(comp)


def test_one_stanza_with_a_spec_and_its_npm_spelling_is_bound(tmp_path):
    lock = stanza('"openai@4.0.0", "openai@npm:4.0.0"', PUBLIC)
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"
