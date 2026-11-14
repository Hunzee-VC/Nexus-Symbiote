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
