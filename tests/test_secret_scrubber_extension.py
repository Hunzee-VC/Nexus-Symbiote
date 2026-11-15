"""A scrubber extended with a server's own values behaves as one built from the union."""

from __future__ import annotations

from nexus_symbiote.utils.secrets import REDACTED, SecretScrubber

FILE_VALUES = ["shared-credential-0001", "long-shared-credential-value-0002", "abcdefgh"]
OWN_VALUES = ["own-credential-0003", "abcdefgh", "abcdefghijkl"]


def test_extension_orders_and_scrubs_as_the_union():
    base = SecretScrubber(FILE_VALUES)
    extended = base.extended(OWN_VALUES)
    union = SecretScrubber([*FILE_VALUES, *OWN_VALUES])
    assert extended._values == union._values
    assert extended._shortest == union._shortest == 8
    assert len(extended) == len(union) == 5
    text = "x abcdefghijkl y long-shared-credential-value-0002 z own-credential-0003"
    assert extended.scrub(text) == union.scrub(text)
    assert "abcdefgh" not in extended.scrub(text)
    assert extended.scrub(text).count(REDACTED) == 3
    assert extended.contains("own-credential-0003") and not base.contains("own-credential-0003")


def test_extension_without_new_values_returns_the_same_scrubber():
    base = SecretScrubber(FILE_VALUES)
    assert base.extended(["abcdefgh", ""]) is base
    assert base.extended([]) is base


def test_extending_an_empty_scrubber_prepares_the_values():
    extended = SecretScrubber().extended(OWN_VALUES)
    assert extended._values == SecretScrubber(OWN_VALUES)._values
    assert extended.scrub("own-credential-0003") == REDACTED
