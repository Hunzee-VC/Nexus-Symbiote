"""The bounded ONNX and GGUF readers follow the formats and fail closed on what they cannot read."""

from __future__ import annotations

import io

import pytest

from nexus_symbiote.utils.model_formats import (
    GGUF_LIMIT,
    GGUF_UNREADABLE,
    ONNX_LIMIT,
    ONNX_UNEXPLAINED,
    ONNX_UNREADABLE,
    FormatError,
    InspectionBudget,
    gguf_metadata,
    onnx_external_data,
    template_escape_markers,
)


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        low, value = value & 0x7F, value >> 7
        out.append(low | (0x80 if value else 0))
        if not value:
            return bytes(out)


def tag(number: int, wire: int) -> bytes:
    return varint(number << 3 | wire)


def message(number: int, payload: bytes) -> bytes:
    return tag(number, 2) + varint(len(payload)) + payload


def number(field: int, value: int) -> bytes:
    return tag(field, 0) + varint(value)


def entry(key: bytes, value: bytes) -> bytes:
    return message(1, key) + message(2, value)


def external(location: bytes) -> bytes:
    """A TensorProto stored as EXTERNAL at ``location``."""
    return message(8, b"w") + message(13, entry(b"location", location)) + number(14, 1)


def graph(*fields: bytes) -> bytes:
    return number(1, 8) + message(7, b"".join(fields))


def read(data: bytes) -> tuple[str, ...]:
    return onnx_external_data(io.BytesIO(data).read)


def test_tensors_in_attributes_subgraphs_sparse_and_functions_are_followed():
    attribute = message(5, external(b"attribute.bin"))
    subgraph = message(6, message(5, external(b"subgraph.bin")))
    node = message(1, message(5, attribute) + message(5, subgraph))
    sparse = message(15, message(1, external(b"sparse.bin")))
    function = message(25, message(7, message(5, message(10, external(b"function.bin")))))
    data = graph(node, sparse) + function
    assert read(data) == ("attribute.bin", "function.bin", "sparse.bin", "subgraph.bin")


def test_fixed_width_fields_and_groups_are_skipped_like_protobuf_does():
    group = tag(30, 3) + number(1, 5) + tag(31, 3) + tag(31, 4) + tag(30, 4)
    fixed = tag(40, 1) + b"\0" * 8 + tag(41, 5) + b"\0" * 4
    assert read(graph(group, fixed, message(5, external(b"data.bin")))) == ("data.bin",)


def test_a_non_minimal_key_encoding_is_still_attributed():
    key = tag(1, 2) + b"\x88\x00" + b"location"
    tensor = message(13, key + message(2, b"data.bin")) + number(14, 1)
    assert read(graph(message(5, tensor))) == ("data.bin",)


@pytest.mark.parametrize(
    "broken",
    [
        tag(5, 6),
        tag(5, 7),
        tag(0, 0) + b"\0",
        tag(9, 4),
        tag(9, 3) + tag(8, 4),
        tag(5, 0) + b"\xff" * 11,
        tag(5, 2) + varint(1000) + b"short",
    ],
)
def test_malformed_wire_data_fails_only_when_a_location_key_exists(broken):
    with pytest.raises(FormatError, match=ONNX_UNREADABLE):
        read(graph(message(5, external(b"data.bin"))) + broken)
    assert read(number(1, 8) + broken) == ()


# Key encodings protobuf's C++ parser accepts: it keeps the low 32 bits of a tag and
# the low 64 bits of a length, from varints of up to ten bytes.
OVERLONG_TAGS = [
    bytes([0x8A, 0x80, 0x80, 0x80, 0x10]),
    bytes([0x8A, 0x80, 0x80, 0x80, 0xF0, 0x80, 0x80, 0x80, 0x80, 0x01]),
]
OVERLONG_LENGTH = bytes([0x88] + [0x80] * 8 + [0x02])


@pytest.mark.parametrize("key_tag", OVERLONG_TAGS)
def test_a_key_tag_beyond_32_bits_fails_closed(key_tag):
    key = key_tag + b"\x08location"
    tensor = message(8, b"w") + message(13, key + message(2, b"data.bin")) + number(14, 1)
    with pytest.raises(FormatError, match=ONNX_UNREADABLE):
        read(graph(message(5, tensor)))


@pytest.mark.parametrize(
    "key",
    [
        *(key_tag + b"\x08location" for key_tag in OVERLONG_TAGS),
        tag(1, 2) + OVERLONG_LENGTH + b"location",
    ],
)
def test_keys_in_any_accepted_encoding_count_in_skipped_fields(key):
    hidden = message(99, message(13, key + message(2, b"data.bin")))
    with pytest.raises(FormatError, match=ONNX_UNEXPLAINED):
        read(graph(message(5, external(b"model.bin"))) + hidden)


def place(data: bytes, start: int) -> bytes:
    """Prefix ``data`` with a doc string so its first ``location`` starts at ``start``."""
    padded = message(6, b"x" * (start - data.index(b"location") - 4)) + data
    assert padded.index(b"location") == start
    return padded


@pytest.mark.parametrize("shift", [-28, -21, -20, -9, -8, -7, -4, -1, 0, 1])
def test_keys_across_read_boundaries_are_counted_once(shift):
    # The reader reads 64 KiB at a time; a key may straddle any boundary.
    parsed = graph(message(5, external(b"data.bin")))
    assert read(place(parsed, 65536 + shift)) == ("data.bin",)
    for key_tag in [tag(1, 2), *OVERLONG_TAGS]:
        hidden = message(99, message(13, key_tag + b"\x08location" + message(2, b"x")))
        with pytest.raises(FormatError, match=ONNX_UNEXPLAINED):
            read(place(hidden + number(1, 8), 65536 + shift))


def test_a_length_beyond_64_bits_is_read_as_protobuf_reads_it():
    key = tag(1, 2) + OVERLONG_LENGTH + b"location"
    tensor = message(8, b"w") + message(13, key + message(2, b"data.bin")) + number(14, 1)
    assert read(graph(message(5, tensor))) == ("data.bin",)


def test_an_unreadable_file_fails_on_the_key_bytes_alone():
    with pytest.raises(FormatError, match=ONNX_UNREADABLE):
        read(number(1, 8) + b"\x7f location")
    assert read(number(1, 8) + b"\x7f locator") == ()


def test_names_spelled_location_are_not_external_data_keys():
    named = [
        message(11, message(1, b"location")),
        message(1, message(1, b"location") + message(4, b"Relu")),
        message(1, message(5, message(1, b"location") + number(3, 1)) + message(4, b"Relu")),
        message(5, message(1, b"location") + message(8, b"w")),
    ]
    opset = message(8, message(1, b"location") + number(2, 1))
    assert read(graph(*named) + opset) == ()


def test_nesting_beyond_the_depth_limit_fails_closed():
    nested = message(5, external(b"deep.bin"))
    for _ in range(40):
        nested = message(6, message(1, message(5, nested)))
    with pytest.raises(FormatError, match=ONNX_LIMIT):
        read(graph(message(1, message(5, nested))))


@pytest.mark.parametrize("location", [b"x" * 5000, b"\xff\xfe.bin"])
def test_unusable_locations_fail_closed(location):
    with pytest.raises(FormatError, match=ONNX_UNREADABLE):
        read(graph(message(5, external(location))))


def test_location_without_a_value_fails_only_for_external_tensors():
    keyless = message(13, message(1, b"location"))
    with pytest.raises(FormatError, match=ONNX_UNREADABLE):
        read(graph(message(5, keyless + number(14, 1))))
    assert read(graph(message(5, keyless))) == ()


def test_an_exhausted_budget_fails_files_that_name_external_data():
    data = graph(message(5, external(b"data.bin")))
    budget = InspectionBudget(3)
    with pytest.raises(FormatError, match=ONNX_LIMIT):
        onnx_external_data(io.BytesIO(data).read, budget)
    assert onnx_external_data(io.BytesIO(number(1, 8)).read, budget) == ()


def gguf_string(text: bytes) -> bytes:
    return len(text).to_bytes(8, "little") + text


def gguf(*entries: tuple[bytes, int, bytes], version: int = 3) -> bytes:
    header = b"GGUF" + version.to_bytes(4, "little") + (0).to_bytes(8, "little")
    header += len(entries).to_bytes(8, "little")
    return header + b"".join(
        gguf_string(key) + kind.to_bytes(4, "little") + value for key, kind, value in entries
    )


def array(item: int, values: list[bytes]) -> bytes:
    return item.to_bytes(4, "little") + len(values).to_bytes(8, "little") + b"".join(values)


def test_gguf_named_templates_and_nested_arrays_are_read():
    nested = array(9, [array(4, [(1).to_bytes(4, "little")]), array(8, [gguf_string(b"x")])])
    data = gguf(
        (b"general.architecture", 8, gguf_string(b"llama")),
        (b"tokenizer.ggml.merges", 9, nested),
        (b"general.flag", 7, b"\x01"),
        (b"tokenizer.chat_template.tool_use", 8, gguf_string(b"{{ tools }}")),
    )
    metadata = gguf_metadata(io.BytesIO(data).read)
    assert metadata.architecture == "llama"
    assert metadata.chat_templates == (("tokenizer.chat_template.tool_use", b"{{ tools }}"),)


def test_gguf_template_names_with_control_characters_are_named_by_position():
    data = gguf(
        (b"tokenizer.chat_template", 8, gguf_string(b"{{ a }}")),
        (b"tokenizer.chat_template.\x1b[31mx", 8, gguf_string(b"{{ b }}")),
    )
    names = [name for name, _ in gguf_metadata(io.BytesIO(data).read).chat_templates]
    assert names == ["tokenizer.chat_template", "tokenizer.chat_template.#1"]


def test_gguf_architecture_must_be_a_plain_name():
    data = gguf((b"general.architecture", 8, gguf_string(b"Llama\n::warning::x")))
    assert gguf_metadata(io.BytesIO(data).read).architecture is None


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"GGUF" + (1).to_bytes(4, "little"), GGUF_UNREADABLE),
        (b"NOPE" + (3).to_bytes(4, "little"), GGUF_UNREADABLE),
        (gguf((b"k", 13, b"")), GGUF_UNREADABLE),
        (gguf((b"k", 9, array(9, [array(9, [array(4, [])])]))), GGUF_UNREADABLE),
        (gguf((b"k", 8, (1 << 40).to_bytes(8, "little"))), GGUF_LIMIT),
        (gguf((b"k", 9, (8).to_bytes(4, "little") + (1 << 40).to_bytes(8, "little"))), GGUF_LIMIT),
        (
            b"GGUF" + (3).to_bytes(4, "little") + b"\0" * 8 + (1 << 20).to_bytes(8, "little"),
            GGUF_LIMIT,
        ),
        (gguf((b"k", 8, gguf_string(b"abc")))[:-2], GGUF_UNREADABLE),
    ],
)
def test_gguf_metadata_outside_the_format_or_its_bounds_is_refused(data, reason):
    with pytest.raises(FormatError, match=reason):
        gguf_metadata(io.BytesIO(data).read)


def test_gguf_budget_is_shared():
    data = gguf(*[(b"k%d" % i, 4, b"\0" * 4) for i in range(10)])
    with pytest.raises(FormatError, match=GGUF_LIMIT):
        gguf_metadata(io.BytesIO(data).read, InspectionBudget(5))


@pytest.mark.parametrize(
    ("template", "escapes"),
    [
        (b"{{ messages[0]['content'] }}", False),
        (b"{{ '<__media__>' }}", False),
        (b"{{ getattr(x, 'y') }}", False),
        (b"{{ x.__class__ }}", True),
        (b"{{ x['__globals__'] }}", True),
        (b"{{ x|attr('a') }}", True),
    ],
)
def test_template_escape_heuristic(template, escapes):
    assert template_escape_markers(template) is escapes
