"""An abstract interpreter of ``pickle.load`` that never imports, calls or builds objects.

``load_segment`` reads one pickle from a byte sample the way ``pickle.load`` reads it
from ``io.BytesIO``, as the C unpickler (``"c"``) or the pure-Python one (``"py"``)
does: the same reads and frame handling, the same stack, MARK and memo rules and the
same errors, opcode by opcode. ``find_class`` fails for a module or name that is not a
dotted identifier, which no import finds; otherwise it returns an opaque class, as a
loader that records instead of importing does. Calling that class, creating an
instance of it through ``__new__`` or setting its state through BUILD invokes it, and
the walk stops there; anything else that needs more than a class (iterating it,
indexing it, adding items to it) fails as it fails for a plain class.
``persistent_load``, which ``torch.load`` defines, returns an inert object, as the
storages it returns run nothing they are given. Builtin values are modelled by what
decides the loader's next step: their type, length, whether they hash, and the strings
``STACK_GLOBAL`` takes.

The sample may be a prefix of the file: a read past its end, or past the opcode and
MARK budget, ends the walk as unread, since the loader's behaviour is not decided.
"""

from __future__ import annotations

import codecs
import re
import struct
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, cast

Flavor = Literal["c", "py"]
FLAVORS: tuple[Flavor, ...] = ("c", "py")
Outcome = Literal["stop", "error", "unread", "called"]
_HIGHEST_PROTOCOL = 5


class _LoadError(Exception):
    """The loader raises here: ``pickle.load`` stops."""


class _UnreadError(Exception):
    """The loader's next step depends on bytes or opcodes past the inspection bounds."""


class _CallError(Exception):
    """The loader invokes a class that ``find_class`` returned."""


class _Opaque:
    """A class that ``find_class`` returned."""

    __slots__ = ()


class _Persistent:
    """What ``persistent_load`` returned: an object the loader made, such as a storage."""

    __slots__ = ()


class _Tuple:
    __slots__ = ("items", "hashable")

    def __init__(self, items: tuple[object, ...]) -> None:
        self.items = items
        self.hashable = all(_hashable(item) for item in items)


class _Sized:
    """A list, dict, set, frozenset, bytearray or read-only view of one, by its length."""

    __slots__ = ("kind", "length", "string_keys")

    def __init__(self, kind: str, length: int = 0) -> None:
        self.kind = kind
        self.length = length
        self.string_keys = True


_SCALARS = (type(None), bool, int, float, str, bytes, _Opaque, _Persistent)
_ITERABLE = (str, bytes, _Tuple, _Sized)


def _hashable(value: object) -> bool:
    if isinstance(value, _Tuple):
        return value.hashable
    if isinstance(value, _Sized):
        return value.kind in ("frozenset", "view")
    return isinstance(value, _SCALARS)


def _hash(value: object) -> None:
    if not _hashable(value):
        raise _LoadError  # unhashable type


def _kind(value: object, kind: str) -> bool:
    return isinstance(value, _Sized) and value.kind == kind


def _truth(value: object) -> bool:
    if isinstance(value, (type(None), bool, int, float)):
        return bool(value)
    if isinstance(value, (str, bytes)):
        return bool(value)
    if isinstance(value, _Tuple):
        return bool(value.items)
    if isinstance(value, _Sized):
        return value.length > 0
    return True


def _byte(value: object) -> None:
    if not isinstance(value, int) or not 0 <= value < 256:
        raise _LoadError


@dataclass
class Budget:
    """Opcodes and MARKs left for every pickle of one sample."""

    opcodes: int
    marks: int


@dataclass(frozen=True)
class Segment:
    """How one ``pickle.load`` ends.

    ``resolved`` says whether it reached ``find_class``. After a STOP, ``resumes``
    holds where the next ``pickle.load`` starts: where the loader left ``io.BytesIO``,
    then, when different, right after the STOP, as the C unpickler leaves a buffered
    file it peeked ahead in.
    """

    outcome: Outcome
    resolved: bool
    resumes: tuple[int, ...] = ()


_C_INT = re.compile(
    rb"[ \t\n\v\f\r]*[+-]?(?:0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)(?:\x00[^\n]*)?\n"
)
_C_FLOAT = re.compile(
    rb"[+-]?(?:(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|inf(?:inity)?|nan)"
    rb"(?:\x00[^\n]*)?\n",
    re.IGNORECASE,
)


class _Machine:
    """One ``Unpickler(stream).load()`` from ``start``.

    Both read a FRAME as a unit that ends at ``self.frame``: a read that crosses its end
    fails, and one that starts at its end reads on from the file. The C unpickler also
    wants the whole frame, every byte a read asks for and a newline after each line.
    """

    def __init__(
        self, sample: bytes, size: int, start: int, flavor: Flavor, budget: Budget
    ) -> None:
        self.sample = sample
        self.whole = len(sample) >= size
        self.size = size
        self.pos = start
        self.frame: int | None = None
        self.c = flavor == "c"
        self.budget = budget
        self.stack: list[object] = []
        self.marks: list[int] = []
        self.memo: dict[int, object] = {}
        self.resolved = False

    # -- reads -----------------------------------------------------------------------

    def _take(self, start: int, end: int) -> bytes:
        """File bytes ``start:end``; past the sample, unread, or short at the file's end."""
        if end > len(self.sample) and not self.whole:
            raise _UnreadError
        return self.sample[start:end]

    def read(self, count: int) -> bytes:
        if self.frame is not None:
            if self.pos >= self.frame and count:
                self.frame = None
            elif self.frame - self.pos < count:
                self._take(self.pos, self.frame)
                raise _LoadError  # pickle exhausted before end of frame
        data = self._take(self.pos, self.pos + count)
        if self.c and len(data) < count:
            raise _LoadError  # pickle data was truncated
        self.pos += len(data)
        return data

    def _line(self, end: int) -> bytes | None:
        """The line from ``pos`` if it ends before ``end``; ``None`` if it does not."""
        newline = self.sample.find(b"\n", self.pos, end)
        if newline < 0:
            self._take(self.pos, end)
            return None
        data = self.sample[self.pos : newline + 1]
        self.pos = newline + 1
        return data

    def readline(self) -> bytes:
        if self.frame is not None and self.pos < self.frame:
            data = self._line(self.frame)
            if data is None:
                raise _LoadError  # pickle exhausted before end of frame
            return data
        self.frame = None
        data = self._line(len(self.sample) + 1)
        if data is None:
            if self.c:
                raise _LoadError  # pickle data was truncated
            data = self.sample[self.pos :]
            self.pos = len(self.sample)
        return data

    def line(self) -> bytes:
        """A text argument without its newline; the C unpickler wants a character too."""
        data = self.readline()
        if self.c and len(data) < 2:
            raise _LoadError
        return data[:-1]

    def number(self, width: int, form: str) -> int:
        data = self.read(width)
        if len(data) < width:
            raise _LoadError
        value: int = struct.unpack(form, data)[0]
        return value

    # -- stack -----------------------------------------------------------------------

    def _floor(self) -> int:
        return self.marks[-1] if self.marks else 0

    def push(self, value: object) -> None:
        self.stack.append(value)

    def pop(self) -> object:
        if len(self.stack) <= self._floor():
            raise _LoadError  # stack underflow
        return self.stack.pop()

    def top(self) -> object:
        if len(self.stack) <= self._floor():
            raise _LoadError
        return self.stack[-1]

    def pop_mark(self) -> list[object]:
        if not self.marks:
            raise _LoadError  # could not find MARK
        floor = self.marks.pop()
        items = self.stack[floor:]
        del self.stack[floor:]
        return items

    def _marked(self) -> list[object] | None:
        """The C unpickler's items to add after a MARK, or ``None`` when there are none.

        The item they are added to sits below the MARK, inside any enclosing one.
        """
        if not self.marks:
            raise _LoadError
        if self.marks[-1] <= (self.marks[-2] if len(self.marks) > 1 else 0):
            raise _LoadError
        return self.pop_mark() or None

    def resolve(self, module: str, name: str) -> None:
        """``find_class(module, name)``, which imports nothing a dotted name cannot name."""
        self.resolved = True
        if not all(part.isidentifier() for part in [*module.split("."), *name.split(".")]):
            raise _LoadError  # ModuleNotFoundError, or an AttributeError
        self.push(_Opaque())

    # -- the loop --------------------------------------------------------------------

    def run(self) -> Segment:
        try:
            while True:
                key = self.read(1)
                if not key:
                    raise _LoadError  # EOFError
                handler = _DISPATCH.get(key[0])
                if handler is None:
                    raise _LoadError  # invalid load key
                if self.budget.opcodes <= 0:
                    raise _UnreadError
                self.budget.opcodes -= 1
                if handler is _Machine.op_stop:
                    self.pop()
                    return Segment("stop", self.resolved, self._resumes())
                handler(self)
        except _CallError:
            return Segment("called", self.resolved)
        except _UnreadError:
            return Segment("unread", self.resolved)
        except (_LoadError, ValueError, UnicodeError, OverflowError, struct.error):
            return Segment("error", self.resolved)

    def _resumes(self) -> tuple[int, ...]:
        if self.frame is None or self.frame <= self.pos:
            return (self.pos,)
        return (self.frame, self.pos) if self.c else (self.frame,)

    # -- opcodes ---------------------------------------------------------------------

    def op_stop(self) -> None:  # pragma: no cover - run() handles STOP
        raise AssertionError

    def op_proto(self) -> None:
        if self.number(1, "<B") > _HIGHEST_PROTOCOL:
            raise _LoadError

    def op_frame(self) -> None:
        size = self.number(8, "<Q")
        if size > sys.maxsize:
            raise _LoadError
        if self.frame is not None and self.frame > self.pos:
            raise _LoadError  # beginning of a new frame before end of current frame
        if self.c and self.pos + size > self.size:
            raise _LoadError  # pickle data was truncated
        self.frame = min(self.pos + size, max(self.size, len(self.sample)))

    def op_persid(self) -> None:
        self.readline()[:-1].decode("ascii")
        self.push(_Persistent())

    def op_binpersid(self) -> None:
        self.pop()
        self.push(_Persistent())

    def op_none(self) -> None:
        self.push(None)

    def op_true(self) -> None:
        self.push(True)

    def op_false(self) -> None:
        self.push(False)

    def op_int(self) -> None:
        data = self.readline()
        if self.c and len(data) < 2:
            raise _LoadError
        if data in (b"00\n", b"01\n"):
            self.push(data == b"01\n")
        elif self.c and _C_INT.fullmatch(data):
            self.push(int(data.split(b"\x00")[0].strip() or b"0", 8 if _octal(data) else 0))
        else:
            self.push(int(data, 0))

    def op_binint(self) -> None:
        self.push(self.number(4, "<i"))

    def op_binint1(self) -> None:
        self.push(self.number(1, "<B"))

    def op_binint2(self) -> None:
        self.push(self.number(2, "<H"))

    def op_long(self) -> None:
        data = self.line()
        if data.endswith(b"L"):
            data = data[:-1]
        self.push(int(data, 0))

    def op_long1(self) -> None:
        self.push(int.from_bytes(self.read(self.number(1, "<B")), "little", signed=True))

    def op_long4(self) -> None:
        count = self.number(4, "<i")
        if count < 0:
            raise _LoadError
        self.push(int.from_bytes(self.read(count), "little", signed=True))

    def op_float(self) -> None:
        data = self.readline()
        if not self.c:
            self.push(float(data[:-1]))
            return
        if len(data) < 2 or not _C_FLOAT.fullmatch(data):
            raise _LoadError  # could not convert string to float
        value = float(data.split(b"\x00")[0])
        if value in (float("inf"), float("-inf")) and b"inf" not in data.lower():
            raise _LoadError  # OverflowError
        self.push(value)

    def op_binfloat(self) -> None:
        self.push(float(self.number(8, ">d")))

    def op_string(self) -> None:
        data = self.line()
        if len(data) < 2 or data[0] != data[-1] or data[0] not in b"\"'":
            raise _LoadError  # the STRING opcode argument must be quoted
        self.push(cast(bytes, codecs.escape_decode(data[1:-1])[0]).decode("ascii"))

    def op_binstring(self) -> None:
        count = self.number(4, "<i")
        if count < 0:
            raise _LoadError
        self.push(self.read(count).decode("ascii"))

    def op_short_binstring(self) -> None:
        self.push(self.read(self.number(1, "<B")).decode("ascii"))

    def op_binbytes(self) -> None:
        self.push(self.read(self.number(4, "<I")))

    def op_short_binbytes(self) -> None:
        self.push(self.read(self.number(1, "<B")))

    def _long_count(self) -> int:
        count = self.number(8, "<Q")
        if count > sys.maxsize:
            raise _LoadError
        return count

    def op_binbytes8(self) -> None:
        self.push(self.read(self._long_count()))

    def op_bytearray8(self) -> None:
        count = self._long_count()
        self.read(count)
        self.push(_Sized("bytearray", count))

    def op_unicode(self) -> None:
        self.push(str(self.readline()[:-1], "raw-unicode-escape"))

    def _utf8(self, data: bytes) -> None:
        self.push(str(data, "utf-8", "surrogatepass"))

    def op_short_binunicode(self) -> None:
        self._utf8(self.read(self.number(1, "<B")))

    def op_binunicode(self) -> None:
        self._utf8(self.read(self.number(4, "<I")))

    def op_binunicode8(self) -> None:
        self._utf8(self.read(self._long_count()))

    def op_next_buffer(self) -> None:
        raise _LoadError  # no out-of-band buffers

    def op_readonly_buffer(self) -> None:
        value = self.top()
        if isinstance(value, _Sized) and value.kind == "bytearray":
            self.stack[-1] = _Sized("view", value.length)
        elif not isinstance(value, bytes) and not _kind(value, "view"):
            raise _LoadError  # memoryview() of something without the buffer protocol

    # -- tuples, lists, dicts and sets -----------------------------------------------

    def op_tuple(self) -> None:
        self.push(_Tuple(tuple(self.pop_mark())))

    def op_empty_tuple(self) -> None:
        self.push(_Tuple(()))

    def _tuple(self, count: int) -> None:
        if len(self.stack) - self._floor() < count:
            raise _LoadError
        items = tuple(self.stack[-count:])
        del self.stack[-count:]
        self.push(_Tuple(items))

    def op_tuple1(self) -> None:
        self._tuple(1)

    def op_tuple2(self) -> None:
        self._tuple(2)

    def op_tuple3(self) -> None:
        self._tuple(3)

    def op_empty_list(self) -> None:
        self.push(_Sized("list"))

    def op_empty_dict(self) -> None:
        self.push(_Sized("dict"))

    def op_empty_set(self) -> None:
        self.push(_Sized("set"))

    def op_list(self) -> None:
        self.push(_Sized("list", len(self.pop_mark())))

    def op_dict(self) -> None:
        items = self.pop_mark()
        if self.c and len(items) % 2:
            raise _LoadError  # odd number of items for DICT
        made = _Sized("dict")
        for index in range(0, len(items), 2):
            if index + 1 >= len(items):
                raise _LoadError
            self._key(made, items[index])
        self.push(made)

    def op_frozenset(self) -> None:
        items = self.pop_mark()
        for item in items:
            _hash(item)
        self.push(_Sized("frozenset", len(items)))

    def _key(self, target: _Sized, key: object) -> None:
        _hash(key)
        target.length += 1
        target.string_keys = target.string_keys and isinstance(key, str)

    def _setitem(self, target: object, key: object, value: object) -> None:
        if not isinstance(target, _Sized):
            raise _LoadError  # no __setitem__
        if target.kind == "dict":
            self._key(target, key)
            return
        if target.kind not in ("list", "bytearray") or not isinstance(key, int):
            raise _LoadError
        if not -target.length <= key < target.length:
            raise _LoadError  # assignment index out of range
        if target.kind == "bytearray":
            _byte(value)

    def op_setitem(self) -> None:
        value = self.pop()
        key = self.pop()
        self._setitem(self.top(), key, value)

    def op_setitems(self) -> None:
        if self.c:
            items = self._marked()
            if items is None:
                return
            if len(items) % 2:
                raise _LoadError  # odd number of items for SETITEMS
        else:
            items = self.pop_mark()
        target = self.top()
        for index in range(0, len(items), 2):
            if index + 1 >= len(items):
                raise _LoadError
            self._setitem(target, items[index], items[index + 1])

    def _extend(self, target: object, items: list[object]) -> None:
        if _kind(target, "bytearray"):
            for item in items:
                _byte(item)
        elif not _kind(target, "list"):
            raise _LoadError  # no extend() or append()
        assert isinstance(target, _Sized)
        target.length += len(items)

    def op_append(self) -> None:
        value = self.pop()
        self._extend(self.top(), [value])

    def op_appends(self) -> None:
        items = self._marked() if self.c else self.pop_mark()
        if items is not None:
            self._extend(self.top(), items)

    def op_additems(self) -> None:
        items = self._marked() if self.c else self.pop_mark()
        if items is None:
            return
        target = self.top()
        if not _kind(target, "set"):
            raise _LoadError  # no add()
        for item in items:
            _hash(item)
        assert isinstance(target, _Sized)
        target.length += len(items)

    # -- what resolves or calls ------------------------------------------------------

    def op_global(self) -> None:
        module = self.line().decode("utf-8")
        self.resolve(module, self.line().decode("utf-8"))

    def op_stack_global(self) -> None:
        name = self.pop()
        module = self.pop()
        if not isinstance(name, str) or not isinstance(module, str):
            raise _LoadError  # STACK_GLOBAL requires str
        self.resolve(module, name)

    def _ext(self, width: int, form: str) -> None:
        self.number(width, form)
        raise _LoadError  # no extension code is registered

    def op_ext1(self) -> None:
        self._ext(1, "<B")

    def op_ext2(self) -> None:
        self._ext(2, "<H")

    def op_ext4(self) -> None:
        self._ext(4, "<i")

    def _instantiate(self, klass: object) -> None:
        if isinstance(klass, _Opaque):
            raise _CallError  # klass(*args), or klass.__new__(klass) without arguments
        raise _LoadError  # a builtin value is not callable

    def op_inst(self) -> None:
        if self.c and not self.marks:
            raise _LoadError  # could not find MARK
        module = self.line().decode("ascii")
        self.resolve(module, self.line().decode("ascii"))
        klass = self.stack.pop()
        self.pop_mark()
        self._instantiate(klass)

    def op_obj(self) -> None:
        if self.c and (not self.marks or len(self.stack) <= self.marks[-1]):
            raise _LoadError
        args = self.pop_mark()
        if not args:
            raise _LoadError
        self._instantiate(args[0])

    def op_reduce(self) -> None:
        args = self.pop()
        func = self.top()
        if not isinstance(args, _Tuple if self.c else _ITERABLE):
            raise _LoadError  # the argument list must be a tuple, or iterable
        self._instantiate(func)

    def _new(self, kwargs: object | None) -> None:
        args = self.pop()
        klass = self.pop()
        if self.c and not isinstance(klass, _Opaque):
            raise _LoadError  # class argument must be a type
        if not isinstance(args, _Tuple if self.c else _ITERABLE):
            raise _LoadError
        if kwargs is not None and not (
            isinstance(kwargs, _Sized) and kwargs.kind == "dict" and kwargs.string_keys
        ):
            raise _LoadError  # keywords must be strings in a dict
        self._instantiate(klass)

    def op_newobj(self) -> None:
        self._new(None)

    def op_newobj_ex(self) -> None:
        self._new(self.pop())

    def op_build(self) -> None:
        state = self.pop()
        inst = self.top()
        if isinstance(inst, _Opaque):
            raise _CallError  # inst.__setstate__(state)
        split = isinstance(state, _Tuple) and len(state.items) == 2
        slots: object = None
        if isinstance(state, _Tuple) and split:
            state, slots = state.items
        if not self.c:
            if _truth(state) or _truth(slots):
                raise _LoadError  # a builtin value has no __dict__ and takes no attributes
        elif state is not None:
            raise _LoadError  # state is not a dictionary, or a builtin value has no __dict__
        elif split and not (isinstance(slots, _Sized) and slots.kind == "dict"):
            raise _LoadError  # slot state is not a dictionary
        elif split and _truth(slots):
            raise _LoadError  # a builtin value takes no attributes

    # -- stack and memo --------------------------------------------------------------

    def op_pop(self) -> None:
        if len(self.stack) > self._floor():
            self.stack.pop()
        else:
            self.pop_mark()

    def op_pop_mark(self) -> None:
        self.pop_mark()

    def op_dup(self) -> None:
        self.push(self.top())

    def op_mark(self) -> None:
        if self.budget.marks <= 0:
            raise _UnreadError
        self.budget.marks -= 1
        self.marks.append(len(self.stack))

    def _get(self, index: int) -> None:
        if index not in self.memo:
            raise _LoadError  # Memo value not found
        self.push(self.memo[index])

    def op_get(self) -> None:
        self._get(int(self.line()))

    def op_binget(self) -> None:
        self._get(self.number(1, "<B"))

    def op_long_binget(self) -> None:
        self._get(self.number(4, "<I"))

    def _put(self, index: int) -> None:
        if index < 0:
            raise _LoadError  # negative PUT argument
        self.memo[index] = self.top()

    def op_put(self) -> None:
        self._put(int(self.line()))

    def op_binput(self) -> None:
        self._put(self.number(1, "<B"))

    def op_long_binput(self) -> None:
        self._put(self.number(4, "<I"))

    def op_memoize(self) -> None:
        self.memo[len(self.memo)] = self.top()


def _octal(data: bytes) -> bool:
    digits = data.split(b"\x00")[0].strip().lstrip(b"+-")
    return len(digits) > 1 and digits[:1] == b"0" and digits[1:2] not in (b"x", b"X")


_DISPATCH: dict[int, Callable[[_Machine], None]] = {
    ord(code): handler
    for code, handler in {
        "(": _Machine.op_mark,
        ".": _Machine.op_stop,
        "0": _Machine.op_pop,
        "1": _Machine.op_pop_mark,
        "2": _Machine.op_dup,
        "B": _Machine.op_binbytes,
        "C": _Machine.op_short_binbytes,
        "F": _Machine.op_float,
        "G": _Machine.op_binfloat,
        "I": _Machine.op_int,
        "J": _Machine.op_binint,
        "K": _Machine.op_binint1,
        "L": _Machine.op_long,
        "M": _Machine.op_binint2,
        "N": _Machine.op_none,
        "P": _Machine.op_persid,
        "Q": _Machine.op_binpersid,
        "R": _Machine.op_reduce,
        "S": _Machine.op_string,
        "T": _Machine.op_binstring,
        "U": _Machine.op_short_binstring,
        "V": _Machine.op_unicode,
        "X": _Machine.op_binunicode,
        "]": _Machine.op_empty_list,
        "a": _Machine.op_append,
        "b": _Machine.op_build,
        "c": _Machine.op_global,
        "d": _Machine.op_dict,
        "e": _Machine.op_appends,
        "g": _Machine.op_get,
        "h": _Machine.op_binget,
        "i": _Machine.op_inst,
        "j": _Machine.op_long_binget,
        "l": _Machine.op_list,
        "o": _Machine.op_obj,
        "p": _Machine.op_put,
        "q": _Machine.op_binput,
        "r": _Machine.op_long_binput,
        "s": _Machine.op_setitem,
        "t": _Machine.op_tuple,
        "u": _Machine.op_setitems,
        "}": _Machine.op_empty_dict,
        ")": _Machine.op_empty_tuple,
        "\x80": _Machine.op_proto,
        "\x81": _Machine.op_newobj,
        "\x82": _Machine.op_ext1,
        "\x83": _Machine.op_ext2,
        "\x84": _Machine.op_ext4,
        "\x85": _Machine.op_tuple1,
        "\x86": _Machine.op_tuple2,
        "\x87": _Machine.op_tuple3,
        "\x88": _Machine.op_true,
        "\x89": _Machine.op_false,
        "\x8a": _Machine.op_long1,
        "\x8b": _Machine.op_long4,
        "\x8c": _Machine.op_short_binunicode,
        "\x8d": _Machine.op_binunicode8,
        "\x8e": _Machine.op_binbytes8,
        "\x8f": _Machine.op_empty_set,
        "\x90": _Machine.op_additems,
        "\x91": _Machine.op_frozenset,
        "\x92": _Machine.op_newobj_ex,
        "\x93": _Machine.op_stack_global,
        "\x94": _Machine.op_memoize,
        "\x95": _Machine.op_frame,
        "\x96": _Machine.op_bytearray8,
        "\x97": _Machine.op_next_buffer,
        "\x98": _Machine.op_readonly_buffer,
    }.items()
}


def load_segment(sample: bytes, size: int, start: int, flavor: Flavor, budget: Budget) -> Segment:
    """How ``pickle.load`` ends reading the pickle at ``start`` of a file of ``size`` bytes.

    ``sample`` holds the file's first bytes; ``budget`` is charged for every opcode and
    MARK read and is shared by the pickles of one sample.
    """
    return _Machine(sample, size, start, flavor, budget).run()
