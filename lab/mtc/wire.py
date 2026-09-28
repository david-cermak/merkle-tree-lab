"""The slice of the TLS presentation language the MTC draft's structures need.

The draft writes its entries, proofs, and cosignature messages with the TLS
presentation language of Section 3 of [RFC9846]. This module implements the
handful of primitives those structures are built from, so the lab can encode
and decode them without a TLS stack:

===========================  =================================================
``uint8`` / ``uint16`` /    fixed-width unsigned integers, big endian
``uint48`` / ``uint64``
``opaque x<N>``             ``N`` bytes, no length
``opaque x<0..2^16-1>``     two-byte length prefix, then the data
``opaque x<0..2^8-1>``      one-byte length prefix, then the data
a vector of a struct         the encoded elements behind a *variable-length*
                            prefix: one byte when the total is below 64,
                            otherwise two bytes with the top bit of the first
                            set
===========================  =================================================

Everything else the draft uses -- the ``select`` in ``MTCLogEntry``, the
enums, the ``HashValue`` fixed-size opaque -- is handled by the modules that
own the structure.

These primitives follow the draft's encoding: a length prefix means what the
presentation language says it means, and the byte layouts here are the layouts
the draft describes. What is *not* here is a TLS stack -- this is a
hand-written subset, and the structures built on top of it deviate from the
draft in ways decision D7 in ``PLAN-update.md`` lists. Every one of those
deviations is recorded in the module that owns the structure, so the boundary
is: correct prefixes here, honest simplifications there.

``Reader`` is a strict sequential decoder. It raises :class:`DecodeError` on
truncated input or trailing bytes, because a certificate parser that silently
ignores the tail of a signature is exactly the bug the lab is teaching people
not to write (Section 7.2 step 2).
"""

from __future__ import annotations

from typing import Iterable


class DecodeError(ValueError):
    """Raised when a structure cannot be decoded."""


def uint(value: int, width: int) -> bytes:
    """Encode ``value`` as a ``width``-byte big-endian unsigned integer."""
    if not 0 <= value < 1 << (8 * width):
        raise ValueError(f"{value} does not fit in uint{8 * width}")
    return value.to_bytes(width, "big")


def opaque(data: bytes) -> bytes:
    """Encode a fixed-size ``opaque x<N>``: the data, with no length prefix."""
    return bytes(data)


def opaque_var(data: bytes, width: int = 2) -> bytes:
    """Encode a variable-length ``opaque``: a length prefix, then the data.

    ``width`` is the prefix size in bytes, so ``width=1`` is
    ``opaque x<0..2^8-1>`` and ``width=2`` is ``opaque x<0..2^16-1>``.
    """
    return uint(len(data), width) + bytes(data)


def vector(items: Iterable[bytes] | bytes) -> bytes:
    """Encode a vector, from a single already-encoded element or many.

    A ``bytes`` argument is one element, not a sequence of integers -- which is
    what ``b"".join`` would otherwise do with it. Passing a single element is
    common here: most of the draft's vectors hold one thing, and ``vector(one)``
    reads better than ``vector((one,))``.

    Uses the presentation language's variable-length prefix: one byte for a
    total below 64, otherwise two bytes with the top two bits set to ``01``,
    which is how a decoder knows to read a second byte. A vector can never need
    more than two bytes here, because the largest thing it wraps is an
    ``opaque x<0..2^16-1>``.
    """
    body = bytes(items) if isinstance(items, (bytes, bytearray)) else b"".join(items)
    return vector_prefix(len(body)) + body


def vector_prefix(length: int) -> bytes:
    """Encode the variable-length prefix a vector of ``length`` bytes gets."""
    if length < 64:
        return uint(length, 1)
    if length < 0x4000:
        return bytes([0x40 | (length >> 8), length & 0xFF])
    raise ValueError(f"vector of {length} bytes exceeds the two-byte prefix limit")



class Reader:
    """A strict sequential reader over encoded bytes."""

    def __init__(self, data: bytes, context: str = "structure") -> None:
        self._data = bytes(data)
        self._offset = 0
        self._context = context

    @property
    def remaining(self) -> int:
        return len(self._data) - self._offset

    def _take(self, count: int) -> bytes:
        if count < 0 or self.remaining < count:
            raise DecodeError(
                f"{self._context}: need {count} more bytes at offset "
                f"{self._offset}, have {self.remaining}"
            )
        chunk = self._data[self._offset : self._offset + count]
        self._offset += count
        return chunk

    def uint(self, width: int) -> int:
        """Read a fixed-width unsigned integer."""
        return int.from_bytes(self._take(width), "big")

    def opaque(self, size: int) -> bytes:
        """Read a fixed-size ``opaque x<N>``."""
        return self._take(size)

    def opaque_var(self, width: int = 2) -> bytes:
        """Read a variable-length ``opaque`` with a ``width``-byte prefix."""
        return self._take(self.uint(width))

    def vector_body(self) -> bytes:
        """Read a vector's variable-length prefix and return the body.

        The body is returned unparsed: the caller knows the element structure
        and hands :func:`read_elements` a parser for it.
        """
        return self._take(self._vector_length())

    def vector_bytes(self) -> bytes:
        """Read a whole vector, length prefix included.

        The same bytes :meth:`vector_body` skips past, for a caller that wants
        to hand the vector on as an opaque value -- the entry's extension list
        is hashed, so it has to survive the trip rather than be re-encoded.

        The prefix is read separately from the body and both are returned, so a
        two-byte prefix contributes its two bytes rather than being mistaken for
        part of the length.
        """
        first = self._take(1)[0]
        if first < 0x40:
            return bytes([first]) + self._take(first)
        if first < 0x80:
            second = self._take(1)[0]
            return bytes([first, second]) + self._take(((first & 0x3F) << 8) | second)
        raise DecodeError(f"{self._context}: reserved vector length prefix {first:#04x}")

    def _vector_length(self) -> int:
        return self._length_after_prefix(self._take(1)[0])

    def _length_after_prefix(self, first: int) -> int:
        """Return the body length for an already-read prefix byte.

        Split from :meth:`_vector_length` so :meth:`vector_bytes` can add the
        prefix back to what it reads without reading it twice.
        """
        if first < 0x40:
            return first
        if first < 0x80:
            return ((first & 0x3F) << 8) | self._take(1)[0]
        raise DecodeError(f"{self._context}: reserved vector length prefix {first:#04x}")

    def rest(self) -> bytes:
        """Return every remaining byte and mark the reader finished.

        For the tail of a structure whose last field has no length prefix, where
        "the rest of this" is exactly the field and any surplus is an error the
        caller checks.
        """
        return self._take(self.remaining)

    def skip(self, count: int) -> None:
        """Advance past ``count`` bytes, still bounds-checked."""
        self._take(count)

    def at_end(self) -> bool:
        return self.remaining == 0

    def expect_end(self) -> None:
        """Raise unless every byte has been consumed."""
        if self.remaining:
            raise DecodeError(
                f"{self._context}: {self.remaining} trailing byte(s) after the structure"
            )


def read_vector(reader: Reader, parse) -> list:
    """Read a length-prefixed vector and return its elements.

    :meth:`Reader.vector_bytes` is the counterpart for a vector whose *bytes*
    are the value -- an extension list, for instance, which has to survive a
    round trip unchanged. This one parses the elements instead.
    """
    body = Reader(reader.vector_body())
    elements = []
    while not body.at_end():
        elements.append(parse(body))
    return elements


def read_elements(reader: Reader, parse) -> list:
    """Read elements from a vector body until the reader is exhausted.

    ``parse`` is called with the reader and must consume exactly one element.
    Every vector in the draft's structures is made of self-delimiting
    elements -- each begins with a length or a fixed-width field that tells the
    reader where the next element starts -- so the owning module supplies the
    element parser and this function only supplies the loop.
    """
    items = []
    while not reader.at_end():
        items.append(parse(reader))
    return items
