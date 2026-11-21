"""The paths and modes a git index records, read from its bytes without running git."""

import hashlib
import struct

# The object type in the top four bits of an index entry's mode.
_TYPE_SHIFT = 12
REGULAR = 0o10
SYMLINK = 0o12
GITLINK = 0o16
DIRECTORY = 0o04

_SHA1_SIZE = 20
_SHA256_SIZE = 32
_HEADER = struct.Struct(">4sII")
_EXTENSION = struct.Struct(">4sI")
_EXTENDED_FLAG = 0x4000


class GitIndexError(ValueError):
    pass


def object_type(mode: int) -> int:
    return mode >> _TYPE_SHIFT


def hash_size(config: str) -> int:
    """The object hash size in bytes, from the text of the repository's `config` file."""
    section = ""
    for raw in config.split("\n"):
        line = raw.strip()
        if line.startswith("["):
            section = line[1 : line.find("]")].strip().lower()
            continue
        key, _, value = line.partition("=")
        if section == "extensions" and key.strip().lower() == "objectformat":
            return _SHA256_SIZE if value.strip().lower() == "sha256" else _SHA1_SIZE
    return _SHA1_SIZE


def parse_index(data: bytes, hash_bytes: int) -> dict[str, int]:
    """Each path in the index with its mode. Versions 2, 3 and 4 are supported."""
    try:
        return _parse(data, hash_bytes)
    except (IndexError, struct.error) as error:
        raise GitIndexError("the index is truncated") from error


def _parse(data: bytes, hash_bytes: int) -> dict[str, int]:
    signature, version, count = _HEADER.unpack_from(data)
    if signature != b"DIRC":
        raise GitIndexError("not a git index")
    if version not in (2, 3, 4):
        raise GitIndexError(f"index version {version} is not supported")
    body, trailer = data[:-hash_bytes], data[-hash_bytes:]
    digest = hashlib.sha256 if hash_bytes == _SHA256_SIZE else hashlib.sha1
    # index.skipHash writes a trailer of zeros instead of the checksum.
    if any(trailer) and digest(body).digest() != trailer:
        raise GitIndexError("the index checksum does not match")
    fixed = 40 + hash_bytes + 2
    entries: dict[str, int] = {}
    offset = _HEADER.size
    previous = b""
    for _ in range(count):
        mode = struct.unpack_from(">I", body, offset + 24)[0]
        flags = struct.unpack_from(">H", body, offset + 40 + hash_bytes)[0]
        cursor = offset + fixed
        if flags & _EXTENDED_FLAG:
            if version < 3:
                raise GitIndexError("an extended entry in a version 2 index")
            cursor += 2
        if version == 4:
            strip, cursor = _varint(body, cursor)
            if strip > len(previous):
                raise GitIndexError("an entry strips more of the previous path than it has")
            end = _terminator(body, cursor)
            name = previous[: len(previous) - strip] + body[cursor:end]
            offset = end + 1
        else:
            end = _terminator(body, cursor)
            name = body[cursor:end]
            # Versions 2 and 3 pad each entry with 1 to 8 NULs to a multiple of 8 bytes.
            offset += ((end - offset) // 8 + 1) * 8
        previous = name
        entries[name.decode("utf-8", "replace")] = mode
    _check_extensions(body, offset)
    return entries


def _varint(data: bytes, position: int) -> tuple[int, int]:
    byte = data[position]
    position += 1
    value = byte & 0x7F
    while byte & 0x80:
        byte = data[position]
        position += 1
        value = ((value + 1) << 7) | (byte & 0x7F)
    return value, position


def _terminator(data: bytes, start: int) -> int:
    end = data.find(b"\0", start)
    if end < 0:
        raise GitIndexError("the index is truncated")
    return end


def _check_extensions(body: bytes, offset: int) -> None:
    while offset < len(body):
        name, size = _EXTENSION.unpack_from(body, offset)
        # An extension whose name starts with a capital letter is optional. Any other, such
        # as `link` (split index) or `sdir` (sparse index), changes which entries exist.
        if not b"A" <= name[:1] <= b"Z":
            label = name.decode("ascii", "replace")
            raise GitIndexError(f"index extension {label!r} is not supported")
        offset += _EXTENSION.size + size
    if offset != len(body):
        raise GitIndexError("the index is truncated")
