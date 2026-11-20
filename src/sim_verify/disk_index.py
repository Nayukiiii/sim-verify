"""Temporary disk-backed, quota-capped exact deduplication index.

Uses SQLite `WITHOUT ROWID` with `PRAGMA page_size` and `PRAGMA max_page_count`
to enforce a strict hard byte budget on disk while keeping RAM cache bounded.
Keys are encoded using canonical prefix-free binary encodings so 64-bit integers,
integer tuples, and arbitrary byte strings remain lossless and mutually disjoint.
"""
from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
from typing import Iterable, Sequence

_SMALL_BYTES = tuple(bytes((i,)) for i in range(128))
_WIDTH_TAGS = tuple(bytes((128 + i,)) for i in range(9))

DEFAULT_MAX_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB
MAX_ALLOWED_BYTES = 16 * 1024 * 1024 * 1024  # 16 GiB
DEFAULT_PAGE_SIZE = 4096

IndexKey = int | tuple[int, ...] | bytes | bytearray | memoryview


class DiskQuotaExceededError(ValueError):
    """Raised when an operation exceeds the configured SQLite disk budget."""


def encode_u64(value: int) -> bytes:
    """Encode an unsigned 64-bit integer into a canonical prefix-free byte token."""
    if type(value) is not int or not (0 <= value < (1 << 64)):
        raise ValueError(f"Expected unsigned 64-bit int, got {value!r}")
    if value < 128:
        return _SMALL_BYTES[value]
    width = (value.bit_length() + 7) // 8
    return _WIDTH_TAGS[width] + value.to_bytes(width, "big")


def unpack_u64(buf: bytes | bytearray | memoryview, offset: int = 0) -> tuple[int, int]:
    """Decode one canonical prefix-free unsigned 64-bit integer starting at `offset`."""
    view = memoryview(buf)
    if offset < 0 or offset >= len(view):
        raise ValueError("Truncated u64 token")
    tag = view[offset]
    if tag < 128:
        return int(tag), offset + 1
    width = tag - 128
    if width < 1 or width > 8:
        raise ValueError(f"Invalid u64 width tag: {tag:#x}")
    end = offset + 1 + width
    if end > len(view):
        raise ValueError("Truncated u64 payload")
    value = int.from_bytes(view[offset + 1 : end], "big")
    if value < 128 or (value.bit_length() + 7) // 8 != width:
        raise ValueError("Non-canonical u64 encoding")
    return value, end


def encode_u64_tuple(values: Sequence[int] | Iterable[int]) -> bytes:
    """Encode a sequence of unsigned 64-bit integers into a prefix-free binary blob."""
    items = list(values)
    parts = [encode_u64(len(items))]
    parts.extend(encode_u64(v) for v in items)
    return b"".join(parts)


def decode_u64_tuple(data: bytes | bytearray | memoryview) -> tuple[int, ...]:
    """Decode a prefix-free binary blob produced by `encode_u64_tuple`."""
    view = memoryview(data)
    count, offset = unpack_u64(view, 0)
    out: list[int] = []
    for _ in range(count):
        val, offset = unpack_u64(view, offset)
        out.append(val)
    if offset != len(view):
        raise ValueError("Trailing bytes in encoded u64 tuple")
    return tuple(out)


def encode_prefix_free_bytes(data: bytes | bytearray | memoryview) -> bytes:
    """Encode arbitrary bytes with a prefix-free length header."""
    raw = bytes(data)
    return encode_u64(len(raw)) + raw


def unpack_prefix_free_bytes(
    buf: bytes | bytearray | memoryview, offset: int = 0
) -> tuple[bytes, int]:
    """Unpack one length-prefixed byte string starting at `offset`."""
    view = memoryview(buf)
    length, pos = unpack_u64(view, offset)
    end = pos + length
    if end > len(view):
        raise ValueError("Truncated prefix-free byte payload")
    return bytes(view[pos:end]), end


def decode_prefix_free_bytes(data: bytes | bytearray | memoryview) -> bytes:
    """Decode an exact buffer produced by `encode_prefix_free_bytes`."""
    out, end = unpack_prefix_free_bytes(data, 0)
    if end != len(data):
        raise ValueError("Trailing bytes in prefix-free byte payload")
    return out


def encode_index_key(key: IndexKey) -> bytes:
    """Encode an int, tuple of ints, or byte string into disjoint prefix-free keys."""
    if type(key) is int:
        return b"I" + encode_u64(key)
    if isinstance(key, tuple):
        return b"T" + encode_u64_tuple(key)
    if isinstance(key, (bytes, bytearray, memoryview)):
        return b"B" + encode_prefix_free_bytes(key)
    raise TypeError(f"Unsupported index key type: {type(key).__name__}")


class DiskNamespace:
    """Named sub-view over a `DiskCappedIndex`."""

    def __init__(self, index: DiskCappedIndex, name: str, namespace_id: int) -> None:
        self._index = index
        self.name = name
        self.namespace_id = namespace_id

    def __len__(self) -> int:
        return self._index._ns_counts.get(self.namespace_id, 0)

    def __contains__(self, key: IndexKey) -> bool:
        return self._index.contains(key, namespace=self.namespace_id)

    def add(self, key: IndexKey) -> bool:
        return self._index.add(key, namespace=self.namespace_id)

    def add_many(self, keys: Iterable[IndexKey]) -> int:
        return self._index.add_many(keys, namespace=self.namespace_id)


class DiskCappedIndex:
    """Temporary SQLite `WITHOUT ROWID` deduplication index with a strict disk byte cap."""

    def __init__(
        self,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        page_size: int = DEFAULT_PAGE_SIZE,
        cache_kb: int = 16384,
    ) -> None:
        if type(page_size) is not int or page_size < 512 or page_size > 65536 or (page_size & (page_size - 1)):
            raise ValueError(f"Invalid SQLite page_size: {page_size!r}")
        if (
            type(max_bytes) is not int
            or max_bytes < 2 * page_size
            or max_bytes > MAX_ALLOWED_BYTES
            or max_bytes % page_size != 0
        ):
            raise ValueError(
                f"max_bytes must be a multiple of {page_size} in [{2 * page_size}, {MAX_ALLOWED_BYTES}]"
            )
        if type(cache_kb) is not int or cache_kb <= 0:
            raise ValueError("cache_kb must be a positive integer")

        self.max_bytes = max_bytes
        self.page_size = page_size
        self.max_pages = max_bytes // page_size

        self._directory = tempfile.TemporaryDirectory(prefix="sim-verify-index-")
        self.path = Path(self._directory.name) / "index.sqlite"
        self._db: sqlite3.Connection | None = sqlite3.connect(self.path)
        self._closed = False
        self._count = 0
        self._ns_counts: dict[int, int] = {}
        self._namespaces: dict[str, int] = {"default": 0}

        try:
            self._db.execute(f"PRAGMA page_size={self.page_size}")
            self._db.execute("PRAGMA journal_mode=OFF")
            self._db.execute("PRAGMA synchronous=OFF")
            self._db.execute(f"PRAGMA cache_size=-{cache_kb}")
            self._db.execute(f"PRAGMA max_page_count={self.max_pages}")
            self._db.execute(
                "CREATE TABLE seen ("
                "namespace INTEGER NOT NULL, "
                "identity BLOB NOT NULL, "
                "PRIMARY KEY(namespace, identity)"
                ") WITHOUT ROWID"
            )
        except Exception:
            self.close()
            raise

    @property
    def count(self) -> int:
        return self._count

    def __len__(self) -> int:
        return self._count

    @property
    def db_size_bytes(self) -> int:
        if self._closed or not self.path.exists():
            return 0
        return self.path.stat().st_size

    @property
    def temp_dir(self) -> Path:
        return Path(self._directory.name)

    def _require_open(self) -> sqlite3.Connection:
        if self._closed or self._db is None:
            raise RuntimeError("DiskCappedIndex is closed")
        return self._db

    def namespace(self, name: str) -> DiskNamespace:
        """Return a named sub-namespace sharing the same bounded database."""
        self._require_open()
        if name not in self._namespaces:
            self._namespaces[name] = len(self._namespaces)
        return DiskNamespace(self, name, self._namespaces[name])

    def contains(self, key: IndexKey, *, namespace: int = 0) -> bool:
        db = self._require_open()
        blob = encode_index_key(key)
        try:
            row = db.execute(
                "SELECT 1 FROM seen WHERE namespace=? AND identity=?",
                (namespace, blob),
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise DiskQuotaExceededError(f"Disk index lookup failed: {exc}") from exc
        return row is not None

    def __contains__(self, key: object) -> bool:
        return self.contains(key, namespace=0)  # type: ignore[arg-type]

    def add(self, key: IndexKey, *, namespace: int = 0) -> bool:
        """Insert `key`; return True if newly added or False if already present."""
        db = self._require_open()
        blob = encode_index_key(key)
        before = db.total_changes
        try:
            db.execute(
                "INSERT OR IGNORE INTO seen (namespace, identity) VALUES (?, ?)",
                (namespace, blob),
            )
        except sqlite3.DatabaseError as exc:
            raise DiskQuotaExceededError(f"Disk index quota exceeded: {exc}") from exc
        inserted = db.total_changes - before
        if inserted:
            self._count += inserted
            self._ns_counts[namespace] = self._ns_counts.get(namespace, 0) + inserted
            return True
        return False

    def add_many(self, keys: Iterable[IndexKey], *, namespace: int = 0) -> int:
        """Batch-insert `keys` and return the count of newly inserted unique entries."""
        db = self._require_open()
        rows = [(namespace, encode_index_key(k)) for k in keys]
        if not rows:
            return 0
        before = db.total_changes
        try:
            with db:
                db.executemany(
                    "INSERT OR IGNORE INTO seen (namespace, identity) VALUES (?, ?)",
                    rows,
                )
        except sqlite3.DatabaseError as exc:
            raise DiskQuotaExceededError(f"Disk index quota exceeded: {exc}") from exc
        inserted = db.total_changes - before
        if inserted:
            self._count += inserted
            self._ns_counts[namespace] = self._ns_counts.get(namespace, 0) + inserted
        return inserted

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._db is not None:
            try:
                self._db.close()
            finally:
                self._db = None
        self._directory.cleanup()

    def __enter__(self) -> DiskCappedIndex:
        return self

    def __exit__(self, *unused: object) -> None:
        self.close()
