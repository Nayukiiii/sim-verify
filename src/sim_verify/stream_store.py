"""Bounded dual-hashed stream storage reader and Windows named-pipe repacker.

Provides:
1. Pure-stdlib LZ4 frame header parsing and strict policy validation
   (requiring block checksum, content checksum, bounded block size, and bounded
   logical stream length).
2. `BoundedStreamReader` and `open_bounded_stream`: streaming reader supporting
   both raw uncompressed streams (pure stdlib) and `.lz4` framed streams (using
   the optional `lz4.frame` codec when installed), tracking simultaneous
   physical and logical SHA-256 digests and enforcing hard byte ceilings.
3. `compute_dual_sha256`: single-pass physical + logical digest computation.
4. `NamedPipeRepacker`: Windows zero-disk-copy streaming repacker over a
   `CreateNamedPipeW` byte pipe verifying exact logical SHA-256 equivalence
   between source and repacked destination.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import time
from typing import Any, BinaryIO, Callable, Iterator, Sequence
import uuid

LZ4_MAGIC = b"\x04\x22\x4d\x18"
DEFAULT_MAX_BLOCK_BYTES = 4 * 1024 * 1024  # 4 MiB
DEFAULT_MAX_LOGICAL_BYTES = 128 * 1024 * 1024 * 1024  # 128 GiB

_LZ4_BLOCK_SIZE_MAP = {
    4: 64 * 1024,
    5: 256 * 1024,
    6: 1024 * 1024,
    7: 4 * 1024 * 1024,
}


@dataclass(frozen=True)
class LZ4FrameHeader:
    """Decoded fields from an LZ4 frame header."""

    version: int
    block_independent: bool
    block_checksum: bool
    content_checksum: bool
    block_size_id: int
    block_size: int
    content_size: int | None
    dict_id: int | None
    header_checksum: int
    header_length: int


def parse_lz4_frame_header(data: bytes) -> LZ4FrameHeader:
    """Parse an LZ4 frame header from raw leading bytes without external packages."""
    if len(data) < 7:
        raise ValueError("Truncated LZ4 frame header")
    if data[:4] != LZ4_MAGIC:
        raise ValueError("Invalid LZ4 frame magic")

    flg = data[4]
    bd = data[5]
    version = (flg >> 6) & 0x03
    if version != 1:
        raise ValueError(f"Unsupported LZ4 frame version: {version}")
    if flg & 0x02:
        raise ValueError("Invalid LZ4 FLG reserved bit")
    if bd & 0x8F:
        raise ValueError("Invalid LZ4 BD reserved bits")

    block_independent = bool((flg >> 5) & 1)
    block_checksum = bool((flg >> 4) & 1)
    has_content_size = bool((flg >> 3) & 1)
    content_checksum = bool((flg >> 2) & 1)
    has_dict_id = bool(flg & 1)

    block_size_id = (bd >> 4) & 0x07
    block_size = _LZ4_BLOCK_SIZE_MAP.get(block_size_id)
    if block_size is None:
        raise ValueError(f"Invalid LZ4 block size descriptor: {block_size_id}")

    pos = 6
    content_size: int | None = None
    if has_content_size:
        if len(data) < pos + 8 + 1:
            raise ValueError("Truncated LZ4 frame content size")
        (content_size,) = struct.unpack_from("<Q", data, pos)
        pos += 8

    dict_id: int | None = None
    if has_dict_id:
        if len(data) < pos + 4 + 1:
            raise ValueError("Truncated LZ4 frame dictionary ID")
        (dict_id,) = struct.unpack_from("<I", data, pos)
        pos += 4

    if len(data) < pos + 1:
        raise ValueError("Truncated LZ4 frame header checksum")
    header_checksum = data[pos]
    header_length = pos + 1

    return LZ4FrameHeader(
        version=version,
        block_independent=block_independent,
        block_checksum=block_checksum,
        content_checksum=content_checksum,
        block_size_id=block_size_id,
        block_size=block_size,
        content_size=content_size,
        dict_id=dict_id,
        header_checksum=header_checksum,
        header_length=header_length,
    )


def validate_lz4_frame_header(
    data: bytes,
    *,
    max_block_bytes: int = DEFAULT_MAX_BLOCK_BYTES,
    max_logical_bytes: int = DEFAULT_MAX_LOGICAL_BYTES,
) -> LZ4FrameHeader:
    """Validate an LZ4 frame header against sim-verify bounded-storage requirements."""
    header = parse_lz4_frame_header(data)
    if not header.block_checksum or not header.content_checksum:
        raise ValueError("LZ4 stream requires both block_checksum and content_checksum")
    if header.block_size > max_block_bytes:
        raise ValueError(
            f"LZ4 block size {header.block_size} exceeds limit {max_block_bytes}"
        )
    if header.content_size is not None and header.content_size > max_logical_bytes:
        raise ValueError(
            f"LZ4 declared content size {header.content_size} exceeds limit {max_logical_bytes}"
        )
    return header


class BoundedStreamReader:
    """Bounded streaming reader tracking physical and logical SHA-256 digests."""

    def __init__(
        self,
        source: BinaryIO,
        *,
        compressed: bool = False,
        max_logical_bytes: int = DEFAULT_MAX_LOGICAL_BYTES,
        max_block_bytes: int = DEFAULT_MAX_BLOCK_BYTES,
    ) -> None:
        if max_logical_bytes <= 0 or max_block_bytes <= 0:
            raise ValueError("Byte limits must be positive")
        self.source = source
        self.compressed = compressed
        self.max_logical_bytes = int(max_logical_bytes)
        self.max_block_bytes = int(max_block_bytes)

        self._physical_digest = hashlib.sha256()
        self._logical_digest = hashlib.sha256()
        self._physical_bytes = 0
        self._logical_bytes = 0

        self._buffer = b""
        self._offset = 0
        self._done = False
        self._first_chunk = True
        self._codec = None
        self._decoder = None

        if self.compressed:
            try:
                import lz4.frame  # type: ignore[import-not-found]
            except ImportError as exc:
                raise ImportError(
                    "Reading .lz4 streams requires the optional 'lz4' package"
                ) from exc
            self._codec = lz4.frame
            self._decoder = lz4.frame.LZ4FrameDecompressor()

    @property
    def storage_encoding(self) -> str:
        return "lz4-frame-checksummed-v1" if self.compressed else "raw-uncompressed-v1"

    @property
    def physical_sha256(self) -> str:
        return self._physical_digest.hexdigest().upper()

    @property
    def logical_sha256(self) -> str:
        return self._logical_digest.hexdigest().upper()

    @property
    def physical_bytes(self) -> int:
        return self._physical_bytes

    @property
    def logical_bytes(self) -> int:
        return self._logical_bytes

    def tell(self) -> int:
        return self._logical_bytes

    def _read_raw_bounded(self, size: int) -> bytes:
        if self._done:
            return b""
        chunk = self.source.read(size)
        if not chunk:
            self._done = True
            return b""
        self._physical_digest.update(chunk)
        self._physical_bytes += len(chunk)
        self._logical_bytes += len(chunk)
        if self._logical_bytes > self.max_logical_bytes:
            raise ValueError("Stream logical byte limit exceeded")
        self._logical_digest.update(chunk)
        return chunk

    def _read_lz4_header_chunk(self) -> bytes:
        """Read enough initial bytes to inspect the full LZ4 frame header."""
        read_size = min(max(self.max_block_bytes, 64), 1024 * 1024)
        buf = self.source.read(read_size)
        if not buf:
            raise ValueError("Truncated LZ4 frame")
        while len(buf) < 19:
            more = self.source.read(read_size)
            if not more:
                break
            buf += more
        return buf

    def _fill_lz4(self) -> bool:
        assert self._codec is not None and self._decoder is not None
        if self._done:
            return False

        while True:
            if self._first_chunk:
                chunk = self._read_lz4_header_chunk()
                validate_lz4_frame_header(
                    chunk,
                    max_block_bytes=self.max_block_bytes,
                    max_logical_bytes=self.max_logical_bytes,
                )
                try:
                    info = self._codec.get_frame_info(chunk)
                except (RuntimeError, ValueError, EOFError) as exc:
                    raise ValueError(f"Invalid LZ4 frame header: {exc}") from exc
                if (
                    not info.get("content_checksum")
                    or not info.get("block_checksum")
                    or info.get("block_size", 0) > self.max_block_bytes
                ):
                    raise ValueError("LZ4 stream violates checksum or block-size policy")
                self._first_chunk = False
            elif self._decoder.needs_input:
                chunk = self.source.read(min(self.max_block_bytes, 1024 * 1024))
                if not chunk:
                    raise ValueError("Truncated LZ4 frame")
            else:
                chunk = b""

            if chunk:
                self._physical_digest.update(chunk)
                self._physical_bytes += len(chunk)

            try:
                decoded = self._decoder.decompress(chunk, max_length=self.max_block_bytes)
            except (RuntimeError, EOFError) as exc:
                raise ValueError(f"Invalid LZ4 stream payload: {exc}") from exc

            if self._decoder.eof:
                if self._decoder.unused_data or self.source.read(1):
                    raise ValueError("Trailing data after LZ4 frame")
                self._done = True

            self._buffer = decoded
            self._offset = 0
            if decoded:
                return True
            if self._done:
                return False

    def read(self, size: int) -> bytes:
        """Read up to `size` logical bytes, bounded by `max_block_bytes` and `max_logical_bytes`."""
        if type(size) is not int or size < 0 or size > self.max_block_bytes:
            raise ValueError(f"Read size must be an integer in [0, {self.max_block_bytes}]")
        if size == 0:
            return b""

        if not self.compressed:
            pieces: list[bytes] = []
            remaining = size
            while remaining:
                chunk = self._read_raw_bounded(remaining)
                if not chunk:
                    break
                pieces.append(chunk)
                remaining -= len(chunk)
            return b"".join(pieces)

        pieces = []
        remaining = size
        while remaining:
            if self._offset == len(self._buffer) and not self._fill_lz4():
                break
            take = min(remaining, len(self._buffer) - self._offset)
            slice_bytes = self._buffer[self._offset : self._offset + take]
            self._offset += take
            remaining -= take
            self._logical_bytes += take
            if self._logical_bytes > self.max_logical_bytes:
                raise ValueError("Stream logical byte limit exceeded")
            self._logical_digest.update(slice_bytes)
            pieces.append(slice_bytes)
        return b"".join(pieces)


@contextmanager
def open_bounded_stream(
    path: str | Path,
    max_logical_bytes: int = DEFAULT_MAX_LOGICAL_BYTES,
    max_block_bytes: int = DEFAULT_MAX_BLOCK_BYTES,
) -> Iterator[BoundedStreamReader]:
    """Open a raw or `.lz4` framed file with bounded reads and dual SHA-256 tracking."""
    file_path = Path(path)
    with file_path.open("rb") as source:
        prefix = source.read(4)
        source.seek(0)
        is_lz4 = prefix == LZ4_MAGIC or file_path.suffix.lower() == ".lz4"
        yield BoundedStreamReader(
            source,
            compressed=is_lz4,
            max_logical_bytes=max_logical_bytes,
            max_block_bytes=max_block_bytes,
        )


def compute_dual_sha256(
    source: str | Path | BoundedStreamReader,
    *,
    max_logical_bytes: int = DEFAULT_MAX_LOGICAL_BYTES,
    max_block_bytes: int = DEFAULT_MAX_BLOCK_BYTES,
) -> tuple[str, str, int, int]:
    """Return `(physical_sha256, logical_sha256, physical_bytes, logical_bytes)`."""
    if isinstance(source, BoundedStreamReader):
        chunk_size = source.max_block_bytes
        while source.read(chunk_size):
            pass
        return (
            source.physical_sha256,
            source.logical_sha256,
            source.physical_bytes,
            source.logical_bytes,
        )

    with open_bounded_stream(
        source,
        max_logical_bytes=max_logical_bytes,
        max_block_bytes=max_block_bytes,
    ) as reader:
        while reader.read(reader.max_block_bytes):
            pass
        return (
            reader.physical_sha256,
            reader.logical_sha256,
            reader.physical_bytes,
            reader.logical_bytes,
        )


class NamedPipeRepacker:
    """Windows zero-disk-copy streaming repacker using `CreateNamedPipeW`."""

    def __init__(
        self,
        *,
        pipe_prefix: str = r"\\.\pipe\sim-verify-repack-",
        buffer_bytes: int = DEFAULT_MAX_BLOCK_BYTES,
        connect_timeout_s: float = 30.0,
        process_timeout_s: float = 60.0,
        max_logical_bytes: int = DEFAULT_MAX_LOGICAL_BYTES,
    ) -> None:
        if sys.platform != "win32":
            raise NotImplementedError("NamedPipeRepacker requires Windows named pipes")
        if buffer_bytes <= 0 or buffer_bytes > DEFAULT_MAX_BLOCK_BYTES:
            raise ValueError(f"buffer_bytes must be in (0, {DEFAULT_MAX_BLOCK_BYTES}]")
        self.pipe_prefix = pipe_prefix
        self.buffer_bytes = int(buffer_bytes)
        self.connect_timeout_s = float(connect_timeout_s)
        self.process_timeout_s = float(process_timeout_s)
        self.max_logical_bytes = int(max_logical_bytes)

    def repack(
        self,
        source_path: str | Path,
        dest_path: str | Path,
        converter_cmd: Sequence[str] | Callable[[str, Path], subprocess.Popen[str]],
        *,
        expected_logical_sha256: str | None = None,
        expected_physical_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Stream `source_path` over a Windows named pipe into `converter_cmd` producing `dest_path`."""
        from ctypes import wintypes

        src = Path(source_path).resolve()
        dst = Path(dest_path).resolve()
        dst.parent.mkdir(parents=True, exist_ok=True)

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateNamedPipeW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        kernel.CreateNamedPipeW.restype = wintypes.HANDLE
        kernel.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        kernel.ConnectNamedPipe.restype = wintypes.BOOL
        kernel.SetNamedPipeHandleState.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        kernel.SetNamedPipeHandleState.restype = wintypes.BOOL
        kernel.WriteFile.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        kernel.WriteFile.restype = wintypes.BOOL
        kernel.FlushFileBuffers.argtypes = [wintypes.HANDLE]
        kernel.FlushFileBuffers.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL

        pipe_name = f"{self.pipe_prefix}{uuid.uuid4().hex}"
        # PIPE_ACCESS_OUTBOUND (2), PIPE_NOWAIT (1) during ConnectNamedPipe polling
        handle = kernel.CreateNamedPipeW(
            pipe_name, 2, 1, 1, self.buffer_bytes, 0, 0, None
        )
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())

        if callable(converter_cmd):
            process = converter_cmd(pipe_name, dst)
        else:
            cmd = [str(arg).replace("{pipe}", pipe_name).replace("{output}", str(dst)) for arg in converter_cmd]
            if not any("{pipe}" in str(arg) or "{output}" in str(arg) for arg in converter_cmd):
                cmd.extend([pipe_name, str(dst)])
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

        start = time.perf_counter()
        try:
            deadline = time.monotonic() + self.connect_timeout_s
            while True:
                if kernel.ConnectNamedPipe(handle, None) or ctypes.get_last_error() == 535:
                    break
                err = ctypes.get_last_error()
                if err != 536 or process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(f"Named pipe connection failed (win32 error {err})")
                time.sleep(0.02)

            # Switch to blocking byte-stream mode for WriteFile
            wait_mode = wintypes.DWORD(0)
            if not kernel.SetNamedPipeHandleState(handle, ctypes.byref(wait_mode), None, None):
                raise ctypes.WinError(ctypes.get_last_error())

            with open_bounded_stream(
                src,
                max_logical_bytes=self.max_logical_bytes,
                max_block_bytes=self.buffer_bytes,
            ) as stream:
                while chunk := stream.read(self.buffer_bytes):
                    buf = ctypes.create_string_buffer(chunk)
                    offset = 0
                    while offset < len(chunk):
                        written = wintypes.DWORD()
                        ok = kernel.WriteFile(
                            handle,
                            ctypes.byref(buf, offset),
                            len(chunk) - offset,
                            ctypes.byref(written),
                            None,
                        )
                        if not ok or not written.value:
                            raise ctypes.WinError(ctypes.get_last_error())
                        offset += written.value
                src_phys_sha = stream.physical_sha256
                src_log_sha = stream.logical_sha256
                src_phys_bytes = stream.physical_bytes
                src_log_bytes = stream.logical_bytes

            if expected_logical_sha256 is not None and src_log_sha != expected_logical_sha256.upper():
                raise ValueError("Source logical SHA-256 mismatch")
            if expected_physical_sha256 is not None and src_phys_sha != expected_physical_sha256.upper():
                raise ValueError("Source physical SHA-256 mismatch")

            if not kernel.FlushFileBuffers(handle):
                raise ctypes.WinError(ctypes.get_last_error())
            kernel.CloseHandle(handle)
            handle = None

            stdout, stderr = process.communicate(timeout=self.process_timeout_s)
            if process.returncode != 0:
                raise RuntimeError(f"Converter exited with {process.returncode}: {stderr.strip()}")
        finally:
            if handle is not None:
                kernel.CloseHandle(handle)
            if process.poll() is None:
                process.kill()
                process.wait()

        dst_phys_sha, dst_log_sha, dst_phys_bytes, dst_log_bytes = compute_dual_sha256(
            dst,
            max_logical_bytes=self.max_logical_bytes,
            max_block_bytes=self.buffer_bytes,
        )
        if dst_log_bytes != src_log_bytes or dst_log_sha != src_log_sha:
            raise ValueError("Repacked destination logical bytes differ from source")

        return {
            "schema": "sim_verify-pipe-repack-v1",
            "pipe_name": pipe_name,
            "source_physical_sha256": src_phys_sha,
            "source_logical_sha256": src_log_sha,
            "destination_physical_sha256": dst_phys_sha,
            "destination_logical_sha256": dst_log_sha,
            "source_physical_bytes": src_phys_bytes,
            "destination_physical_bytes": dst_phys_bytes,
            "logical_bytes": src_log_bytes,
            "exact_roundtrip": True,
            "elapsed_seconds": time.perf_counter() - start,
            "converter_stdout": stdout,
        }
