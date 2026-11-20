"""Streaming boundary index, O(1)-seek random-access reader, interval profiler,
schedule-invariant cross-frame unit pairing, and deterministic start-gate / split model.

Fully wire-compatible with `sim_verify.boundary_recorder` (`BDRCREC1` / `BDRC`).
Pure Python stdlib (no NumPy required).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
import math
import mmap
import os
from pathlib import Path
import struct
from typing import Any, Iterable, Sequence
import zlib

from .boundary_recorder import (
    FormatError,
    FrameRecord,
    HEADER_SIZE,
    K_END,
    K_EVENT,
    K_FOOTER,
    K_FRAME,
    K_RUN,
    K_RUN_END,
    K_UNIT,
    MAGIC,
    REC_MAGIC,
    UnitBlock,
    VERSION,
    _unpack_blocks,
)

Frame = FrameRecord


def build_stream_index(path: str | Path) -> dict[str, Any]:
    """Verify every CRC32, sequence number, nesting invariant, and chained footer
    in a single sequential pass, storing only byte offsets in memory.
    """
    file_path = Path(path)
    file_size = file_path.stat().st_size
    out: dict[str, Any] = {
        "schema": "sim_verify-boundary-index-v1",
        "path": str(file_path),
        "size": file_size,
        "frames": [],
        "stray_events": [],
        "records": 0,
    }

    with open(file_path, "rb", buffering=0) as f:
        head = f.read(HEADER_SIZE)
        if len(head) != HEADER_SIZE or head[:8] != MAGIC:
            raise FormatError("not a BDRCREC1 stream")
        ver, hs = struct.unpack_from("<II", head, 8)
        if ver != VERSION or hs != HEADER_SIZE or any(head[16:]):
            raise FormatError("invalid stream header")
        out["version"] = ver

        offset = HEADER_SIZE
        seq = 0
        chain = 0
        cur: dict[str, Any] | None = None
        footer: dict[str, int] | None = None

        while True:
            hdr = f.read(32)
            if not hdr:
                break
            if footer is not None:
                raise FormatError("bytes after footer")
            if len(hdr) < 32:
                raise FormatError(f"truncated record header at {offset}")

            magic, kind, flags, size, crc, rec_seq, res = struct.unpack("<IHHIIQQ", hdr)
            if magic != REC_MAGIC or res:
                raise FormatError(f"bad record magic at {offset}")
            if rec_seq != seq:
                raise FormatError(f"record sequence gap: expected {seq} got {rec_seq}")

            payload = f.read(size)
            if len(payload) != size:
                raise FormatError(f"truncated payload at {offset}")

            hdr0 = struct.pack("<IHHIIQQ", REC_MAGIC, kind, flags, size, 0, rec_seq, 0)
            expected_crc = zlib.crc32(payload, zlib.crc32(hdr0)) & 0xFFFFFFFF
            if expected_crc != crc:
                raise FormatError(f"crc mismatch in record {rec_seq}")

            if kind != K_FOOTER:
                chain = zlib.crc32(struct.pack("<I", crc), chain) & 0xFFFFFFFF

            if kind == K_RUN:
                if len(payload) < 92:
                    raise FormatError(f"truncated K_RUN payload at {offset}")
                out["run_offset"] = offset
            elif kind == K_FRAME:
                if cur is not None:
                    raise FormatError(f"nested frame at record {rec_seq}")
                if len(payload) < 40:
                    raise FormatError(f"truncated K_FRAME payload at {offset}")
                fs, tk, th = struct.unpack_from("<QQI", payload, 0)
                cur = {
                    "seq": fs,
                    "tick": tk,
                    "thread": th,
                    "begin": [offset, size],
                    "units": [],
                    "events": [],
                }
            elif kind == K_UNIT:
                if cur is None:
                    raise FormatError("unit block outside frame")
                if len(payload) < 40:
                    raise FormatError(f"truncated K_UNIT payload at {offset}")
                ph, st, werr, order, unit = struct.unpack_from("<BBHIQ", payload, 0)
                cur["units"].append([offset, size, ph, st, werr, order, unit])
            elif kind == K_EVENT:
                if len(payload) < 40:
                    raise FormatError(f"truncated K_EVENT payload at {offset}")
                target = cur["events"] if cur is not None else out["stray_events"]
                target.append([offset, size])
            elif kind == K_END:
                if cur is None:
                    raise FormatError("frame end outside frame")
                if len(payload) < 32:
                    raise FormatError(f"truncated K_END payload at {offset}")
                _, _, stt, _, _ = struct.unpack_from("<QIIII", payload, 0)
                cur["end"] = [offset, size]
                cur["status"] = stt
                out["frames"].append(cur)
                cur = None
            elif kind == K_RUN_END:
                if len(payload) < 4:
                    raise FormatError(f"truncated K_RUN_END payload at {offset}")
                out["run_end_offset"] = offset
            elif kind == K_FOOTER:
                if len(payload) != 28:
                    raise FormatError(f"invalid K_FOOTER size at {offset}")
                cnt, nf, ni, ch = struct.unpack("<QQQI", payload)
                invalid_count = sum(1 for fr in out["frames"] if fr["status"])
                if cnt != seq + 1 or nf != len(out["frames"]) or ni != invalid_count or ch != chain:
                    raise FormatError("footer mismatch")
                footer = {"records": cnt, "frames": nf, "invalid": ni}
            else:
                raise FormatError(f"unknown record kind {kind}")

            seq += 1
            offset += 32 + size

        if footer is None or cur is not None:
            raise FormatError("truncated stream")

    out["footer"] = footer
    out["records"] = seq
    return out


class IndexedBoundaryReader:
    """O(1)-seek random-access reader for `BDRCREC1` boundary streams."""

    def __init__(self, path: str | Path, index: dict[str, Any] | None = None) -> None:
        self.path = Path(path)
        self.index = index if index is not None else build_stream_index(self.path)
        self.by_seq: dict[int, dict[str, Any]] = {
            fr["seq"]: fr for fr in self.index["frames"]
        }
        self._f = open(self.path, "rb")
        self._closed = False

    def __len__(self) -> int:
        return len(self.index["frames"])

    @property
    def frame_seqs(self) -> list[int]:
        return [fr["seq"] for fr in self.index["frames"]]

    def _read_payload(self, offset: int, size: int) -> bytes:
        if self._closed:
            raise RuntimeError("IndexedBoundaryReader is closed")
        self._f.seek(offset + 32)
        payload = self._f.read(size)
        if len(payload) != size:
            raise FormatError(f"truncated payload at {offset}")
        return payload

    def _read_record_payload(self, offset: int) -> bytes:
        if self._closed:
            raise RuntimeError("IndexedBoundaryReader is closed")
        self._f.seek(offset)
        hdr = self._f.read(32)
        if len(hdr) != 32:
            raise FormatError(f"truncated record header at {offset}")
        _, _, _, size, _, _, _ = struct.unpack("<IHHIIQQ", hdr)
        payload = self._f.read(size)
        if len(payload) != size:
            raise FormatError(f"truncated payload at {offset}")
        return payload

    def run(self) -> dict[str, Any] | None:
        offset = self.index.get("run_offset")
        if offset is None:
            return None
        payload = self._read_record_payload(offset)
        fl, pid, _, _, tl = struct.unpack_from("<IIQQI", payload, 64)
        return {
            "rules_sha256": payload[:32].hex().upper(),
            "binary_sha256": payload[32:64].hex().upper(),
            "frame_limit": fl,
            "pid": pid,
            "info": json.loads(payload[92 : 92 + tl]),
        }

    def run_end(self) -> dict[str, Any] | None:
        offset = self.index.get("run_end_offset")
        if offset is None:
            return None
        payload = self._read_record_payload(offset)
        (tl,) = struct.unpack_from("<I", payload, 0)
        return json.loads(payload[4 : 4 + tl])

    def outside_events(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for offset, size in self.index.get("stray_events", ()):
            ep = self._read_payload(offset, size)
            ev, _, val, obj, _, fs, th, _ = struct.unpack("<HHIQQQII", ep)
            out.append(
                {
                    "kind": ev,
                    "value": val,
                    "object": obj,
                    "frame_seq": fs,
                    "thread": th,
                }
            )
        return out

    def frame(self, seq: int, units: Iterable[int] | None = None) -> FrameRecord:
        """Load and decode a single `FrameRecord` by sequence ID in O(1) seek time."""
        fr = self.by_seq[seq]
        unit_filter = set(units) if units is not None else None

        begin_payload = self._read_payload(*fr["begin"])
        fs, tk, th, _, _, _, _ = struct.unpack_from("<QQIIQiI", begin_payload, 0)
        globals_blocks, _ = _unpack_blocks(begin_payload, 40)
        record = FrameRecord(fs, tk, th, globals_blocks)

        for offset, size, _, _, _, _, unit_id in fr["units"]:
            if unit_filter is not None and unit_id not in unit_filter:
                continue
            up = self._read_payload(offset, size)
            ph, st, werr, order, unit, _, th2, _, nr, nb = struct.unpack_from(
                "<BBHIQQIiII", up, 0
            )
            pos = 40
            regs: list[tuple[int, int, int]] = []
            for _ in range(nr):
                addr, sz, cat, _ = struct.unpack_from("<QIHH", up, pos)
                pos += 16
                regs.append((addr, sz, cat))
            blocks, _ = _unpack_blocks(struct.pack("<I", nb) + up[pos:], 0)
            record.units.append(
                UnitBlock(ph, st, order, unit, th2, regs, blocks, walk_error=werr)
            )

        for offset, size in fr["events"]:
            ep = self._read_payload(offset, size)
            ev, _, val, obj, _, efs, eth, _ = struct.unpack("<HHIQQQII", ep)
            record.events.append(
                {
                    "kind": ev,
                    "value": val,
                    "object": obj,
                    "frame_seq": efs,
                    "thread": eth,
                }
            )

        end_payload = self._read_payload(*fr["end"])
        _, th_e, stt, nu, mask, _ = struct.unpack("<QIIIIQ", end_payload)
        record.end = {
            "thread": th_e,
            "status": stt,
            "units": nu,
            "changed_mask": mask,
        }
        return record

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._f.close()

    def __enter__(self) -> IndexedBoundaryReader:
        return self

    def __exit__(self, *unused: object) -> None:
        self.close()


def _linear_quantile(sorted_vals: Sequence[float], q: float) -> float:
    n = len(sorted_vals)
    if n == 0:
        return 0.0
    if n == 1:
        return float(sorted_vals[0])
    pos = q * (n - 1)
    lo = math.floor(pos)
    hi = math.ceil(pos)
    frac = pos - lo
    return float(sorted_vals[lo] + frac * (sorted_vals[hi] - sorted_vals[lo]))


def compute_quantiles(values: Sequence[float]) -> dict[str, float | int]:
    """Compute pure-Python summary quantiles (`n`, `median`, `p05`, `p95`, `mean`, `max`)."""
    n = len(values)
    if n == 0:
        return {"n": 0, "median": 0.0, "p05": 0.0, "p95": 0.0, "mean": 0.0, "max": 0.0}
    s = sorted(float(x) for x in values)
    return {
        "n": n,
        "median": _linear_quantile(s, 0.5),
        "p05": _linear_quantile(s, 0.05),
        "p95": _linear_quantile(s, 0.95),
        "mean": sum(s) / n,
        "max": s[-1],
    }


def pearson_corr(xs: Sequence[float], ys: Sequence[float]) -> float:
    """Compute pure-Python Pearson correlation; returns 0.0 if degenerate (`n < 2` or zero variance)."""
    n = len(xs)
    if n != len(ys):
        raise ValueError("Series lengths must match")
    if n < 2:
        return 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = 0.0
    sum_xx = 0.0
    sum_yy = 0.0
    for x, y in zip(xs, ys):
        dx = float(x) - mean_x
        dy = float(y) - mean_y
        num += dx * dy
        sum_xx += dx * dx
        sum_yy += dy * dy
    denom = math.sqrt(sum_xx * sum_yy)
    if denom == 0.0:
        return 0.0
    return max(-1.0, min(1.0, num / denom))


def profile_stream_intervals(path: str | Path) -> dict[str, Any]:
    """`mmap`-backed telemetry scanner computing step quantiles and jitter correlations."""
    file_path = Path(path)
    rows: list[dict[str, int]] = []
    freq = 10_000_000

    with open(file_path, "rb") as fh:
        file_size = os.fstat(fh.fileno()).st_size
        if file_size < HEADER_SIZE:
            raise FormatError("not a BDRCREC1 stream")
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            if mm[:8] != MAGIC:
                raise FormatError("not a BDRCREC1 stream")
            ver, hs = struct.unpack_from("<II", mm, 8)
            if ver != VERSION or hs != HEADER_SIZE or any(mm[16:HEADER_SIZE]):
                raise FormatError("invalid stream header")

            offset = HEADER_SIZE
            cur: dict[str, int] | None = None
            while offset < file_size:
                if offset + 32 > file_size:
                    raise FormatError(f"truncated record header at {offset}")
                magic, kind, _, size, _, _, _ = struct.unpack_from("<IHHIIQQ", mm, offset)
                if magic != REC_MAGIC:
                    raise FormatError(f"bad record magic at {offset}")
                p = offset + 32
                if p + size > file_size:
                    raise FormatError(f"truncated payload at {offset}")

                if kind == K_RUN:
                    _, _, _, raw_freq, _ = struct.unpack_from("<IIQQI", mm, p + 64)
                    if raw_freq:
                        freq = raw_freq
                elif kind == K_FRAME:
                    fs, tk, th, rflags, qpc, _, _ = struct.unpack_from("<QQIIQiI", mm, p)
                    cur = {
                        "seq": fs,
                        "tick": tk,
                        "thread": th,
                        "flags": rflags,
                        "qpc": qpc,
                        "bytes": 32 + size,
                    }
                elif cur is not None and kind in (K_UNIT, K_EVENT):
                    cur["bytes"] += 32 + size
                elif kind == K_END:
                    if cur is None:
                        raise FormatError("frame end outside frame")
                    _, _, stt, _, _, write_ticks = struct.unpack_from("<QIIIIQ", mm, p)
                    cur["bytes"] += 32 + size
                    cur["status"] = stt
                    cur["write_ticks"] = write_ticks
                    rows.append(cur)
                    cur = None

                offset = p + size

    by_seq = {r["seq"]: r for r in rows}
    pairs = [(r, by_seq[r["seq"] + 1]) for r in rows if (r["seq"] + 1) in by_seq]

    dt_tick = [float(b["tick"] - a["tick"]) for a, b in pairs]
    dt_qpc_ms = [float(b["qpc"] - a["qpc"]) * 1000.0 / freq for a, b in pairs]
    bytes_per_pair = [float(a["bytes"]) for a, _ in pairs]
    write_ms = [float(a["write_ticks"]) * 1000.0 / freq for a, _ in pairs]
    total_bytes = sum(r["bytes"] for r in rows)

    return {
        "schema": "sim_verify-stream-intervals-v1",
        "path": str(file_path),
        "version": ver,
        "qpc_frequency": freq,
        "frames": len(rows),
        "pairs": len(pairs),
        "total_bytes": total_bytes,
        "tick_step": compute_quantiles(dt_tick),
        "qpc_step_ms": compute_quantiles(dt_qpc_ms),
        "bytes_per_frame": compute_quantiles(bytes_per_pair),
        "write_ms_per_frame": compute_quantiles(write_ms),
        "corr_qpc_step_vs_bytes": pearson_corr(dt_qpc_ms, bytes_per_pair),
        "corr_qpc_step_vs_write_ms": pearson_corr(dt_qpc_ms, write_ms),
        "corr_tick_step_vs_bytes": pearson_corr(dt_tick, bytes_per_pair),
    }


def pair_cross_frame_invariant(frames: Sequence[FrameRecord]) -> dict[str, Any]:
    """Build schedule-invariant `(unit_id, occurrence_index)` cross-frame pairings
    while preserving intra-frame `(unit_id, order)` entry/exit pairing.
    """
    intra_frame: dict[int, dict[tuple[int, int], dict[int, UnitBlock]]] = {}
    ord_to_occ: dict[int, dict[tuple[int, int], int]] = {}
    by_occ: dict[int, dict[tuple[int, int], dict[int, UnitBlock]]] = {}

    for frame in frames:
        intra: dict[tuple[int, int], dict[int, UnitBlock]] = {}
        by_unit: dict[int, dict[int, dict[int, UnitBlock]]] = {}
        for block in frame.units:
            intra.setdefault((block.unit, block.order), {})[block.phase] = block
            if block.phase in (0, 1):
                by_unit.setdefault(block.unit, {}).setdefault(block.order, {})[block.phase] = block

        o2k: dict[tuple[int, int], int] = {}
        occ_map: dict[tuple[int, int], dict[int, UnitBlock]] = {}
        for unit_id, order_map in by_unit.items():
            for occ, order in enumerate(sorted(order_map)):
                o2k[(unit_id, order)] = occ
                occ_map[(unit_id, occ)] = order_map[order]

        intra_frame[frame.seq] = intra
        ord_to_occ[frame.seq] = o2k
        by_occ[frame.seq] = occ_map

    cross_frame: dict[
        tuple[int, int], dict[tuple[int, int], tuple[UnitBlock | None, UnitBlock | None]]
    ] = {}
    for prev, curr in zip(frames, frames[1:]):
        prev_occ = by_occ[prev.seq]
        curr_occ = by_occ[curr.seq]
        transitions: dict[tuple[int, int], tuple[UnitBlock | None, UnitBlock | None]] = {}
        for key in sorted(set(prev_occ) | set(curr_occ)):
            prev_exit = prev_occ.get(key, {}).get(1)
            curr_entry = curr_occ.get(key, {}).get(0)
            transitions[key] = (prev_exit, curr_entry)
        cross_frame[(prev.seq, curr.seq)] = transitions

    return {
        "intra_frame": intra_frame,
        "ord_to_occ": ord_to_occ,
        "by_occ": by_occ,
        "cross_frame": cross_frame,
    }


class MonotonicStartGate:
    """Deterministic one-way start gate requiring `required_increases` strict increases.

    Rules:
    - An inactive observation (`active=False`) resets accumulated state before opening.
    - An equal tick neither increments the streak nor resets it.
    - A decreasing tick resets the streak to 0 and makes that tick the new baseline.
    - Once opened, the gate remains open permanently (one-way).
    """

    def __init__(self, required_increases: int = 2) -> None:
        if type(required_increases) is not int or required_increases < 1:
            raise ValueError("required_increases must be a positive integer")
        self.required_increases = required_increases
        self.have = False
        self.streak = 0
        self.last_tick = 0
        self.opened = False

    @property
    def is_open(self) -> bool:
        return self.opened

    def reset(self) -> None:
        self.have = False
        self.streak = 0
        self.last_tick = 0
        self.opened = False

    def observe(self, tick: int, active: bool = True) -> bool:
        if self.opened:
            return True
        if not active:
            self.have = False
            self.streak = 0
            return False
        if not self.have:
            self.have = True
            self.last_tick = tick
            self.streak = 0
            return False
        if tick > self.last_tick:
            self.last_tick = tick
            self.streak += 1
            if self.streak >= self.required_increases:
                self.opened = True
                return True
            return False
        if tick < self.last_tick:
            self.last_tick = tick
            self.streak = 0
        return False


class BoundaryKind(str, Enum):
    """Deterministic frame-boundary classification labels."""

    GATE = "GATE"
    TIME_ADVANCE = "TIME_ADVANCE"
    UNIT_REPEAT_PAUSED = "UNIT_REPEAT_PAUSED"
    AUXILIARY = "AUXILIARY"


@dataclass
class SplitFrame:
    """One logical frame emitted by `FrameSplitStateMachine`."""

    tick: int
    boundary: BoundaryKind
    paused: bool
    host_paused: bool = False
    dispatches: int = 0
    auxiliary_events: int = 0
    units: list[int] = field(default_factory=list)


class FrameSplitStateMachine:
    """Deterministic frame-boundary classifier paired with `MonotonicStartGate`."""

    def __init__(self, frame_limit: int = 0, *, required_increases: int = 2) -> None:
        if type(frame_limit) is not int or frame_limit < 0:
            raise ValueError("frame_limit must be a non-negative integer")
        self.frame_limit = frame_limit
        self.gate = MonotonicStartGate(required_increases=required_increases)
        self.gate_open = False
        self.start_tick: int | None = None
        self.frames: list[SplitFrame] = []
        self.current_frame: SplitFrame | None = None
        self.done = False
        self.stop_reason: str | None = None

    def _begin(self, tick: int, boundary: BoundaryKind, *, host_paused: bool = False) -> None:
        if self.frame_limit and len(self.frames) >= self.frame_limit:
            self.done = True
            self.stop_reason = "frame_limit_reached"
            return
        self.current_frame = SplitFrame(
            tick=tick,
            boundary=boundary,
            paused=(boundary == BoundaryKind.UNIT_REPEAT_PAUSED),
            host_paused=host_paused,
        )

    def _close(self) -> None:
        if self.current_frame is None:
            return
        self.frames.append(self.current_frame)
        self.current_frame = None
        if self.frame_limit and len(self.frames) >= self.frame_limit:
            self.done = True
            self.stop_reason = "frame_limit_reached"

    def dispatch(
        self,
        unit_id: int,
        tick: int,
        *,
        active: bool = True,
        paused: bool = False,
        readable: bool = True,
    ) -> SplitFrame | None:
        """Process one unit dispatch at logical `tick`."""
        if self.done:
            return None

        if not self.gate_open:
            if not readable:
                self.gate.observe(tick, active=False)
                return None
            if not self.gate.observe(tick, active=active):
                return None
            self.gate_open = True
            self.start_tick = tick
            self._begin(tick, BoundaryKind.GATE, host_paused=paused)
        elif not readable:
            self.done = True
            self.stop_reason = "state_unreadable"
            return None
        elif not active:
            self._close()
            if not self.done:
                self.done = True
                self.stop_reason = "inactive"
            return None
        else:
            boundary: BoundaryKind | None = None
            if self.current_frame is None or tick != self.current_frame.tick:
                boundary = BoundaryKind.TIME_ADVANCE
            elif unit_id in self.current_frame.units:
                boundary = BoundaryKind.UNIT_REPEAT_PAUSED

            if boundary is not None:
                self._close()
                if self.done:
                    return None
                self._begin(tick, boundary, host_paused=paused)

        if self.current_frame is not None:
            self.current_frame.units.append(unit_id)
            self.current_frame.dispatches += 1
        return self.current_frame

    def auxiliary(self, tick: int, *, paused: bool = False) -> SplitFrame | None:
        """Record an auxiliary event; opens an `AUXILIARY` frame only if none is open."""
        if self.done or not self.gate_open:
            return None
        if self.current_frame is None:
            self._begin(tick, BoundaryKind.AUXILIARY, host_paused=paused)
        if self.current_frame is not None:
            self.current_frame.auxiliary_events += 1
        return self.current_frame

    def stop(self, reason: str = "stopped") -> None:
        if self.done:
            return
        self._close()
        self.done = True
        self.stop_reason = self.stop_reason or reason

    def summary(self) -> dict[str, Any]:
        return {
            "frames": len(self.frames),
            "paused": sum(1 for fr in self.frames if fr.paused),
            "gate_open": self.gate_open,
            "start_tick": self.start_tick,
            "stop_reason": self.stop_reason,
            "dispatches": [fr.dispatches for fr in self.frames],
            "boundaries": [fr.boundary.value for fr in self.frames],
        }
