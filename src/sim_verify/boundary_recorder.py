"""Declarative pointer-graph boundary recorder, CRC-chained binary stream (`BDRC`), and self-checker.

Provides:
1. `Rules` and `Walker`: traverses an in-memory or snapshot pointer graph using a declarative
   JSON rule table, merging contiguous/overlapping byte regions and raising structured `WalkError`
   on invalid pointers, inverted vectors, or excessive tree depth.
2. `Writer` and `read_stream`: writes and strictly parses a binary boundary stream (`BDRCREC1`)
   where every record has a header+payload CRC32 and the footer chains all record CRCs to detect
   truncation, reordering, or tampering.
3. `check_stream`: verifies entry-vs-exit read-only categories (`check=true`) and cross-frame
   previous-exit-vs-current-entry categories (`host_may_write=false`), flagging any unattributed
   cross-frame mutation as an unknown writer unless an explaining lifecycle event is recorded.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import struct
from typing import Any, Callable
import zlib

WALK_ERRORS = {
    1: "read fault",
    2: "inverted vector",
    3: "vector over limit",
    4: "unaligned vector",
    5: "unknown child vtable",
    6: "record list without sentinel",
    7: "tree too deep",
    8: "tree over limit",
    9: "unknown tree kind",
    10: "region overflow",
}

MAGIC = b"BDRCREC1"
REC_MAGIC = 0x43524442  # 'BDRC'
VERSION = 1
HEADER_SIZE = 256
K_RUN, K_FRAME, K_UNIT, K_EVENT, K_END, K_RUN_END, K_FOOTER = 1, 2, 3, 4, 5, 6, 0xFFFF

ST_THREAD = 1
ST_READONLY = 2
ST_WALK = 4
ST_OVERFLOW = 8
ST_FAULT = 16
ST_OVERLAP = 32
ST_RUNAWAY = 64
ST_UNPAIRED = 128
ST_RECURSE = 256

STATUS_NAMES = {
    ST_THREAD: "thread changed within one dispatch",
    ST_READONLY: "read-only category mutated during dispatch",
    ST_WALK: "walk error (bad pointer or vector)",
    ST_OVERFLOW: "writer overflow",
    ST_FAULT: "recorder fault or aborted frame",
    ST_OVERLAP: "two calls of one site in flight concurrently",
    ST_RUNAWAY: "frame exceeded block or byte budget",
    ST_UNPAIRED: "exit without matching entry",
    ST_RECURSE: "same-thread recursive re-entry",
}


class ReadFault(Exception):
    pass


class WalkError(Exception):
    def __init__(self, code: int, detail: str = ""):
        super().__init__(f"{WALK_ERRORS.get(code, code)}: {detail}")
        self.code = code
        self.detail = detail


class FormatError(Exception):
    pass


def _h(x: int | str) -> int:
    return int(x, 16) if isinstance(x, str) else int(x)


class Rules:
    def __init__(self, rules_data: dict[str, Any] | Path):
        if isinstance(rules_data, Path):
            raw_bytes = rules_data.read_bytes()
            self.sha256 = hashlib.sha256(raw_bytes).hexdigest().upper()
            self.raw = json.loads(raw_bytes)
        else:
            raw_bytes = json.dumps(rules_data, sort_keys=True).encode("utf-8")
            self.sha256 = hashlib.sha256(raw_bytes).hexdigest().upper()
            self.raw = rules_data
        r = self.raw
        self.limits = {k: _h(v) for k, v in r.get("limits", {"regions": 4096, "tree_depth": 32, "tree_nodes": 1024}).items()}
        self.vtables = {_h(k): v for k, v in r.get("vtables", {}).items()}
        self.categories = list(r["categories"])
        self.cat_index = {c: i for i, c in enumerate(self.categories)}
        self.check = {c for c, v in r["categories"].items() if v.get("check")}
        self.types = r.get("types", {})


def merge_regions(regions: list[tuple[int, int, int]]) -> list[tuple[int, int, int]]:
    out: list[tuple[int, int, int]] = []
    for a, n, c in sorted(regions, key=lambda r: (r[0], -r[1])):
        if out and a < out[-1][0] + out[-1][1]:
            end = max(out[-1][0] + out[-1][1], a + n)
            out[-1] = (out[-1][0], end - out[-1][0], out[-1][2])
        else:
            out.append((a, n, c))
    return out


class Walker:
    def __init__(self, rules: Rules, read_fn: Callable[[int, int], bytes | None]):
        self.R = rules
        self.read = read_fn
        self.regions: list[tuple[int, int, int]] = []
        self.seen: set[tuple[str, int]] = set()

    def rd(self, addr: int, size: int) -> bytes:
        try:
            b = self.read(addr, size)
        except ReadFault:
            raise WalkError(1, hex(addr))
        if b is None or len(b) != size:
            raise WalkError(1, hex(addr))
        return b

    def q(self, addr: int) -> int:
        return struct.unpack("<Q", self.rd(addr, 8))[0]

    def add(self, addr: int, size: int, cat_name: str) -> None:
        if size <= 0:
            return
        self.rd(addr, size)
        self.regions.append((addr, size, self.R.cat_index[cat_name]))
        if len(self.regions) > self.R.limits["regions"]:
            raise WalkError(10, str(len(self.regions)))

    def vec(self, at: int, cap: int, align: int) -> tuple[int, int]:
        b, e = struct.unpack("<2Q", self.rd(at, 16))
        if e < b:
            raise WalkError(2, hex(at))
        if (e - b) % align:
            raise WalkError(4, hex(at))
        if (e - b) // align > cap:
            raise WalkError(3, f"{hex(at)} {(e - b) // align}")
        return b, e

    def visit(self, base: int, typ: str) -> None:
        if (typ, base) in self.seen:
            return
        self.seen.add((typ, base))
        for op in self.R.types.get(typ, ()):
            k = op[0]
            if k == "region":
                self.add(base + _h(op[1]), _h(op[2]), op[3])
            elif k == "ptr":
                p = self.q(base + _h(op[1]))
                if p:
                    self.visit(p, op[2])
            elif k == "deref":
                p = self.q(base + _h(op[1]))
                if p:
                    self.add(p, _h(op[2]), op[3])
            elif k == "vec":
                stride = _h(op[2])
                cap = self.R.limits.get(op[4], _h(op[4]))
                b, e = self.vec(base + _h(op[1]), cap, stride)
                self.add(b, e - b, op[5])
                if op[3] != "none":
                    for i in range((e - b) // stride):
                        self.visit(b + i * stride, op[3])
            else:
                raise ValueError(f"unknown rule op {k!r}")


def walk_unit(rules: Rules, read_fn: Callable[[int, int], bytes | None], root_addr: int, root_type: str = "unit"):
    w = Walker(rules, read_fn)
    w.visit(root_addr, root_type)
    return merge_regions(w.regions), sorted(set(w.regions))


def _pack_blocks(blocks: list[tuple[int, bytes]]) -> bytes:
    out = [struct.pack("<I", len(blocks))]
    for addr, data in blocks:
        out.append(struct.pack("<QII", addr, len(data), 0))
        out.append(data)
    return b"".join(out)


def _unpack_blocks(b: bytes, offset: int) -> tuple[list[tuple[int, bytes]], int]:
    (n,) = struct.unpack_from("<I", b, offset)
    offset += 4
    out: list[tuple[int, bytes]] = []
    for _ in range(n):
        if offset + 16 > len(b):
            raise FormatError("data block header past payload")
        addr, size, z = struct.unpack_from("<QII", b, offset)
        offset += 16
        if z or offset + size > len(b):
            raise FormatError("data block past payload")
        out.append((addr, bytes(b[offset : offset + size])))
        offset += size
    return out, offset


class Writer:
    def __init__(self, path: Path, rules_sha: str, binary_sha: str, frame_limit: int = 0, pid: int = 0, info: dict | None = None):
        self.f = open(path, "wb")
        self.seq = 0
        self.chain = 0
        self.frames = 0
        self.invalid = 0
        hdr = MAGIC + struct.pack("<II", VERSION, HEADER_SIZE)
        self.f.write(hdr + bytes(HEADER_SIZE - len(hdr)))
        t = json.dumps(info or {}, sort_keys=True).encode("utf-8")
        self.record(
            K_RUN,
            bytes.fromhex(rules_sha) + bytes.fromhex(binary_sha) + struct.pack("<IIQQI", frame_limit, pid, 0, 10_000_000, len(t)) + t,
        )

    def record(self, kind: int, payload: bytes, flags: int = 0) -> None:
        hdr0 = struct.pack("<IHHIIQQ", REC_MAGIC, kind, flags, len(payload), 0, self.seq, 0)
        crc = zlib.crc32(payload, zlib.crc32(hdr0)) & 0xFFFFFFFF
        self.f.write(struct.pack("<IHHIIQQ", REC_MAGIC, kind, flags, len(payload), crc, self.seq, 0))
        self.f.write(payload)
        self.chain = zlib.crc32(struct.pack("<I", crc), self.chain) & 0xFFFFFFFF
        self.seq += 1

    def frame_begin(self, seq: int, tick: int, thread: int, globals_blocks: list[tuple[int, bytes]] = ()) -> None:
        g = _pack_blocks(list(globals_blocks))
        self.record(K_FRAME, struct.pack("<QQIIQiI", seq, tick, thread, 0, 0, 0, len(g)) + g)

    def unit_block(
        self,
        phase: int,
        status: int,
        order: int,
        unit_addr: int,
        thread: int,
        regions: list[tuple[int, int, int]],
        blocks: list[tuple[int, bytes]],
        walk_error: int = 0,
    ) -> None:
        body = struct.pack("<BBHIQQIiII", phase, status, walk_error, order, unit_addr, 0, thread, 0, len(regions), len(blocks))
        body += b"".join(struct.pack("<QIHH", a, s, c, 0) for a, s, c in regions)
        body += _pack_blocks(blocks)[4:]
        self.record(K_UNIT, body)

    def event(self, kind: int, value: int, obj: int, frame_seq: int, thread: int) -> None:
        self.record(K_EVENT, struct.pack("<HHIQQQII", kind, 0, value, obj, 0, frame_seq, thread, 0))

    def frame_end(self, seq: int, thread: int, status: int, units: int, changed_mask: int = 0) -> None:
        self.frames += 1
        self.invalid += bool(status)
        self.record(K_END, struct.pack("<QIIIIQ", seq, thread, status, units, changed_mask, 0))

    def close(self, run_end: dict | None = None) -> None:
        t = json.dumps(run_end or {}, sort_keys=True).encode("utf-8")
        self.record(K_RUN_END, struct.pack("<I", len(t)) + t)
        count = self.seq + 1
        self.record(K_FOOTER, struct.pack("<QQQI", count, self.frames, self.invalid, self.chain))
        self.f.close()


@dataclass
class UnitBlock:
    phase: int
    status: int
    order: int
    unit: int
    thread: int
    regions: list[tuple[int, int, int]]
    blocks: list[tuple[int, bytes]]
    walk_error: int = 0


@dataclass
class FrameRecord:
    seq: int
    tick: int
    thread: int
    globals: list[tuple[int, bytes]]
    units: list[UnitBlock] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    end: dict[str, Any] | None = None


def read_stream(path: Path) -> dict[str, Any]:
    b = Path(path).read_bytes()
    if len(b) < HEADER_SIZE or b[:8] != MAGIC:
        raise FormatError("not a BDRCREC1 stream")
    ver, hs = struct.unpack_from("<II", b, 8)
    if ver != VERSION or hs != HEADER_SIZE or any(b[16:HEADER_SIZE]):
        raise FormatError("invalid stream header")
    o = HEADER_SIZE
    seq = 0
    chain = 0
    run = None
    frames: list[FrameRecord] = []
    cur: FrameRecord | None = None
    run_end = None
    footer = None
    outside_events: list[dict[str, Any]] = []

    while o < len(b):
        if footer is not None:
            raise FormatError("bytes after footer")
        if o + 32 > len(b):
            raise FormatError(f"truncated record header at {o}")
        magic, kind, flags, size, crc, s, res = struct.unpack_from("<IHHIIQQ", b, o)
        if magic != REC_MAGIC or res:
            raise FormatError(f"bad record magic at {o}")
        if o + 32 + size > len(b):
            raise FormatError(f"truncated payload at {o}")
        payload = b[o + 32 : o + 32 + size]
        expected_crc = zlib.crc32(payload, zlib.crc32(struct.pack("<IHHIIQQ", REC_MAGIC, kind, flags, size, 0, s, 0))) & 0xFFFFFFFF
        if expected_crc != crc:
            raise FormatError(f"crc mismatch in record {s}")
        if s != seq:
            raise FormatError(f"record sequence gap: expected {seq} got {s}")
        if kind != K_FOOTER:
            chain = zlib.crc32(struct.pack("<I", crc), chain) & 0xFFFFFFFF
        seq += 1
        o += 32 + size

        if kind == K_RUN:
            fl, pid, qpc, freq, tl = struct.unpack_from("<IIQQI", payload, 64)
            run = dict(
                rules_sha256=payload[:32].hex().upper(),
                binary_sha256=payload[32:64].hex().upper(),
                frame_limit=fl,
                pid=pid,
                info=json.loads(payload[92 : 92 + tl]),
            )
        elif kind == K_FRAME:
            fs, tk, th, _, _, _, gl = struct.unpack_from("<QQIIQiI", payload)
            blocks, _ = _unpack_blocks(payload, 40)
            cur = FrameRecord(fs, tk, th, blocks)
        elif kind == K_UNIT:
            if cur is None:
                raise FormatError("unit block outside frame")
            ph, st, werr, order, unit, _, th, _, nr, nb = struct.unpack_from("<BBHIQQIiII", payload)
            p = 40
            regs = []
            for _ in range(nr):
                a, sz, c, _ = struct.unpack_from("<QIHH", payload, p)
                p += 16
                regs.append((a, sz, c))
            blocks, _ = _unpack_blocks(struct.pack("<I", nb) + payload[p:], 0)
            cur.units.append(UnitBlock(ph, st, order, unit, th, regs, blocks, walk_error=werr))
        elif kind == K_EVENT:
            ev, _, val, obj, _, fs, th, _ = struct.unpack("<HHIQQQII", payload)
            (cur.events if cur is not None else outside_events).append(dict(kind=ev, value=val, object=obj, frame_seq=fs, thread=th))
        elif kind == K_END:
            if cur is None:
                raise FormatError("frame end outside frame")
            fs, th, stt, nu, mask, _ = struct.unpack("<QIIIIQ", payload)
            cur.end = dict(thread=th, status=stt, units=nu, changed_mask=mask)
            frames.append(cur)
            cur = None
        elif kind == K_RUN_END:
            (tl,) = struct.unpack_from("<I", payload)
            run_end = json.loads(payload[4 : 4 + tl])
        elif kind == K_FOOTER:
            cnt, nf, ni, ch = struct.unpack("<QQQI", payload)
            if cnt != seq or nf != len(frames) or ch != chain:
                raise FormatError("footer mismatch")
            footer = dict(records=cnt, frames=nf, invalid=ni)
        else:
            raise FormatError(f"unknown record kind {kind}")

    if footer is None or cur is not None:
        raise FormatError("truncated stream")
    return dict(version=ver, run=run, frames=frames, events_outside_frames=outside_events, run_end=run_end, footer=footer)


class RecordMemory:
    def __init__(self, blocks: list[tuple[int, bytes]]):
        self.ranges = sorted((a, a + len(d), d) for a, d in blocks)
        self.starts = [r[0] for r in self.ranges]

    def read(self, addr: int, size: int) -> bytes | None:
        if size == 0:
            return b""
        i = bisect.bisect_right(self.starts, addr) - 1
        if i < 0:
            return None
        lo, hi, d = self.ranges[i]
        if addr < lo or addr + size > hi:
            return None
        return d[addr - lo : addr - lo + size]


def check_stream(path: Path, rules: Rules) -> dict[str, Any]:
    st = read_stream(path)
    frames: list[FrameRecord] = st["frames"]
    cat_name = lambda idx: rules.categories[idx] if 0 <= idx < len(rules.categories) else f"unknown-{idx}"
    readonly_violations = []
    unknown_writers = []

    for i, f in enumerate(frames):
        prev = frames[i - 1] if i > 0 else None
        pairs: dict[tuple[int, int], dict[int, UnitBlock]] = {}
        for b in f.units:
            pairs.setdefault((b.unit, b.order), {})[b.phase] = b
        prev_pairs: dict[tuple[int, int], dict[int, UnitBlock]] = {}
        if prev:
            for b in prev.units:
                prev_pairs.setdefault((b.unit, b.order), {})[b.phase] = b

        explained = [e["kind"] for e in f.events if e["frame_seq"] == f.seq]
        for (unit, order), ph in sorted(pairs.items()):
            e0, x1 = ph.get(0), ph.get(1)
            if e0 is None or x1 is None:
                continue
            em, xm = RecordMemory(e0.blocks), RecordMemory(x1.blocks)
            for a, n, c in e0.regions:
                cname = cat_name(c)
                if cname in rules.check:
                    b0, b1 = em.read(a, n), xm.read(a, n)
                    if b0 != b1:
                        readonly_violations.append({"frame": f.seq, "unit": hex(unit), "category": cname, "address": hex(a), "size": n})
            if prev and (unit, order) in prev_pairs and 1 in prev_pairs[(unit, order)]:
                p1 = prev_pairs[(unit, order)][1]
                pm = RecordMemory(p1.blocks)
                for a, n, c in p1.regions:
                    cname = cat_name(c)
                    if rules.raw["categories"].get(cname, {}).get("host_may_write", True):
                        continue
                    b_prev, b_curr = pm.read(a, n), em.read(a, n)
                    if b_prev != b_curr and not explained:
                        unknown_writers.append({"frame": f.seq, "unit": hex(unit), "category": cname, "address": hex(a), "size": n})

    ok = not readonly_violations and not unknown_writers
    return {
        "schema": "sim_verify-boundary-check-v1",
        "status": "PASS" if ok else "FAIL",
        "frames": len(frames),
        "readonly_violations": readonly_violations,
        "unknown_writers": unknown_writers,
    }
