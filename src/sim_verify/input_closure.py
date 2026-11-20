"""Input-closure verification engine for masked memory snapshots.

Provides:
1. Interval algebra (`interval_merge`, `interval_contains`, `interval_subtract`) over
   half-open byte ranges ``[lo, hi)``.
2. `MemoryView`: stitched sparse ``(addr, bytes)`` reader using binary search.
3. `ByteMask`: declarative JSON/dict whitelist supporting whole-region entries,
   explicit byte ranges, strided array element slices, conditional predicates,
   selectable layers (such as ``copy`` and ``host_events``), and mechanical
   ``forbidden`` firewall rules raising `FirewallViolation`.
4. `MaskedView`: strict read-only view that raises `MaskViolation` if even one byte
   outside the allowed intervals is read.
5. `scramble_outside_mask`, `verify_scramble_invariance`, and
   `verify_negative_control_ablation`: runtime proofs that unwhitelisted bytes are
   never read and that whitelisted entries are genuinely exercised (non-vacuous).
"""
from __future__ import annotations

import bisect
from collections.abc import Callable, Iterable, Mapping, Sequence
import hashlib
import json
from pathlib import Path
import random
import struct
from typing import Any


class MaskViolation(Exception):
    """Raised when a read or mask rule violates the declared input closure."""


class FirewallViolation(MaskViolation):
    """Raised when a forbidden byte range is ever admitted by a mask."""


def _parse_int(value: int | str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        return int(value.strip(), 0)
    raise TypeError(f"expected int or hex/decimal str, got {type(value).__name__}")


def interval_merge(intervals: Iterable[tuple[int, int] | Sequence[int]]) -> list[tuple[int, int]]:
    """Merge overlapping or contiguous half-open intervals ``[lo, hi)``."""
    cleaned = [(int(lo), int(hi)) for lo, hi in intervals if int(lo) < int(hi)]
    cleaned.sort()
    out: list[tuple[int, int]] = []
    for lo, hi in cleaned:
        if out and lo <= out[-1][1]:
            if hi > out[-1][1]:
                out[-1] = (out[-1][0], hi)
        else:
            out.append((lo, hi))
    return out


def interval_contains(
    starts: Sequence[int],
    intervals: Sequence[tuple[int, int] | Sequence[int]],
    addr: int,
    size: int,
) -> bool:
    """Return True iff ``[addr, addr + size)`` lies completely within one merged interval."""
    if size < 0:
        raise ValueError(f"negative size: {size}")
    if size == 0:
        return True
    idx = bisect.bisect_right(starts, addr) - 1
    if idx < 0:
        return False
    lo, hi = intervals[idx]
    return lo <= addr and addr + size <= hi


def interval_subtract(
    intervals: Iterable[tuple[int, int] | Sequence[int]],
    cut: Iterable[tuple[int, int] | Sequence[int]],
) -> list[tuple[int, int]]:
    """Subtract all intervals in ``cut`` from ``intervals``."""
    cuts = interval_merge(cut)
    out: list[tuple[int, int]] = []
    for lo, hi in interval_merge(intervals):
        segs = [(lo, hi)]
        for c0, c1 in cuts:
            nxt: list[tuple[int, int]] = []
            for a, b in segs:
                if c1 <= a or c0 >= b:
                    nxt.append((a, b))
                    continue
                if a < c0:
                    nxt.append((a, c0))
                if c1 < b:
                    nxt.append((c1, b))
            segs = nxt
        out.extend(segs)
    return out


def _intervals_overlap(
    left: Sequence[tuple[int, int]],
    right: Sequence[tuple[int, int]],
) -> tuple[int, int] | None:
    """Return the first overlapping byte range ``(lo, hi)`` between two sorted interval lists."""
    i = j = 0
    while i < len(left) and j < len(right):
        a0, a1 = left[i]
        b0, b1 = right[j]
        lo = max(a0, b0)
        hi = min(a1, b1)
        if lo < hi:
            return (lo, hi)
        if a1 <= b1:
            i += 1
        else:
            j += 1
    return None


class MemoryView:
    """Stitched sparse ``(addr, bytes)`` reader backed by binary search."""

    def __init__(self, blocks: Iterable[tuple[int, bytes | bytearray | memoryview]]):
        merged: list[tuple[int, bytes]] = []
        for addr, raw in sorted(blocks, key=lambda item: int(item[0])):
            if not raw:
                continue
            a = int(addr)
            data = bytes(raw)
            if merged and a <= merged[-1][0] + len(merged[-1][1]):
                lo, prev = merged[-1]
                end = lo + len(prev)
                if a + len(data) > end:
                    merged[-1] = (lo, prev + data[end - a:])
            else:
                merged.append((a, data))
        self.intervals = merged
        self.starts = [a for a, _ in merged]

    def get(self, addr: int, size: int) -> bytes | None:
        """Return ``size`` bytes at ``addr``, or ``None`` if not fully covered."""
        if size < 0:
            raise ValueError(f"negative read size: {size}")
        if size == 0:
            return b""
        idx = bisect.bisect_right(self.starts, addr) - 1
        if idx < 0:
            return None
        lo, data = self.intervals[idx]
        if addr + size <= lo + len(data):
            off = addr - lo
            return data[off:off + size]
        return None

    def read(self, addr: int, size: int) -> bytes:
        """Read ``size`` bytes at ``addr``, raising `MaskViolation` if uncovered."""
        data = self.get(addr, size)
        if data is None:
            raise MaskViolation(f"memory view does not cover {hex(addr)}+{size}")
        return data

    def read_u32(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def read_u64(self, addr: int) -> int:
        return struct.unpack("<Q", self.read(addr, 8))[0]

    def read_f32(self, addr: int) -> float:
        return struct.unpack("<f", self.read(addr, 4))[0]


class ByteMask:
    """Declarative byte-level input whitelist with layer support and firewall rules."""

    def __init__(
        self,
        rules: Mapping[str, Any] | Path,
        *,
        layers: Sequence[str] = ("copy",),
        categories: Sequence[str] | Mapping[int, str] | None = None,
    ):
        if isinstance(rules, Path):
            raw_bytes = rules.read_bytes()
            self.sha256 = hashlib.sha256(raw_bytes).hexdigest().upper()
            self.raw: dict[str, Any] = json.loads(raw_bytes.decode("utf-8"))
        else:
            self.raw = dict(rules)
            canonical = json.dumps(self.raw, sort_keys=True).encode("utf-8")
            self.sha256 = hashlib.sha256(canonical).hexdigest().upper()

        self.layers = tuple(layers)
        self.categories = categories if categories is not None else self.raw.get("categories")
        self.entries = self._collect_entries(self.layers)
        self.forbidden_rules: list[dict[str, Any]] = list(self.raw.get("forbidden", ()))

    def _collect_entries(self, layers: Sequence[str]) -> list[dict[str, Any]]:
        layers_dict = self.raw.get("layers")
        if isinstance(layers_dict, Mapping) or any(layer in self.raw for layer in layers):
            out: list[dict[str, Any]] = []
            for layer in layers:
                if isinstance(layers_dict, Mapping) and layer in layers_dict:
                    out.extend(layers_dict[layer])
                elif layer in self.raw:
                    out.extend(self.raw[layer])
            return out
        return list(self.raw.get("entries", ()))

    def _resolve_category(self, cat: str | int) -> str:
        if isinstance(cat, str):
            return cat
        if isinstance(cat, int):
            if self.categories is None:
                raise MaskViolation(f"integer category {cat} used without category table")
            if isinstance(self.categories, Mapping):
                if cat not in self.categories:
                    raise MaskViolation(f"unknown category index {cat}")
                return str(self.categories[cat])
            if 0 <= cat < len(self.categories):
                return str(self.categories[cat])
            raise MaskViolation(f"unknown category index {cat}")
        raise TypeError(f"invalid category type: {type(cat).__name__}")

    @staticmethod
    def _expand_rule_for_region(
        rule: Mapping[str, Any],
        addr: int,
        size: int,
        cat: str,
    ) -> list[tuple[int, int]]:
        rule_id = rule.get("id", "<unnamed>")
        out: list[tuple[int, int]] = []
        if rule.get("whole"):
            out.append((addr, addr + size))
            return out
        if "stride" in rule:
            stride = _parse_int(rule["stride"])
            start_i = _parse_int(rule.get("start_index", 0))
            if stride <= 0 or size % stride != 0:
                raise MaskViolation(
                    f"strided mask {rule_id!r} region {hex(addr)}+{size} not multiple of {stride}"
                )
            cnt = size // stride
            for lo_raw, hi_raw in rule.get("ranges", ()):
                lo, hi = _parse_int(lo_raw), _parse_int(hi_raw)
                if lo < 0 or hi < lo or hi > stride:
                    raise MaskViolation(f"strided mask {rule_id!r} range [{lo}, {hi}) beyond stride {stride}")
                for idx in range(start_i, cnt):
                    out.append((addr + idx * stride + lo, addr + idx * stride + hi))
            return out
        for lo_raw, hi_raw in rule.get("ranges", ()):
            lo, hi = _parse_int(lo_raw), _parse_int(hi_raw)
            if lo < 0 or hi < lo or hi > size:
                raise MaskViolation(
                    f"mask range {rule_id!r} [{hex(lo)}, {hex(hi)}) beyond region {hex(addr)}+{size} ({cat})"
                )
            out.append((addr + lo, addr + hi))
        return out

    def _entry_matches_region(
        self,
        rule: Mapping[str, Any],
        addr: int,
        cat: str,
        predicate: Callable[[int, str], bool] | None,
        external: Mapping[str, set[int] | frozenset[int]] | None,
    ) -> bool:
        cats = rule.get("categories") or ([rule["category"]] if "category" in rule else None)
        if cats is not None and cat not in cats:
            return False
        if rule.get("condition"):
            if predicate is not None:
                return bool(predicate(addr, cat))
            if external is not None:
                return addr in external.get(cat, ())
            return False
        return True

    def _check_firewall(
        self,
        merged: list[tuple[int, int]],
        regions: Sequence[tuple[int, int, str | int]],
        source: str,
    ) -> None:
        if not self.forbidden_rules or not merged:
            return
        forbidden_iv: list[tuple[int, int]] = []
        for rule in self.forbidden_rules:
            if "source" in rule and rule["source"] != source:
                continue
            for lo_raw, hi_raw in rule.get("absolute_ranges", ()):
                forbidden_iv.append((_parse_int(lo_raw), _parse_int(hi_raw)))
            cats = rule.get("categories") or ([rule["category"]] if "category" in rule else None)
            if "whole" in rule or "ranges" in rule or "stride" in rule:
                for addr, size, cat_raw in regions:
                    cat = self._resolve_category(cat_raw)
                    if cats is not None and cat not in cats:
                        continue
                    # Clamp/filter relative forbidden rules only when region covers them or whole
                    if "stride" in rule:
                        stride = _parse_int(rule["stride"])
                        if stride <= 0 or size % stride != 0:
                            continue
                        start_i = _parse_int(rule.get("start_index", 0))
                        cnt = size // stride
                        for lo_raw, hi_raw in rule.get("ranges", ()):
                            lo, hi = _parse_int(lo_raw), _parse_int(hi_raw)
                            if hi <= stride:
                                for idx in range(start_i, cnt):
                                    forbidden_iv.append((addr + idx * stride + lo, addr + idx * stride + hi))
                    elif rule.get("whole"):
                        forbidden_iv.append((addr, addr + size))
                    else:
                        for lo_raw, hi_raw in rule.get("ranges", ()):
                            lo, hi = _parse_int(lo_raw), _parse_int(hi_raw)
                            if lo < size and hi > lo:
                                forbidden_iv.append((addr + lo, addr + min(hi, size)))
        merged_forbidden = interval_merge(forbidden_iv)
        overlap = _intervals_overlap(merged, merged_forbidden)
        if overlap is not None:
            raise FirewallViolation(
                f"mask firewall violated on source {source!r}: forbidden range "
                f"[{hex(overlap[0])}, {hex(overlap[1])}) was allowed"
            )

    def allowed(
        self,
        regions: Sequence[tuple[int, int, str | int]],
        source: str,
        *,
        predicate: Callable[[int, str], bool] | None = None,
        external: Mapping[str, set[int] | frozenset[int]] | None = None,
        only: str | None = None,
        layers: Sequence[str] | None = None,
    ) -> list[tuple[int, int]]:
        """Compute merged allowed byte intervals ``[lo, hi)`` for ``regions`` under ``source``."""
        entries = self.entries if layers is None else self._collect_entries(layers)
        iv: list[tuple[int, int]] = []
        for entry in entries:
            if "source" in entry and entry["source"] != source:
                continue
            if only is not None and entry.get("id") != only:
                continue
            if "fields" in entry:
                for field in entry["fields"]:
                    addr = _parse_int(field[0])
                    size = _parse_int(field[1])
                    iv.append((addr, addr + size))
                continue
            if entry.get("absolute") and "ranges" in entry:
                for lo_raw, hi_raw in entry["ranges"]:
                    iv.append((_parse_int(lo_raw), _parse_int(hi_raw)))
                continue
            for addr, size, cat_raw in regions:
                cat = self._resolve_category(cat_raw)
                if not self._entry_matches_region(entry, addr, cat, predicate, external):
                    continue
                iv.extend(self._expand_rule_for_region(entry, addr, size, cat))

        merged = interval_merge(iv)
        self._check_firewall(merged, regions, source)
        return merged


class MaskedView:
    """Strictly masked view: any read of even 1 byte outside ``allowed_intervals`` raises `MaskViolation`."""

    def __init__(
        self,
        blocks: Iterable[tuple[int, bytes | bytearray | memoryview]],
        allowed_intervals: Iterable[tuple[int, int] | Sequence[int]],
    ):
        self.intervals = interval_merge(allowed_intervals)
        self.starts = [lo for lo, _ in self.intervals]
        self._mem = MemoryView(blocks)

    def _require_allowed(self, addr: int, size: int) -> None:
        if size < 0:
            raise ValueError(f"negative read size: {size}")
        if size and not interval_contains(self.starts, self.intervals, addr, size):
            raise MaskViolation(f"mask does not allow {hex(addr)}+{size}")

    def get(self, addr: int, size: int) -> bytes | None:
        self._require_allowed(addr, size)
        return self._mem.get(addr, size)

    def read(self, addr: int, size: int) -> bytes:
        self._require_allowed(addr, size)
        return self._mem.read(addr, size)

    def read_u32(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def read_u64(self, addr: int) -> int:
        return struct.unpack("<Q", self.read(addr, 8))[0]

    def read_f32(self, addr: int) -> float:
        return struct.unpack("<f", self.read(addr, 4))[0]


def scramble_outside_mask(
    blocks: Sequence[tuple[int, bytes | bytearray | memoryview]],
    allowed_intervals: Iterable[tuple[int, int] | Sequence[int]],
    rng: random.Random,
) -> list[tuple[int, bytes]]:
    """Replace every byte outside ``allowed_intervals`` with ``rng.randbytes``."""
    allowed = interval_merge(allowed_intervals)
    starts = [lo for lo, _ in allowed]
    out: list[tuple[int, bytes]] = []
    for addr, raw in blocks:
        data = bytes(raw)
        buf = bytearray(rng.randbytes(len(data)))
        i = max(0, bisect.bisect_right(starts, addr) - 1)
        end = addr + len(data)
        while i < len(allowed) and allowed[i][0] < end:
            lo = max(allowed[i][0], addr)
            hi = min(allowed[i][1], end)
            if lo < hi:
                buf[lo - addr:hi - addr] = data[lo - addr:hi - addr]
            i += 1
        out.append((addr, bytes(buf)))
    return out


def verify_scramble_invariance(
    frames_blocks: Sequence[Sequence[tuple[int, bytes]]],
    allowed_per_frame: Sequence[Sequence[tuple[int, int] | Sequence[int]]],
    run_fn: Callable[[Sequence[MaskedView]], Sequence[bytes]],
    seed: int = 1,
    *,
    raise_on_mismatch: bool = True,
) -> dict[str, Any]:
    """Run ``run_fn`` on original vs scrambled frame views and verify byte-identical SHA-256 digests."""
    if len(frames_blocks) != len(allowed_per_frame):
        raise ValueError("frames_blocks and allowed_per_frame must have the same length")
    rng = random.Random(seed)
    orig_views = [MaskedView(b, a) for b, a in zip(frames_blocks, allowed_per_frame)]
    scram_views = [
        MaskedView(scramble_outside_mask(b, a, rng), a)
        for b, a in zip(frames_blocks, allowed_per_frame)
    ]

    orig_outs = [bytes(x) for x in run_fn(orig_views)]
    scram_outs = [bytes(x) for x in run_fn(scram_views)]
    orig_digests = [hashlib.sha256(x).hexdigest().upper() for x in orig_outs]
    scram_digests = [hashlib.sha256(x).hexdigest().upper() for x in scram_outs]

    first_mismatch: int | None = None
    if len(orig_digests) != len(scram_digests):
        first_mismatch = min(len(orig_digests), len(scram_digests))
    else:
        for idx, (d0, d1) in enumerate(zip(orig_digests, scram_digests)):
            if d0 != d1:
                first_mismatch = idx
                break

    passed = first_mismatch is None
    if not passed and raise_on_mismatch:
        raise AssertionError(
            f"scramble invariance failed at frame {first_mismatch}: "
            f"orig={orig_digests[first_mismatch] if first_mismatch < len(orig_digests) else '<missing>'} "
            f"scrambled={scram_digests[first_mismatch] if first_mismatch < len(scram_digests) else '<missing>'}"
        )

    return {
        "schema": "sim_verify-scramble-invariance-v1",
        "status": "PASS" if passed else "FAIL",
        "seed": seed,
        "frames": len(orig_digests),
        "all_equal": passed,
        "first_mismatch_frame": first_mismatch,
        "orig_digests": orig_digests,
        "scrambled_digests": scram_digests,
    }


def verify_negative_control_ablation(
    blocks: Sequence[tuple[int, bytes]],
    mask: ByteMask,
    regions: Sequence[tuple[int, int, str | int]],
    entry_id: str,
    run_fn: Callable[[MaskedView], bytes],
    seed: int = 1,
    *,
    source: str = "entry",
    predicate: Callable[[int, str], bool] | None = None,
    external: Mapping[str, set[int] | frozenset[int]] | None = None,
    raise_on_vacuous: bool = True,
) -> dict[str, Any]:
    """Subtract a single whitelisted entry and scramble it too, asserting that output MUST change."""
    allowed = mask.allowed(regions, source, predicate=predicate, external=external)
    ablated = mask.allowed(regions, source, predicate=predicate, external=external, only=entry_id)
    if not ablated:
        raise MaskViolation(f"negative control entry {entry_id!r} matched no bytes on source {source!r}")

    kept = interval_subtract(allowed, ablated)
    rng = random.Random(seed)
    scrambled_blocks = scramble_outside_mask(blocks, kept, rng)

    orig_out = bytes(run_fn(MaskedView(blocks, allowed)))
    ablated_out = bytes(run_fn(MaskedView(scrambled_blocks, allowed)))
    orig_sha = hashlib.sha256(orig_out).hexdigest().upper()
    ablated_sha = hashlib.sha256(ablated_out).hexdigest().upper()

    changed = orig_sha != ablated_sha
    if not changed and raise_on_vacuous:
        raise AssertionError(
            f"negative control ablation for {entry_id!r} did not change output "
            f"(vacuous mask; digest={orig_sha})"
        )

    return {
        "schema": "sim_verify-negative-control-v1",
        "status": "PASS" if changed else "FAIL",
        "entry_id": entry_id,
        "seed": seed,
        "ablated_bytes": sum(hi - lo for lo, hi in ablated),
        "output_changed": changed,
        "vacuous": not changed,
        "orig_sha256": orig_sha,
        "ablated_sha256": ablated_sha,
    }
