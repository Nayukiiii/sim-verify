from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zlib

from sim_verify.boundary_index import (
    BoundaryKind,
    FrameSplitStateMachine,
    IndexedBoundaryReader,
    MonotonicStartGate,
    build_stream_index,
    compute_quantiles,
    pair_cross_frame_invariant,
    pearson_corr,
    profile_stream_intervals,
)
from sim_verify.boundary_recorder import (
    FormatError,
    HEADER_SIZE,
    K_END,
    K_FRAME,
    K_RUN,
    REC_MAGIC,
    Writer,
    read_stream,
)
from sim_verify.disk_index import (
    DiskCappedIndex,
    DiskQuotaExceededError,
    decode_prefix_free_bytes,
    decode_u64_tuple,
    encode_index_key,
    encode_prefix_free_bytes,
    encode_u64,
    encode_u64_tuple,
    unpack_u64,
)
from sim_verify.stream_store import (
    LZ4_MAGIC,
    NamedPipeRepacker,
    compute_dual_sha256,
    open_bounded_stream,
    parse_lz4_frame_header,
    validate_lz4_frame_header,
)

try:
    import lz4.frame as _lz4_frame
except ImportError:  # pragma: no cover
    _lz4_frame = None


def _build_synthetic_lz4_header(
    *,
    block_independent: bool = True,
    block_checksum: bool = True,
    content_checksum: bool = True,
    block_size_id: int = 7,
    content_size: int | None = 1024,
    dict_id: int | None = None,
    version: int = 1,
) -> bytes:
    flg = (version & 0x03) << 6
    if block_independent:
        flg |= 1 << 5
    if block_checksum:
        flg |= 1 << 4
    if content_size is not None:
        flg |= 1 << 3
    if content_checksum:
        flg |= 1 << 2
    if dict_id is not None:
        flg |= 1
    bd = (block_size_id & 0x07) << 4
    out = bytearray(LZ4_MAGIC)
    out.append(flg)
    out.append(bd)
    if content_size is not None:
        out.extend(struct.pack("<Q", content_size))
    if dict_id is not None:
        out.extend(struct.pack("<I", dict_id))
    out.append(0xAA)  # header checksum placeholder byte for structural parsing
    return bytes(out)


class StreamStoreTests(unittest.TestCase):
    def test_raw_dual_sha256_and_logical_ceiling(self) -> None:
        payload = b"sim_verify-stream-data-" * 500
        expected_sha = hashlib.sha256(payload).hexdigest().upper()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "raw.bin"
            p.write_bytes(payload)

            phys_sha, log_sha, phys_n, log_n = compute_dual_sha256(p, max_block_bytes=1024)
            self.assertEqual(phys_sha, expected_sha)
            self.assertEqual(log_sha, expected_sha)
            self.assertEqual(phys_n, len(payload))
            self.assertEqual(log_n, len(payload))

            with open_bounded_stream(p, max_logical_bytes=len(payload) - 1, max_block_bytes=1024) as s:
                with self.assertRaises(ValueError):
                    while s.read(1024):
                        pass

            with open_bounded_stream(p, max_block_bytes=256) as s:
                with self.assertRaises(ValueError):
                    s.read(257)

    def test_synthetic_lz4_header_validation_pure_stdlib(self) -> None:
        valid_hdr = _build_synthetic_lz4_header(
            block_checksum=True,
            content_checksum=True,
            block_size_id=7,
            content_size=4096,
        )
        parsed = validate_lz4_frame_header(
            valid_hdr, max_block_bytes=4 << 20, max_logical_bytes=128 << 30
        )
        self.assertTrue(parsed.block_checksum)
        self.assertTrue(parsed.content_checksum)
        self.assertEqual(parsed.block_size, 4 << 20)
        self.assertEqual(parsed.content_size, 4096)

        # Missing block checksum
        no_bchk = _build_synthetic_lz4_header(block_checksum=False, content_checksum=True)
        with self.assertRaises(ValueError):
            validate_lz4_frame_header(no_bchk)

        # Missing content checksum
        no_cchk = _build_synthetic_lz4_header(block_checksum=True, content_checksum=False)
        with self.assertRaises(ValueError):
            validate_lz4_frame_header(no_cchk)

        # Block size exceeding cap (e.g., 4 MiB header checked against 1 MiB cap)
        too_big_blk = _build_synthetic_lz4_header(block_size_id=7)
        with self.assertRaises(ValueError):
            validate_lz4_frame_header(too_big_blk, max_block_bytes=1 << 20)

        # Declared content size exceeding logical cap
        too_big_log = _build_synthetic_lz4_header(content_size=(128 << 30) + 1)
        with self.assertRaises(ValueError):
            validate_lz4_frame_header(too_big_log, max_logical_bytes=128 << 30)

        # Invalid magic / truncated / reserved bit
        with self.assertRaises(ValueError):
            parse_lz4_frame_header(b"BAD!" + valid_hdr[4:])
        with self.assertRaises(ValueError):
            parse_lz4_frame_header(LZ4_MAGIC + b"\x00")
        bad_reserved = bytearray(valid_hdr)
        bad_reserved[4] |= 0x02
        with self.assertRaises(ValueError):
            parse_lz4_frame_header(bytes(bad_reserved))

    def test_lz4_missing_dependency_only_on_lz4_stream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            raw_path = Path(tmp) / "plain.bin"
            raw_path.write_bytes(b"abc123")
            lz4_path = Path(tmp) / "packed.lz4"
            lz4_path.write_bytes(_build_synthetic_lz4_header())

            with mock.patch.dict(sys.modules, {"lz4": None, "lz4.frame": None}):
                # Raw file works without lz4 installed
                phys, log, _, _ = compute_dual_sha256(raw_path)
                self.assertEqual(phys, log)

                # .lz4 file raises clear ImportError
                with self.assertRaises(ImportError):
                    with open_bounded_stream(lz4_path):
                        pass

    @unittest.skipIf(_lz4_frame is None, "optional lz4 package not installed")
    def test_lz4_real_roundtrip_and_rejection_cases(self) -> None:
        payload = (b"deterministic-frame-bytes-" * 2048) + b"tail"
        expected_log = hashlib.sha256(payload).hexdigest().upper()
        compressed = _lz4_frame.compress(
            payload,
            block_size=_lz4_frame.BLOCKSIZE_MAX1MB,
            block_checksum=True,
            content_checksum=True,
        )
        expected_phys = hashlib.sha256(compressed).hexdigest().upper()

        with tempfile.TemporaryDirectory() as tmp:
            ok_path = Path(tmp) / "ok.lz4"
            ok_path.write_bytes(compressed)
            phys_sha, log_sha, phys_n, log_n = compute_dual_sha256(ok_path)
            self.assertEqual(phys_sha, expected_phys)
            self.assertEqual(log_sha, expected_log)
            self.assertEqual(phys_n, len(compressed))
            self.assertEqual(log_n, len(payload))
            self.assertNotEqual(phys_sha, log_sha)

            # Reject missing checksums
            no_chk_path = Path(tmp) / "nochk.lz4"
            no_chk_path.write_bytes(
                _lz4_frame.compress(payload, block_checksum=False, content_checksum=True)
            )
            with self.assertRaises(ValueError):
                compute_dual_sha256(no_chk_path)

            # Reject truncated frame
            trunc_path = Path(tmp) / "trunc.lz4"
            trunc_path.write_bytes(compressed[:-5])
            with self.assertRaises(ValueError):
                compute_dual_sha256(trunc_path)

            # Reject trailing garbage
            garbage_path = Path(tmp) / "garbage.lz4"
            garbage_path.write_bytes(compressed + b"\x00")
            with self.assertRaises(ValueError):
                compute_dual_sha256(garbage_path)

    @unittest.skipUnless(sys.platform == "win32", "Windows named pipes required")
    def test_named_pipe_repacker_roundtrip(self) -> None:
        payload = b"pipe-repack-payload-" * 4096
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src.bin"
            dst = Path(tmp) / "dst.bin"
            src.write_bytes(payload)

            worker_code = (
                "import sys; "
                "src_p, dst_p = sys.argv[1], sys.argv[2]; "
                "data = open(src_p, 'rb').read(); "
                "open(dst_p, 'wb').write(data)"
            )
            repacker = NamedPipeRepacker(buffer_bytes=64 * 1024, connect_timeout_s=10.0)
            rep = repacker.repack(src, dst, [sys.executable, "-c", worker_code])
            self.assertTrue(rep["exact_roundtrip"])
            self.assertEqual(rep["source_logical_sha256"], rep["destination_logical_sha256"])
            self.assertEqual(rep["logical_bytes"], len(payload))
            self.assertEqual(dst.read_bytes(), payload)

            # Mismatching converter output must raise ValueError
            bad_dst = Path(tmp) / "bad_dst.bin"
            bad_code = (
                "import sys; "
                "src_p, dst_p = sys.argv[1], sys.argv[2]; "
                "data = open(src_p, 'rb').read(); "
                "open(dst_p, 'wb').write(data[:-1] + b'X')"
            )
            with self.assertRaises(ValueError):
                repacker.repack(src, bad_dst, [sys.executable, "-c", bad_code])


class DiskIndexTests(unittest.TestCase):
    def test_prefix_free_encode_decode_and_disjointness(self) -> None:
        ints = [0, 1, 127, 128, 255, 256, 65535, 1 << 32, (1 << 64) - 1]
        for val in ints:
            tok = encode_u64(val)
            decoded, end = unpack_u64(tok)
            self.assertEqual(decoded, val)
            self.assertEqual(end, len(tok))

        tuples = [(), (0,), (1, 127, 128, (1 << 64) - 1), (42, 42, 0)]
        for tup in tuples:
            blob = encode_u64_tuple(tup)
            self.assertEqual(decode_u64_tuple(blob), tup)

        byte_vals = [b"", b"\x00", b"\x00\xff\x80", b"hello\x00world"]
        for raw in byte_vals:
            enc = encode_prefix_free_bytes(raw)
            self.assertEqual(decode_prefix_free_bytes(enc), raw)

        # Disjoint across scalar, tuple, and raw bytes
        k_int = encode_index_key(1)
        k_tup = encode_index_key((1,))
        k_bytes = encode_index_key(b"\x01")
        self.assertEqual(len({k_int, k_tup, k_bytes}), 3)

        with self.assertRaises(ValueError):
            encode_u64(-1)
        with self.assertRaises(ValueError):
            encode_u64(1 << 64)
        with self.assertRaises(ValueError):
            encode_u64(True)  # type: ignore[arg-type]

    def test_dedup_quota_and_cleanup(self) -> None:
        temp_dir: Path
        with DiskCappedIndex(max_bytes=64 * 1024) as idx:
            temp_dir = idx.temp_dir
            self.assertTrue(temp_dir.name.startswith("sim-verify-index-"))
            self.assertTrue(temp_dir.exists())

            self.assertTrue(idx.add((100, 0)))
            self.assertFalse(idx.add((100, 0)))
            self.assertTrue(idx.add((100, 1)))
            self.assertIn((100, 0), idx)
            self.assertNotIn((100, 2), idx)
            self.assertEqual(idx.count, 2)

            added = idx.add_many([(100, 0), (100, 2), (200, 0), (200, 0)])
            self.assertEqual(added, 2)
            self.assertEqual(idx.count, 4)

            ns = idx.namespace("secondary")
            self.assertTrue(ns.add((100, 0)))
            self.assertIn((100, 0), ns)
            self.assertEqual(len(ns), 1)
            self.assertEqual(idx.count, 5)
            self.assertLessEqual(idx.db_size_bytes, 64 * 1024)

        self.assertFalse(temp_dir.exists())

        # Hard disk cap enforcement
        with DiskCappedIndex(max_bytes=16 * 1024) as small_idx:
            with self.assertRaises(DiskQuotaExceededError):
                for i in range(5000):
                    small_idx.add((i, i ^ 0xDEADBEEF, (1 << 63) + i))
            self.assertLessEqual(small_idx.db_size_bytes, 16 * 1024)


class BoundaryIndexTests(unittest.TestCase):
    def _write_sample_stream(self, path: Path) -> tuple[str, str]:
        rules_sha = "11" * 32
        bin_sha = "22" * 32
        w = Writer(path, rules_sha, bin_sha, frame_limit=10, pid=4242, info={"suite": "unit"})
        w.event(99, 7, 0x1000, 0, 1)  # outside-frame event

        for seq, tick in [(0, 1000), (1, 1016), (2, 1033)]:
            w.frame_begin(seq, tick, 1, [(0x5000, struct.pack("<I", seq))])
            # Unit 0x1000 appears twice; Unit 0x2000 appears once
            w.unit_block(0, 0, 0, 0x1000, 1, [(0x1000, 4, 0)], [(0x1000, struct.pack("<I", seq + 10))])
            w.unit_block(1, 0, 0, 0x1000, 1, [(0x1000, 4, 0)], [(0x1000, struct.pack("<I", seq + 20))])
            w.unit_block(0, 0, 1, 0x2000, 2, [(0x2000, 8, 1)], [(0x2000, b"ABCDEFGH")])
            w.unit_block(1, 0, 1, 0x2000, 2, [(0x2000, 8, 1)], [(0x2000, b"ABCDEFGH")])
            if seq == 1:
                w.event(5, 123, 0x2000, seq, 2)
            status = 2 if seq == 2 else 0
            w.frame_end(seq, 1, status, 2, changed_mask=seq)

        w.close({"reason": "complete"})
        return rules_sha, bin_sha

    def test_index_random_access_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stream_path = Path(tmp) / "trace.bdrc"
            rules_sha, bin_sha = self._write_sample_stream(stream_path)

            ref = read_stream(stream_path)
            idx = build_stream_index(stream_path)
            self.assertEqual(idx["footer"], ref["footer"])
            self.assertEqual(len(idx["frames"]), 3)
            self.assertEqual(len(idx["stray_events"]), 1)

            with IndexedBoundaryReader(stream_path, idx) as reader:
                self.assertEqual(len(reader), 3)
                self.assertEqual(reader.frame_seqs, [0, 1, 2])
                run_meta = reader.run()
                assert run_meta is not None
                self.assertEqual(run_meta["rules_sha256"], rules_sha)
                self.assertEqual(run_meta["binary_sha256"], bin_sha)
                self.assertEqual(reader.run_end(), {"reason": "complete"})
                self.assertEqual(reader.outside_events(), ref["events_outside_frames"])

                for i, expected_frame in enumerate(ref["frames"]):
                    self.assertEqual(reader.frame(i), expected_frame)

                filtered = reader.frame(1, units={0x2000})
                self.assertEqual(len(filtered.units), 2)
                self.assertTrue(all(u.unit == 0x2000 for u in filtered.units))

            # Tamper detection: flip one byte inside a payload
            raw = bytearray(stream_path.read_bytes())
            tampered_payload = Path(tmp) / "tampered_payload.bdrc"
            bad1 = bytearray(raw)
            bad1[HEADER_SIZE + 40] ^= 0x01
            tampered_payload.write_bytes(bytes(bad1))
            with self.assertRaises(FormatError):
                build_stream_index(tampered_payload)

            # Truncation detection
            trunc = Path(tmp) / "trunc.bdrc"
            trunc.write_bytes(bytes(raw[:-16]))
            with self.assertRaises(FormatError):
                build_stream_index(trunc)

            # Trailing bytes after footer detection
            trailing = Path(tmp) / "trailing.bdrc"
            trailing.write_bytes(bytes(raw) + b"\x00" * 32)
            with self.assertRaises(FormatError):
                build_stream_index(trailing)

    def test_profile_stream_intervals_and_stats(self) -> None:
        self.assertEqual(pearson_corr([1.0], [2.0]), 0.0)
        self.assertEqual(pearson_corr([1.0, 2.0, 3.0], [5.0, 5.0, 5.0]), 0.0)
        self.assertAlmostEqual(pearson_corr([1.0, 2.0, 3.0], [2.0, 4.0, 6.0]), 1.0, places=9)
        self.assertAlmostEqual(pearson_corr([1.0, 2.0, 3.0], [6.0, 4.0, 2.0]), -1.0, places=9)

        q = compute_quantiles([10.0, 20.0, 30.0, 40.0, 50.0])
        self.assertEqual(q["n"], 5)
        self.assertEqual(q["median"], 30.0)
        self.assertEqual(q["max"], 50.0)
        self.assertAlmostEqual(q["mean"], 30.0)

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "perf.bdrc"
            # Construct a valid stream with explicit QPC timestamps and write_ticks
            with open(p, "wb") as fh:
                fh.write(b"BDRCREC1" + struct.pack("<II", 1, HEADER_SIZE) + bytes(HEADER_SIZE - 16))
                seq = 0
                chain = 0

                def emit(kind: int, payload: bytes) -> None:
                    nonlocal seq, chain
                    hdr0 = struct.pack("<IHHIIQQ", REC_MAGIC, kind, 0, len(payload), 0, seq, 0)
                    crc = zlib.crc32(payload, zlib.crc32(hdr0)) & 0xFFFFFFFF
                    fh.write(struct.pack("<IHHIIQQ", REC_MAGIC, kind, 0, len(payload), crc, seq, 0))
                    fh.write(payload)
                    chain = zlib.crc32(struct.pack("<I", crc), chain) & 0xFFFFFFFF
                    seq += 1

                emit(K_RUN, bytes(64) + struct.pack("<IIQQI", 0, 1, 0, 10_000_000, 2) + b"{}")
                # 4 frames with varying payload sizes and correlated QPC steps + write_ticks
                qpc = 100_000
                for idx, (extra, wt) in enumerate([(100, 1_000), (5000, 50_000), (200, 2_000), (1000, 10_000)]):
                    emit(K_FRAME, struct.pack("<QQIIQiI", idx, idx * 16, 1, 0, qpc, 0, 4) + struct.pack("<I", 0) + bytes(extra))
                    emit(K_END, struct.pack("<QIIIIQ", idx, 1, 0, 0, 0, wt))
                    qpc += 160_000 + wt
                emit(6, struct.pack("<I", 2) + b"{}")
                emit(0xFFFF, struct.pack("<QQQI", seq + 1, 4, 0, chain))

            prof = profile_stream_intervals(p)
            self.assertEqual(prof["frames"], 4)
            self.assertEqual(prof["pairs"], 3)
            self.assertGreater(prof["corr_qpc_step_vs_bytes"], 0.95)
            self.assertAlmostEqual(prof["corr_qpc_step_vs_write_ms"], 1.0, places=6)
            self.assertEqual(prof["tick_step"]["median"], 16.0)

    def test_cross_frame_invariant_pairing_under_thread_swaps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "multithread.bdrc"
            w = Writer(p, "00" * 32, "00" * 32)

            # Frame 0: thread 1 runs unit 0xA (order 0) then 0xA (order 2); thread 2 runs 0xB (order 1)
            w.frame_begin(0, 100, 1)
            w.unit_block(0, 0, 0, 0xA, 1, [], [(0xA, b"f0-a0-in")])
            w.unit_block(1, 0, 0, 0xA, 1, [], [(0xA, b"f0-a0-out")])
            w.unit_block(0, 0, 1, 0xB, 2, [], [(0xB, b"f0-b0-in")])
            w.unit_block(1, 0, 1, 0xB, 2, [], [(0xB, b"f0-b0-out")])
            w.unit_block(0, 0, 2, 0xA, 1, [], [(0xA, b"f0-a1-in")])
            w.unit_block(1, 0, 2, 0xA, 1, [], [(0xA, b"f0-a1-out")])
            w.frame_end(0, 1, 0, 3)

            # Frame 1: thread 2 finishes 0xB FIRST (order 0!), while 0xA runs at order 1 and 2
            w.frame_begin(1, 116, 1)
            w.unit_block(0, 0, 0, 0xB, 2, [], [(0xB, b"f1-b0-in")])
            w.unit_block(1, 0, 0, 0xB, 2, [], [(0xB, b"f1-b0-out")])
            w.unit_block(0, 0, 1, 0xA, 1, [], [(0xA, b"f1-a0-in")])
            w.unit_block(1, 0, 1, 0xA, 1, [], [(0xA, b"f1-a0-out")])
            w.unit_block(0, 0, 2, 0xA, 1, [], [(0xA, b"f1-a1-in")])
            w.unit_block(1, 0, 2, 0xA, 1, [], [(0xA, b"f1-a1-out")])
            w.frame_end(1, 1, 0, 3)
            w.close()

            frames = read_stream(p)["frames"]
            paired = pair_cross_frame_invariant(frames)

            # Intra-frame uses (unit, order)
            self.assertEqual(paired["intra_frame"][1][(0xB, 0)][0].blocks[0][1], b"f1-b0-in")
            self.assertEqual(paired["intra_frame"][1][(0xB, 0)][1].blocks[0][1], b"f1-b0-out")

            # Cross-frame uses (unit, occ), unaffected by order swap!
            trans = paired["cross_frame"][(0, 1)]
            b0_prev, b0_curr = trans[(0xB, 0)]
            self.assertEqual(b0_prev.blocks[0][1], b"f0-b0-out")
            self.assertEqual(b0_curr.blocks[0][1], b"f1-b0-in")

            a0_prev, a0_curr = trans[(0xA, 0)]
            self.assertEqual(a0_prev.blocks[0][1], b"f0-a0-out")
            self.assertEqual(a0_curr.blocks[0][1], b"f1-a0-in")

            a1_prev, a1_curr = trans[(0xA, 1)]
            self.assertEqual(a1_prev.blocks[0][1], b"f0-a1-out")
            self.assertEqual(a1_curr.blocks[0][1], b"f1-a1-in")

    def test_start_gate_and_frame_split_state_machine(self) -> None:
        gate = MonotonicStartGate(required_increases=2)
        # Equal ticks neither count nor reset
        self.assertFalse(gate.observe(10, active=True))
        self.assertFalse(gate.observe(10, active=True))
        self.assertFalse(gate.observe(20, active=True))  # streak 1
        self.assertFalse(gate.observe(20, active=True))  # still streak 1
        # Decrease resets streak and sets new base
        self.assertFalse(gate.observe(15, active=True))  # streak 0, base 15
        self.assertFalse(gate.observe(18, active=True))  # streak 1
        # Inactive resets everything
        self.assertFalse(gate.observe(99, active=False))
        self.assertFalse(gate.observe(30, active=True))  # base 30, streak 0
        self.assertFalse(gate.observe(40, active=True))  # streak 1
        self.assertTrue(gate.observe(50, active=True))   # streak 2 -> OPEN
        # One-way open even on rewind or inactive
        self.assertTrue(gate.observe(0, active=False))

        sm = FrameSplitStateMachine(frame_limit=3)
        # Before gate opens, ticks 10 -> 20 -> 30 open gate on 30
        self.assertIsNone(sm.dispatch(1, 10))
        self.assertIsNone(sm.dispatch(1, 20))
        f0 = sm.dispatch(1, 30)
        assert f0 is not None
        self.assertEqual(f0.boundary, BoundaryKind.GATE)

        # Distinct unit at same tick stays in same frame
        f0_again = sm.dispatch(2, 30)
        self.assertIs(f0_again, f0)
        self.assertEqual(f0.dispatches, 2)

        # Repeat unit at same tick splits with UNIT_REPEAT_PAUSED
        f1 = sm.dispatch(1, 30)
        assert f1 is not None
        self.assertEqual(f1.boundary, BoundaryKind.UNIT_REPEAT_PAUSED)
        self.assertTrue(f1.paused)

        # Time advance splits with TIME_ADVANCE
        f2 = sm.dispatch(1, 46)
        assert f2 is not None
        self.assertEqual(f2.boundary, BoundaryKind.TIME_ADVANCE)
        self.assertFalse(f2.paused)

        # Next boundary hits frame_limit=3 (closes f2 and stops)
        self.assertIsNone(sm.dispatch(1, 62))
        self.assertTrue(sm.done)
        self.assertEqual(sm.stop_reason, "frame_limit_reached")
        summary = sm.summary()
        self.assertEqual(summary["frames"], 3)
        self.assertEqual(summary["paused"], 1)
        self.assertEqual(summary["boundaries"], ["GATE", "UNIT_REPEAT_PAUSED", "TIME_ADVANCE"])

        # Auxiliary opens frame only when no frame is open
        sm_aux = FrameSplitStateMachine()
        self.assertIsNone(sm_aux.auxiliary(5))  # gate not open yet
        sm_aux.dispatch(1, 10)
        sm_aux.dispatch(1, 20)
        sm_aux.dispatch(1, 30)
        sm_aux.auxiliary(30)
        self.assertEqual(sm_aux.current_frame.boundary, BoundaryKind.GATE)  # type: ignore[union-attr]
        self.assertEqual(sm_aux.current_frame.auxiliary_events, 1)  # type: ignore[union-attr]
        sm_aux._close()
        aux_f = sm_aux.auxiliary(40)
        assert aux_f is not None
        self.assertEqual(aux_f.boundary, BoundaryKind.AUXILIARY)
        sm_aux.dispatch(1, 40, active=False)
        self.assertTrue(sm_aux.done)
        self.assertEqual(sm_aux.stop_reason, "inactive")


if __name__ == "__main__":
    unittest.main()
