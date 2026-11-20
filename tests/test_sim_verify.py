from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest

from sim_verify.bitdiff import compare_f32_arrays, run_differential_fuzz
from sim_verify.boundary_index import IndexedBoundaryReader, build_stream_index
from sim_verify.boundary_recorder import FormatError, Rules, Writer, check_stream, read_stream, walk_unit
from sim_verify import msvc_ninja, partest, pcore_run
from sim_verify.provenance import freeze_contract, verify_contract
from sim_verify.spec_lint import check_spec_pair, scan_text
from sim_verify.stateless_check import GuardViolation, check_ast_stateless, guarded_call, run_isolated_steps


class SimVerifyTests(unittest.TestCase):
    def test_bitdiff_f32_and_signed_zero(self) -> None:
        res_ok = compare_f32_arrays([1.0, -2.5, 0.0], [1.0, -2.5, 0.0])
        self.assertTrue(res_ok["all_bitwise_equal"])
        res_neg_zero = compare_f32_arrays([0.0], [-0.0])
        self.assertFalse(res_neg_zero["all_bitwise_equal"])
        self.assertEqual(res_neg_zero["first_difference"]["index"], 0)

    def test_differential_fuzz_with_known_diff(self) -> None:
        def ref_fn(inp: dict) -> bytes:
            return struct.pack("<II", inp["x"] + 1, inp["bug"] * 2)

        def cand_fn(inp: dict) -> bytes:
            return struct.pack("<II", inp["x"] + 1, inp["bug"] * 3)

        def gen_fn(rng, i: int) -> dict:
            return {"x": rng.randint(0, 100), "bug": 1 if i % 4 == 0 else 0}

        def pred(inp: dict, r: bytes, c: bytes) -> bool:
            return inp["bug"] == 1 and r[:4] == c[:4] and r[4:] != c[4:]

        rep = run_differential_fuzz(ref_fn, cand_fn, gen_fn, cases=16, known_diff_predicate=pred)
        self.assertEqual(rep["status"], "PASS")
        self.assertEqual(rep["known_diffs"], 4)

    def test_frozen_contract_and_review_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f1 = root / "a.txt"
            f1.write_text("hello\n", encoding="utf-8")
            contract = freeze_contract([f1], root)
            self.assertEqual(verify_contract(contract, root)["status"], "PASS")

            review = root / "review.json"
            review.write_text(
                json.dumps({
                    "contract_sha256": contract["contract_sha256"],
                    "verdict": "ACCEPTED",
                    "author": "engineer-a",
                    "reviewer": "engineer-b",
                    "must_fix": [],
                }),
                encoding="utf-8",
            )
            self.assertEqual(verify_contract(contract, root, require_review=review)["status"], "PASS")

            # Self-review must be refused
            review.write_text(
                json.dumps({
                    "contract_sha256": contract["contract_sha256"],
                    "verdict": "ACCEPTED",
                    "author": "engineer-a",
                    "reviewer": "engineer-a",
                    "must_fix": [],
                }),
                encoding="utf-8",
            )
            self.assertEqual(verify_contract(contract, root, require_review=review)["status"], "REFUSED")

    def test_spec_lint_and_traceability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = root / "S1_model_SPEC.md"
            trace = root / "S1_model_TRACEABILITY.md"
            spec.write_text("# Spec\n**S1-01** The solver advances by one step.\n", encoding="utf-8")
            trace.write_text("| ID | Level | Note |\n| S1-01 | VERIFIED | Unit test |\n", encoding="utf-8")
            res = check_spec_pair(spec, trace, banned_substrings=["legacy_term"])
            self.assertEqual(res["status"], "PASS")

            hits = scan_text("Constant 0xdeadbeef in legacy_term", banned_substrings=["legacy_term"])
            self.assertGreaterEqual(len(hits), 2)

    def test_stateless_isolation_and_audit_guard(self) -> None:
        problems = check_ast_stateless("G = 1\ndef f(x=[]):\n    global G\n    return x\n")
        self.assertEqual(len(problems), 2)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mod = root / "sim_step.py"
            mod.write_text(
                "def step(state, drive):\n"
                "    return {'pos': state['pos'] + drive['vel'], 'ticks': state['ticks'] + 1}\n",
                encoding="utf-8",
            )
            res = run_isolated_steps(mod, "step", {"pos": 0, "ticks": 0}, [{"vel": 3}, {"vel": -1}])
            self.assertEqual(res["status"], "PASS")
            self.assertEqual(res["final_state"], {"pos": 2, "ticks": 2})

            with self.assertRaises(GuardViolation):
                guarded_call(lambda: open(mod, "r").close())

    def test_boundary_recorder_stream_and_self_check(self) -> None:
        rules_spec = {
            "limits": {"regions": 64},
            "categories": {
                "config": {"check": True, "host_may_write": False},
                "state": {"check": False, "host_may_write": False},
            },
            "types": {
                "unit": [
                    ["region", "0x0", "0x4", "config"],
                    ["region", "0x4", "0x4", "state"],
                ]
            },
        }
        rules = Rules(rules_spec)
        mem = {0x1000: b"\x01\x00\x00\x00\x10\x00\x00\x00"}
        merged, distinct = walk_unit(rules, lambda a, n: mem[0x1000][a - 0x1000 : a - 0x1000 + n], 0x1000)
        self.assertEqual(len(distinct), 2)

        with tempfile.TemporaryDirectory() as tmp:
            stream_path = Path(tmp) / "trace.bdrc"
            w = Writer(stream_path, rules.sha256, "00" * 32, frame_limit=2, pid=1234)
            # Frame 0: entry & exit have identical config (0x01), state changes 0x10 -> 0x20
            w.frame_begin(0, 1, 100)
            w.unit_block(0, 0, 0, 0x1000, 100, distinct, [(0x1000, b"\x01\x00\x00\x00\x10\x00\x00\x00")])
            w.unit_block(1, 0, 0, 0x1000, 100, distinct, [(0x1000, b"\x01\x00\x00\x00\x20\x00\x00\x00")])
            w.frame_end(0, 100, 0, 1)
            # Frame 1: entry matches Frame 0 exit
            w.frame_begin(1, 2, 100)
            w.unit_block(0, 0, 0, 0x1000, 100, distinct, [(0x1000, b"\x01\x00\x00\x00\x20\x00\x00\x00")])
            w.unit_block(1, 0, 0, 0x1000, 100, distinct, [(0x1000, b"\x01\x00\x00\x00\x30\x00\x00\x00")])
            w.frame_end(1, 100, 0, 1)
            w.close({"status": "stopped"})

            chk = check_stream(stream_path, rules)
            self.assertEqual(chk["status"], "PASS")

            # Tamper last byte -> CRC failure
            raw = bytearray(stream_path.read_bytes())
            raw[-1] ^= 0xFF
            stream_path.write_bytes(raw)
            with self.assertRaises(FormatError):
                read_stream(stream_path)

    def test_partest_cli_and_pcore_alias(self) -> None:
        self.assertIs(pcore_run.select_highest_efficiency_cpu_sets, pcore_run.select)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tdir = root / "tests"
            tdir.mkdir()
            (tdir / "test_sample.py").write_text(
                "import unittest\n"
                "class SampleTest(unittest.TestCase):\n"
                "    def test_one(self): self.assertEqual(1 + 1, 2)\n"
                "    def test_two(self): self.assertTrue(True)\n",
                encoding="utf-8",
            )
            rep_path = root / "partest_report.json"
            rc = partest.main(["--test-dir", str(tdir), "--jobs", "2", "--report", str(rep_path)])
            self.assertEqual(rc, 0)
            rep = json.loads(rep_path.read_text(encoding="utf-8"))
            self.assertEqual(rep["schema"], "sim_verify-partest-report-v1")
            self.assertEqual(rep["tests_run"], 2)
            self.assertEqual(rep["status"], "PASS")

    def test_native_cpp_recorder_cross_language_stream(self) -> None:
        native_dir = Path(__file__).resolve().parents[1] / "native"
        try:
            msvc_ninja.install()
        except Exception as exc:
            self.skipTest(f"MSVC toolchain not available: {exc}")
        with tempfile.TemporaryDirectory(prefix="sim_verify_xlang_") as tmp:
            bdir = Path(tmp) / "build"
            bdrc = Path(tmp) / "native_out.bdrc"
            r_cfg = msvc_ninja.configure(native_dir, bdir)
            self.assertEqual(r_cfg.returncode, 0, r_cfg.stdout + r_cfg.stderr)
            r_bld = msvc_ninja.build(bdir, "Release")
            self.assertEqual(r_bld.returncode, 0, r_bld.stdout + r_bld.stderr)
            exe = bdir / "Release" / "sim_verify_recorder_test.exe"
            self.assertTrue(exe.is_file())
            import subprocess
            r_run = subprocess.run([str(exe), str(bdrc)], capture_output=True, text=True, timeout=60)
            self.assertEqual(r_run.returncode, 0, r_run.stdout + r_run.stderr)
            self.assertTrue(bdrc.is_file())
            parsed = read_stream(bdrc)
            self.assertEqual(len(parsed["frames"]), 2)
            idx = build_stream_index(bdrc)
            self.assertEqual(len(idx["frames"]), 2)
            with IndexedBoundaryReader(bdrc, idx) as reader:
                f0 = reader.frame(0)
                self.assertEqual(f0.seq, 0)
                self.assertGreaterEqual(len(f0.units), 2)


if __name__ == "__main__":
    unittest.main()
