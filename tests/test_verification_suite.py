from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import random
import struct
import sys
import tempfile
import unittest

from sim_verify.dep_surface import (
    DEFAULT_MASKS,
    certify_dependency_surface,
    classify_perturbation,
    collective_split,
    ddmin_shrink,
    settle_dependency_surface,
    xor_patch_bytes,
)
from sim_verify.input_closure import (
    ByteMask,
    FirewallViolation,
    MaskedView,
    MaskViolation,
    MemoryView,
    interval_contains,
    interval_merge,
    interval_subtract,
    scramble_outside_mask,
    verify_negative_control_ablation,
    verify_scramble_invariance,
)
from sim_verify.mutation_gate import (
    MutantEdit,
    MutantSpec,
    MutationAnchorError,
    apply_mutations,
    main as mutation_main,
    run_mutation_gate,
)
from sim_verify.purity_verifier import main as purity_main, verify_package_purity


def _picklable_dep_runner(state: bytes) -> list[bytes]:
    """Top-level picklable runner for multi-process dependency surface tests."""
    words = list(struct.unpack("<6I", state))
    # w0: single dependency (copied to output slot 5)
    # w1: overwritten (zeroed)
    # w2: unread (copied through unchanged)
    # w3, w4: joint dependency (output slot 5 flips if BOTH w3 != 0 and w4 != 0)
    # w5: baseline trigger slot
    w0, _w1, w2, w3, w4, _w5 = words
    trigger = w0 ^ (0x12345678 if (w3 != 0 and w4 != 0) else 0)
    return [struct.pack("<6I", w0, 0, w2, w3, w4, trigger)]


class InputClosureTests(unittest.TestCase):
    def test_intervals_and_memory_view(self) -> None:
        merged = interval_merge([(10, 20), (15, 25), (30, 35), (35, 40), (50, 50)])
        self.assertEqual(merged, [(10, 25), (30, 40)])
        starts = [lo for lo, _ in merged]
        self.assertTrue(interval_contains(starts, merged, 10, 15))
        self.assertFalse(interval_contains(starts, merged, 20, 10))
        self.assertTrue(interval_contains(starts, merged, 999, 0))

        sub = interval_subtract([(10, 30)], [(12, 15), (25, 35)])
        self.assertEqual(sub, [(10, 12), (15, 25)])

        mv = MemoryView(
            [
                (0x1000, struct.pack("<If", 0xCAFEBABE, 1.5)),
                (0x1004, struct.pack("<fQ", 1.5, 0x0102030405060708)),
            ]
        )
        self.assertEqual(mv.read_u32(0x1000), 0xCAFEBABE)
        self.assertEqual(mv.read_f32(0x1004), 1.5)
        self.assertEqual(mv.read_u64(0x1008), 0x0102030405060708)
        self.assertIsNone(mv.get(0x2000, 4))
        with self.assertRaises(MaskViolation):
            mv.read(0x2000, 4)

    def test_strided_mask_layers_condition_and_firewall(self) -> None:
        rules = {
            "categories": ["header", "items", "node", "control_block"],
            "layers": {
                "copy": [
                    {"id": "hdr", "source": "entry", "category": "header", "whole": True},
                    {
                        "id": "items_tail",
                        "source": "entry",
                        "category": "items",
                        "stride": 16,
                        "start_index": 1,
                        "ranges": [["0x4", "0x8"]],
                    },
                    {
                        "id": "ext_node",
                        "source": "entry",
                        "category": "node",
                        "condition": True,
                        "ranges": [[0, 4]],
                    },
                ],
                "host_events": [
                    {"id": "event_byte", "source": "entry", "category": "control_block", "ranges": [["0x10", "0x14"]]},
                ],
            },
            "forbidden": [
                {"source": "entry", "category": "control_block", "ranges": [["0x80", "0xC0"]]},
            ],
        }
        regions = [
            (0x1000, 8, 0),    # header
            (0x2000, 48, 1),   # 3 items * 16 bytes
            (0x3000, 16, 2),   # external node
            (0x4000, 16, 2),   # non-external node (excluded by condition)
            (0x5000, 0x100, 3),
        ]
        mask_copy = ByteMask(rules, layers=("copy",))
        iv_copy = mask_copy.allowed(regions, "entry", predicate=lambda addr, cat: cat == "node" and addr == 0x3000)
        self.assertEqual(
            iv_copy,
            [(0x1000, 0x1008), (0x2014, 0x2018), (0x2024, 0x2028), (0x3000, 0x3004)],
        )

        mask_both = ByteMask(rules, layers=("copy", "host_events"))
        iv_both = mask_both.allowed(regions, "entry", predicate=lambda addr, cat: addr == 0x3000)
        self.assertIn((0x5010, 0x5014), iv_both)

        bad_rules = dict(rules)
        bad_rules["layers"] = {
            "copy": [{"id": "bad_ctrl", "source": "entry", "category": "control_block", "ranges": [["0x80", "0x84"]]}]
        }
        with self.assertRaises(FirewallViolation):
            ByteMask(bad_rules, layers=("copy",)).allowed(regions, "entry")

    def test_masked_view_scramble_invariance_and_ablation(self) -> None:
        rules = {
            "copy": [
                {"id": "k0", "source": "entry", "category": "buf", "ranges": [["0x0", "0x4"]]},
                {"id": "k1", "source": "entry", "category": "buf", "ranges": [["0x8", "0xC"]]},
            ]
        }
        mask = ByteMask(rules)
        regions = [(0x1000, 16, "buf")]
        allowed = mask.allowed(regions, "entry")
        blocks_f0 = [(0x1000, struct.pack("<IIII", 10, 999, 20, 888))]
        blocks_f1 = [(0x1000, struct.pack("<IIII", 30, 777, 40, 666))]

        view = MaskedView(blocks_f0, allowed)
        self.assertEqual(view.read_u32(0x1000), 10)
        with self.assertRaises(MaskViolation):
            view.read_u32(0x1004)  # unmasked gap

        # Scrambling outside mask keeps whitelisted bytes intact
        scram = scramble_outside_mask(blocks_f0, allowed, random.Random(7))
        self.assertEqual(scram[0][1][0:4], blocks_f0[0][1][0:4])
        self.assertEqual(scram[0][1][8:12], blocks_f0[0][1][8:12])
        self.assertNotEqual(scram[0][1][4:8], blocks_f0[0][1][4:8])

        def good_stream(views):
            return [struct.pack("<I", v.read_u32(0x1000) + v.read_u32(0x1008)) for v in views]

        inv_ok = verify_scramble_invariance([blocks_f0, blocks_f1], [allowed, allowed], good_stream, seed=42)
        self.assertEqual(inv_ok["status"], "PASS")
        self.assertTrue(inv_ok["all_equal"])

        # Scramble invariance failure if run_fn depends on unmasked bytes (via raw bypass)
        def leaky_stream(views):
            return [v._mem.read(0x1000, 16) for v in views]

        with self.assertRaises(AssertionError):
            verify_scramble_invariance([blocks_f0, blocks_f1], [allowed, allowed], leaky_stream, seed=42)

        # Negative-control ablation: ablating k0 must change output
        neg_ok = verify_negative_control_ablation(
            blocks_f0,
            mask,
            regions,
            "k0",
            lambda v: struct.pack("<I", v.read_u32(0x1000) + v.read_u32(0x1008)),
            seed=5,
        )
        self.assertEqual(neg_ok["status"], "PASS")
        self.assertFalse(neg_ok["vacuous"])

        # Vacuous mask detection: run_fn ignores k0 -> output unchanged -> AssertionError
        with self.assertRaises(AssertionError):
            verify_negative_control_ablation(
                blocks_f0,
                mask,
                regions,
                "k0",
                lambda v: struct.pack("<I", v.read_u32(0x1008)),
                seed=5,
            )


class DepSurfaceTests(unittest.TestCase):
    def test_xor_patch_and_classify_all_outcomes(self) -> None:
        base = struct.pack("<4I", 1, 2, 3, 4)
        patched = xor_patch_bytes(base, [0, 8], 0x000000FF)
        self.assertEqual(struct.unpack("<4I", patched), (1 ^ 0xFF, 2, 3 ^ 0xFF, 4))

        def run_unread(b: bytes) -> list[bytes]:
            return [b]

        def run_overwritten(b: bytes) -> list[bytes]:
            w = list(struct.unpack("<4I", b))
            w[0] = 1
            return [struct.pack("<4I", *w)]

        def run_mixed(b: bytes) -> list[bytes]:
            w = list(struct.unpack("<4I", b))
            return [b, struct.pack("<4I", 1, w[1], w[2], w[3])]

        def run_dep(b: bytes) -> list[bytes]:
            w = list(struct.unpack("<4I", b))
            return [struct.pack("<4I", w[0], w[1] ^ w[0], w[2], w[3])]

        def run_reject(b: bytes) -> list[bytes]:
            raise ValueError("invalid state")

        self.assertEqual(classify_perturbation(base, run_unread(base), run_unread, [0], 0x41414141), "unread")
        self.assertEqual(classify_perturbation(base, run_overwritten(base), run_overwritten, [0], 0x41414141), "overwritten")
        self.assertEqual(classify_perturbation(base, run_mixed(base), run_mixed, [0], 0x41414141), "mixed")
        self.assertEqual(classify_perturbation(base, run_dep(base), run_dep, [0], 0x41414141), "dependency")
        self.assertEqual(classify_perturbation(base, [base], run_reject, [0], 0x41414141), "rejected")

    def test_synthetic_joint_dependency_ddmin_and_settle(self) -> None:
        # 8 words:
        # 0: single_dep (affects output slot 7)
        # 1: unread_a
        # 2: joint_a (together with joint_b flips output slot 7)
        # 3: overwritten
        # 4: unread_b
        # 5: joint_b (together with joint_a flips output slot 7)
        # 6: mixed (unread on step 0, overwritten on step 1)
        # 7: trigger output slot
        base = struct.pack("<8I", 10, 20, 0, 30, 40, 0, 50, 0)

        def run_fn(s: bytes) -> list[bytes]:
            w = list(struct.unpack("<8I", s))
            trigger = (w[0] * 3) ^ (0x55555555 if (w[2] != 0 and w[5] != 0) else 0)
            step0 = struct.pack("<8I", w[0], w[1], w[2], 0, w[4], w[5], w[6], trigger)
            step1 = struct.pack("<8I", w[0], w[1], w[2], 0, w[4], w[5], 50, trigger)
            return [step0, step1]

        templates = {
            "single_dep": [0],
            "unread_a": [4],
            "joint_a": [8],
            "overwritten": [12],
            "unread_b": [16],
            "joint_b": [20],
            "mixed_field": [24],
        }
        report = certify_dependency_surface(base, templates, run_fn, masks=DEFAULT_MASKS, workers=1)
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["remainder_clean_under_all_masks"])

        single_names = [d["template"] for d in report["single_dependencies"]]
        self.assertEqual(single_names, ["single_dep"])

        self.assertEqual(len(report["joint_dependencies"]), 1)
        self.assertEqual(sorted(report["joint_dependencies"][0]["members"]), ["joint_a", "joint_b"])

        self.assertEqual(
            sorted(report["final_quiet_templates"]),
            ["mixed_field", "overwritten", "unread_a", "unread_b"],
        )
        self.assertEqual(len(report["final_flip_results"]), len(DEFAULT_MASKS))

    def test_ddmin_and_multiprocess_certify(self) -> None:
        base = struct.pack("<6I", 7, 11, 13, 0, 0, 0)
        templates = {
            "single": [0],
            "over": [4],
            "unread": [8],
            "joint_x": [12],
            "joint_y": [16],
        }
        rep = certify_dependency_surface(base, templates, _picklable_dep_runner, workers=2)
        self.assertEqual(rep["status"], "PASS")
        self.assertEqual([d["template"] for d in rep["single_dependencies"]], ["single"])
        self.assertEqual(sorted(rep["joint_dependencies"][0]["members"]), ["joint_x", "joint_y"])
        self.assertEqual(sorted(rep["final_quiet_templates"]), ["over", "unread"])


class PurityVerifierTests(unittest.TestCase):
    def _write_pkg(self, root: Path, files: dict[str, str]) -> Path:
        pkg = root / "pure_pkg"
        pkg.mkdir(parents=True, exist_ok=True)
        for rel, content in files.items():
            (pkg / rel).write_text(content, encoding="utf-8")
        return pkg

    def test_pure_package_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkg = self._write_pkg(
                Path(tmp),
                {
                    "__init__.py": "",
                    "helper.py": (
                        "from dataclasses import dataclass\n"
                        "SCALE = 2.0\n"
                        "TABLE = {'a': 1, 'b': 3}\n\n"
                        "@dataclass(frozen=True)\n"
                        "class Vec:\n"
                        "    x: float\n"
                        "    y: float\n\n"
                        "def read_table(d, key):\n"
                        "    return d.get(key, 0)\n\n"
                        "def compute(v, key):\n"
                        "    local = [v.x * SCALE, v.y * SCALE]\n"
                        "    return local[0] + local[1] + read_table(TABLE, key)\n"
                    ),
                    "solver.py": (
                        "from .helper import Vec, compute\n\n"
                        "def step(x, y, key):\n"
                        "    v = Vec(x, y)\n"
                        "    return compute(v, key)\n"
                    ),
                },
            )
            res = verify_package_purity(pkg, "pure_pkg", [("solver", "step")])
            self.assertEqual(res["status"], "PASS", res["problems"])
            self.assertEqual(res["problems"], [])
            self.assertIn("helper.Vec", res["live_classes"])

            rep_path = Path(tmp) / "purity_report.json"
            rc = purity_main(
                [
                    "--package-dir",
                    str(pkg),
                    "--package-name",
                    "pure_pkg",
                    "--entry",
                    "solver:step",
                    "--report",
                    str(rep_path),
                ]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(rep_path.read_text(encoding="utf-8"))["status"], "PASS")

    def test_negative_bypasses_all_rejected(self) -> None:
        cases = {
            "mutable_dict_to_helper": (
                "TABLE = {'a': 1}\n"
                "def mutate_helper(d):\n"
                "    d['x'] = 2\n"
                "    return d['a']\n"
                "def step(x):\n"
                "    return mutate_helper(TABLE) + x\n"
            ),
            "class_attr_mutation": (
                "class Box:\n"
                "    count = 0\n"
                "def step(x):\n"
                "    Box.count = x\n"
                "    return x\n"
            ),
            "global_statement": (
                "STATE = 0\n"
                "def step(x):\n"
                "    global STATE\n"
                "    STATE = x\n"
                "    return STATE\n"
            ),
            "mutable_default": (
                "def step(x, memo=[]):\n"
                "    memo.append(x)\n"
                "    return len(memo)\n"
            ),
            "wrapped_and_frame_access": (
                "def inner(x):\n"
                "    return x + 1\n"
                "def step(gen):\n"
                "    f = gen.gi_frame\n"
                "    w = inner.__wrapped__\n"
                "    return (f, w)\n"
            ),
            "setattr_on_non_self": (
                "class Node:\n"
                "    def __init__(self, v):\n"
                "        self.v = v\n"
                "def step(other):\n"
                "    setattr(other, 'v', 42)\n"
                "    return other.v\n"
            ),
        }
        for label, code in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmp:
                pkg = self._write_pkg(Path(tmp), {"__init__.py": "", "mod.py": code})
                res = verify_package_purity(pkg, "pure_pkg", [("mod", "step")])
                self.assertEqual(res["status"], "FAIL", f"{label} unexpectedly passed")
                self.assertGreater(len(res["problems"]), 0, f"{label} had no problems")


class MutationGateTests(unittest.TestCase):
    def test_apply_mutations_and_missing_anchor(self) -> None:
        src = "line1\r\nline2\r\n"
        out = apply_mutations(src, [MutantEdit("line1\nline2", "line1\nchanged")])
        self.assertEqual(out, "line1\r\nchanged\r\n")
        with self.assertRaises(MutationAnchorError):
            apply_mutations(src, [MutantEdit("missing_anchor", "x")])

    def test_mutation_gate_pass_and_unkilled_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "calc.py"
            target.write_text(
                "def add_one(x):\n"
                "    unused_flag = False\n"
                "    if unused_flag:\n"
                "        return -999\n"
                "    return x + 1\n",
                encoding="utf-8",
            )
            test_file = root / "test_calc.py"
            test_file.write_text(
                "import importlib.util, os, unittest\n"
                "spec = importlib.util.spec_from_file_location('calc', os.environ['TARGET_UNDER_TEST'])\n"
                "mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
                "class T(unittest.TestCase):\n"
                "    def test_add(self):\n"
                "        self.assertEqual(mod.add_one(4), 5)\n"
                "if __name__ == '__main__':\n"
                "    unittest.main()\n",
                encoding="utf-8",
            )

            m1 = MutantSpec("M1", (MutantEdit("return x + 1", "return x + 2"),), "off-by-one")
            rep_pass = run_mutation_gate(
                target,
                [m1],
                [sys.executable, "-B", str(test_file)],
                cwd=root,
            )
            self.assertEqual(rep_pass["status"], "PASS")
            self.assertTrue(rep_pass["control_clean"])
            self.assertEqual(rep_pass["killed"], 1)
            self.assertEqual(rep_pass["survived"], [])

            # Unkilled mutant: mutates dead branch -> tests still pass -> gate MUST fail
            m_unkilled = MutantSpec("M2_survives", (MutantEdit("return -999", "return -888"),), "dead branch")
            rep_fail = run_mutation_gate(
                target,
                [m1, m_unkilled],
                [sys.executable, "-B", str(test_file)],
                cwd=root,
            )
            self.assertEqual(rep_fail["status"], "FAIL")
            self.assertEqual(rep_fail["survived"], ["M2_survives"])

            # CLI smoke test
            cfg_path = root / "mutants.json"
            cfg_path.write_text(
                json.dumps(
                    {
                        "target_file": str(target),
                        "test_cmd": [sys.executable, "-B", str(test_file)],
                        "cwd": str(root),
                        "mutants": [{"name": "M1", "edits": [{"old": "return x + 1", "new": "return x + 2"}]}],
                    }
                ),
                encoding="utf-8",
            )
            out_path = root / "report.json"
            rc = mutation_main(["--config", str(cfg_path), "--out", str(out_path)])
            self.assertEqual(rc, 0)
            self.assertTrue(json.loads(out_path.read_text(encoding="utf-8"))["passed"])


if __name__ == "__main__":
    unittest.main()
