"""Bitwise float32 / binary stream comparator and known-defect differential fuzzing harness.

Provides:
1. `compare_f32_arrays`: compares two float32 sequences at the IEEE-754 u32 bit level
   (distinguishing -0.0 from +0.0 and NaN payloads) and reports the exact first difference.
2. `run_differential_fuzz`: runs a reference implementation against a candidate implementation
   across seeded random input perturbations, supporting explicit "known difference" assertions
   so historical defects in a frozen reference can be isolated to exact byte/field spans
   without masking any other discrepancy.
"""
from __future__ import annotations

import random
import struct
from typing import Any, Callable


def f32_bits(val: float) -> int:
    return struct.unpack("<I", struct.pack("<f", float(val)))[0]


def compare_f32_arrays(expected: list[float], actual: list[float]) -> dict[str, Any]:
    if len(expected) != len(actual):
        return {
            "all_bitwise_equal": False,
            "count": min(len(expected), len(actual)),
            "first_difference": {"reason": "length_mismatch", "expected_len": len(expected), "actual_len": len(actual)},
        }
    for idx, (e, a) in enumerate(zip(expected, actual)):
        eb, ab = f32_bits(e), f32_bits(a)
        if eb != ab:
            return {
                "all_bitwise_equal": False,
                "count": len(expected),
                "first_difference": {
                    "index": idx,
                    "expected_f32": struct.unpack("<f", struct.pack("<I", eb))[0],
                    "actual_f32": struct.unpack("<f", struct.pack("<I", ab))[0],
                    "expected_hex": f"0x{eb:08X}",
                    "actual_hex": f"0x{ab:08X}",
                    "ulp_diff": abs(eb - ab),
                },
            }
    return {"all_bitwise_equal": True, "count": len(expected), "first_difference": None}


def run_differential_fuzz(
    reference_fn: Callable[[dict[str, Any]], bytes],
    candidate_fn: Callable[[dict[str, Any]], bytes],
    generator_fn: Callable[[random.Random, int], dict[str, Any]],
    cases: int = 64,
    seed: int = 1,
    known_diff_predicate: Callable[[dict[str, Any], bytes, bytes], bool] | None = None,
) -> dict[str, Any]:
    rng = random.Random(seed)
    exact_matches = 0
    known_diffs = 0
    mismatches = []

    for i in range(cases):
        inp = generator_fn(rng, i)
        ref_out = reference_fn(inp)
        cand_out = candidate_fn(inp)
        if ref_out == cand_out:
            exact_matches += 1
        elif known_diff_predicate is not None and known_diff_predicate(inp, ref_out, cand_out):
            known_diffs += 1
        else:
            first_off = next((idx for idx, (b0, b1) in enumerate(zip(ref_out, cand_out)) if b0 != b1), min(len(ref_out), len(cand_out)))
            mismatches.append({"case": i, "first_offset": first_off, "ref_len": len(ref_out), "cand_len": len(cand_out)})

    return {
        "schema": "sim_verify-differential-fuzz-v1",
        "status": "PASS" if not mismatches else "MISMATCH",
        "cases": cases,
        "exact_matches": exact_matches,
        "known_diffs": known_diffs,
        "mismatches": mismatches,
    }
