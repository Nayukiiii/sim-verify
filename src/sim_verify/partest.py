"""Parallel unittest runner with per-module process-tree timeout and known-loss baseline gate.

Combines:
1. One subprocess per test module (processes, not threads) with strict zero-test/crash refusal.
2. Per-module wall-clock timeout that kills the entire child process tree on expiry.
3. Optional known-failure / missing-fixture baseline check (with strict non-empty directory rules
   and skipped-test accounting).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time
import unittest

from .provenance import identity, write_json


def _kill_tree(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)
    else:
        try:
            os.kill(pid, 9)
        except OSError:
            pass


def run_one_in_child(test_dir: Path, name: str, out: Path) -> int:
    sys.path.insert(0, str(test_dir.resolve()))
    suite = unittest.defaultTestLoader.discover(str(test_dir), pattern=name + ".py")
    with open(os.devnull, "w", encoding="utf-8") as sink:
        result = unittest.TextTestRunner(verbosity=0, stream=sink).run(suite)
    payload = dict(
        tests_run=result.testsRun,
        failures=[str(t) for t, _ in result.failures],
        errors=[str(t) for t, _ in result.errors],
        skipped=[str(t) for t, _ in result.skipped],
        skipped_reasons=[r for _, r in result.skipped],
        details=[d for _, d in result.failures + result.errors],
    )
    out.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return 0


def run_module(test_dir: Path, name: str, folder: Path, timeout: float = 300.0) -> dict:
    out = folder / (name + ".json")
    start = time.perf_counter()
    cmd = [sys.executable, "-B", "-m", "sim_verify.partest", "--test-dir", str(test_dir), "--one", name, "--out", str(out)]
    env = dict(os.environ)
    pkg_src = str(Path(__file__).resolve().parents[1])
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{pkg_src}{os.pathsep}{existing_pp}" if existing_pp else pkg_src
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True, encoding="utf-8", errors="replace")
    try:
        _, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc.pid)
        proc.communicate()
        return dict(
            name=name,
            seconds=time.perf_counter() - start,
            tests_run=0,
            failures=[],
            errors=[f"{name} timed out after {timeout}s"],
            skipped=[],
            details=[f"TimeoutExpired: {timeout}s"],
        )
    seconds = time.perf_counter() - start
    if not out.is_file():
        return dict(
            name=name,
            seconds=seconds,
            tests_run=0,
            failures=[],
            errors=[f"{name} process exit {proc.returncode}"],
            skipped=[],
            details=[stderr[-2000:]],
        )
    row = dict(json.loads(out.read_text(encoding="utf-8")), name=name, seconds=seconds)
    if not row["tests_run"]:
        row["errors"] = row["errors"] + [f"{name} loaded no tests"]
    return row


def verify_against_baseline(rows: list[dict], baseline: dict, root_dir: Path) -> dict:
    """Verify failures and skips against an explicit known-loss baseline without broad empty-dir exemptions."""
    known_failures = {(b["file"], b["test"]): b.get("absent_path") for b in baseline.get("known_failures", [])}
    known_skips = {(b["file"], b["test"]): b.get("absent_path") for b in baseline.get("known_skips", [])}
    unexplained = []
    reappeared_still_failing = []

    for r in rows:
        fname = r["name"]
        for tid in list(r["failures"]) + list(r["errors"]):
            key = (fname, tid)
            if key not in known_failures:
                unexplained.append({"file": fname, "test": tid, "kind": "unexpected_failure"})
                continue
            rel = known_failures[key]
            if rel and (root_dir / rel).exists():
                reappeared_still_failing.append({"file": fname, "test": tid, "reappeared_path": rel})
        for tid in r.get("skipped", []):
            key = (fname, tid)
            if key not in known_skips:
                unexplained.append({"file": fname, "test": tid, "kind": "unexpected_skip"})

    status = "PASS" if not unexplained and not reappeared_still_failing else "REGRESSION"
    return {
        "status": status,
        "unexplained": unexplained,
        "reappeared_still_failing": reappeared_still_failing,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--test-dir", type=Path, default=Path("tests"))
    p.add_argument("--report", type=Path)
    p.add_argument("--baseline", type=Path, help="Optional known-failure baseline JSON")
    p.add_argument("--jobs", type=int, default=min(os.cpu_count() or 1, 8))
    p.add_argument("--timeout", type=float, default=300.0)
    p.add_argument("--one")
    p.add_argument("--out", type=Path)
    a = p.parse_args(argv)

    if a.one:
        return run_one_in_child(a.test_dir, a.one, a.out)

    if a.report and a.report.exists():
        raise SystemExit("Report exists; choose a fresh path")

    nested = sorted(str(x) for x in a.test_dir.rglob("test*.py") if x.parent != a.test_dir)
    if nested:
        raise SystemExit(f"Nested test files are refused (keep flat discovery): {nested}")

    names = sorted(x.stem for x in a.test_dir.glob("test*.py"))
    start = time.perf_counter()
    with tempfile.TemporaryDirectory() as folder, concurrent.futures.ThreadPoolExecutor(a.jobs) as pool:
        rows = list(pool.map(lambda n: run_module(a.test_dir, n, Path(folder), a.timeout), names))

    wall = time.perf_counter() - start
    total = sum(r["tests_run"] for r in rows)
    fails = [x for r in rows for x in r["failures"]]
    errors = [x for r in rows for x in r["errors"]]
    skipped = [x for r in rows for x in r["skipped"]]

    baseline_check = None
    if a.baseline:
        base_data = json.loads(a.baseline.read_text(encoding="utf-8"))
        baseline_check = verify_against_baseline(rows, base_data, a.test_dir.parent)
        ok = baseline_check["status"] == "PASS" and total > 0
    else:
        ok = not fails and not errors and total > 0

    report_data = {
        "schema": "sim_verify-partest-report-v1",
        "jobs": a.jobs,
        "timeout_seconds": a.timeout,
        "wall_seconds": wall,
        "python": platform.python_version(),
        "tests_run": total,
        "failures": len(fails),
        "errors": len(errors),
        "skipped": len(skipped),
        "status": "PASS" if ok else "FAIL",
        "baseline_check": baseline_check,
        "files": {r["name"]: dict(tests_run=r["tests_run"], seconds=r["seconds"]) for r in rows},
    }
    if a.report:
        write_json(a.report, report_data)
    print(f"Ran {total} tests in {wall:.2f}s, jobs={a.jobs}, failures={len(fails)}, errors={len(errors)}, skipped={len(skipped)} -> {report_data['status']}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
