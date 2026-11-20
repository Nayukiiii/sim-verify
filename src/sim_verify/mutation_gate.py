"""Language-agnostic anchor-driven source mutation testing gate.

Proves that a test suite detects injected defects (mutants) rather than passing
vacuously:
1. `MutantEdit` and `MutantSpec`: declarative text/regex edits anchored to exact
   substrings or regular expressions in the target source file.
2. `apply_mutations`: adapts line endings (LF vs CRLF) to match the target file
   and fails loudly (`MutationAnchorError`) if any anchor is missing.
3. `run_mutation_gate`: copies the target file into an isolated temporary
   directory per mutant, exposes its path via ``env_var``, verifies that the
   unmutated ``M0`` control passes, and requires every mutant to be killed
   (non-zero test exit code).
4. CLI `main()`: reads a JSON mutant configuration file and emits a structured
   audit report.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any


class MutationAnchorError(ValueError):
    """Raised when a mutation anchor cannot be found in the target text."""


@dataclass(frozen=True)
class MutantEdit:
    old: str
    new: str
    is_regex: bool = False


@dataclass(frozen=True)
class MutantSpec:
    name: str
    edits: tuple[MutantEdit, ...] = ()
    description: str = ""


def _adapt_newlines(pattern: str, nl: str) -> str:
    if nl == "\r\n":
        return pattern.replace("\r\n", "\n").replace("\n", "\r\n")
    return pattern.replace("\r\n", "\n")


def apply_mutations(text: str, edits: Sequence[MutantEdit]) -> str:
    """Apply ``edits`` sequentially to ``text``, adapting LF/CRLF line endings."""
    nl = "\r\n" if "\r\n" in text else "\n"
    cur = text
    for edit in edits:
        if edit.is_regex:
            rep = _adapt_newlines(edit.new, nl)
            cur, count = re.subn(edit.old, rep, cur, count=1)
            if count < 1:
                raise MutationAnchorError(f"mutation regex anchor missing: {edit.old[:80]!r}")
        else:
            old = _adapt_newlines(edit.old, nl)
            new = _adapt_newlines(edit.new, nl)
            if cur.count(old) < 1:
                raise MutationAnchorError(f"mutation anchor missing: {edit.old[:80]!r}")
            cur = cur.replace(old, new, 1)
    return cur


def run_mutation_gate(
    target_file: Path,
    mutants: Sequence[MutantSpec],
    test_cmd: Sequence[str],
    env_var: str = "TARGET_UNDER_TEST",
    cwd: Path | None = None,
    timeout: float = 300.0,
    extra_rewrites: Sequence[MutantEdit] = (),
) -> dict[str, Any]:
    """Run ``M0`` clean control plus every mutant in ``mutants`` against ``test_cmd``."""
    target_path = Path(target_file).resolve()
    raw_bytes = target_path.read_bytes()
    has_bom = raw_bytes.startswith(b"\xef\xbb\xbf")
    orig_text = raw_bytes.decode("utf-8-sig")
    orig_sha256 = hashlib.sha256(raw_bytes).hexdigest().upper()

    specs = list(mutants)
    if not any(spec.name == "M0" for spec in specs):
        specs.insert(0, MutantSpec(name="M0", edits=(), description="clean control"))

    rows: list[dict[str, Any]] = []
    work_cwd = str(Path(cwd).resolve()) if cwd is not None else str(target_path.parent)

    with tempfile.TemporaryDirectory(prefix="sim_verify_mutants_") as tmp:
        tmp_root = Path(tmp)
        for spec in specs:
            mutant_path = tmp_root / spec.name / target_path.name
            mutant_path.parent.mkdir(parents=True, exist_ok=True)
            body = apply_mutations(orig_text, spec.edits)
            if extra_rewrites:
                body = apply_mutations(body, extra_rewrites)
            encoded = body.encode("utf-8")
            if has_bom:
                encoded = b"\xef\xbb\xbf" + encoded
            mutant_path.write_bytes(encoded)

            env = dict(os.environ)
            env[env_var] = str(mutant_path)

            t0 = time.perf_counter()
            proc = subprocess.run(
                list(test_cmd),
                cwd=work_cwd,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            elapsed = round(time.perf_counter() - t0, 3)
            combined_lines = [line for line in (proc.stdout + "\n" + proc.stderr).splitlines() if line.strip()]
            summary = combined_lines[-1] if combined_lines else ""

            is_control = spec.name == "M0" and len(spec.edits) == 0
            rows.append(
                {
                    "mutant": spec.name,
                    "description": spec.description,
                    "exit_code": proc.returncode,
                    "detected": (proc.returncode != 0) if not is_control else None,
                    "clean": (proc.returncode == 0) if is_control else None,
                    "summary": summary,
                    "seconds": elapsed,
                    "diff_bytes": len(body) - len(orig_text),
                }
            )

    control_ok = all(r["clean"] is True for r in rows if r["mutant"] == "M0")
    mutant_rows = [r for r in rows if r["mutant"] != "M0"]
    all_killed = all(r["detected"] is True for r in mutant_rows)
    passed = control_ok and all_killed

    return {
        "schema": "sim_verify-mutation-gate-v1",
        "status": "PASS" if passed else "FAIL",
        "passed": passed,
        "target_file": str(target_path),
        "target_sha256": orig_sha256,
        "test_cmd": list(test_cmd),
        "env_var": env_var,
        "control_clean": control_ok,
        "total_mutants": len(mutant_rows),
        "killed": sum(1 for r in mutant_rows if r["detected"] is True),
        "survived": [r["mutant"] for r in mutant_rows if r["detected"] is False],
        "rows": rows,
    }


def _load_edits(items: Sequence[dict[str, Any]]) -> tuple[MutantEdit, ...]:
    return tuple(
        MutantEdit(
            old=str(item["old"]),
            new=str(item["new"]),
            is_regex=bool(item.get("is_regex", False)),
        )
        for item in items
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run anchor-driven source mutation testing gate.")
    parser.add_argument("--config", type=Path, required=True, help="JSON mutant configuration file")
    parser.add_argument("--target", type=Path, help="Override target_file from config")
    parser.add_argument("--out", type=Path, help="Optional JSON audit report output path")
    parser.add_argument("--only", action="append", help="Restrict run to named mutant(s) plus M0")
    args = parser.parse_args(argv)

    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    base_dir = args.config.resolve().parent
    target = Path(args.target) if args.target else Path(cfg["target_file"])
    if not target.is_absolute():
        target = (base_dir / target).resolve()

    cwd_raw = cfg.get("cwd")
    cwd = (base_dir / cwd_raw).resolve() if cwd_raw and not Path(cwd_raw).is_absolute() else (Path(cwd_raw) if cwd_raw else None)

    mutants = [
        MutantSpec(
            name=str(m["name"]),
            edits=_load_edits(m.get("edits", ())),
            description=str(m.get("description", "")),
        )
        for m in cfg.get("mutants", ())
    ]
    if args.only:
        want = set(args.only) | {"M0"}
        mutants = [m for m in mutants if m.name in want]

    extra = _load_edits(cfg.get("extra_rewrites", ()))
    report = run_mutation_gate(
        target_file=target,
        mutants=mutants,
        test_cmd=list(cfg["test_cmd"]),
        env_var=str(cfg.get("env_var", "TARGET_UNDER_TEST")),
        cwd=cwd,
        timeout=float(cfg.get("timeout", 300.0)),
        extra_rewrites=extra,
    )

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "status": report["status"],
                "control_clean": report["control_clean"],
                "killed": report["killed"],
                "total_mutants": report["total_mutants"],
                "survived": report["survived"],
            }
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
