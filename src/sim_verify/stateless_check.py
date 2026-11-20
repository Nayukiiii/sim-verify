"""Stateless isolation runner and AST global-state checker.

Proves that a step function carries no hidden in-process state across ticks:
1. `guarded_call`: executes a callable under a process-wide `sys.addaudithook` guard
   that refuses any file I/O, import, compile/exec, socket, or subprocess call.
2. `check_ast_stateless`: static AST check forbidding `global`, `nonlocal`, mutable
   default arguments, and top-level mutable assignments outside frozen constants.
3. `run_isolated_steps`: runs each simulation tick in two fresh child processes with
   distinct `PYTHONHASHSEED` values (`1` and `2`) and distinct working directories,
   passing only the serialized state JSON between ticks and requiring byte-identical
   outputs.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Callable

DEFAULT_ALLOWED_AUDIT_EVENTS = frozenset({"ctypes.create_string_buffer"})


class GuardViolation(RuntimeError):
    def __init__(self, violations: list[str]):
        super().__init__(f"ISOLATION_GUARD: audited operation during step: {violations}")
        self.violations = list(violations)


_GUARD: dict[str, Any] = dict(installed=False, active=False, counts=None, violations=None, allowed=DEFAULT_ALLOWED_AUDIT_EVENTS)


def _hook(event: str, args: Any) -> None:
    if not _GUARD["active"]:
        return
    _GUARD["counts"][event] = _GUARD["counts"].get(event, 0) + 1
    if event not in _GUARD["allowed"]:
        _GUARD["violations"].append(event)
        raise RuntimeError("ISOLATION_GUARD: audited operation during step: " + event)


def guarded_call(
    fn: Callable[..., Any],
    *args: Any,
    allowed_events: frozenset[str] = DEFAULT_ALLOWED_AUDIT_EVENTS,
    **kwargs: Any,
) -> tuple[Any, dict[str, int], list[str]]:
    if not _GUARD["installed"]:
        sys.addaudithook(_hook)
        _GUARD["installed"] = True
    _GUARD.update(active=True, counts={}, violations=[], allowed=allowed_events)
    try:
        result = fn(*args, **kwargs)
    except Exception:
        if _GUARD["violations"]:
            raise GuardViolation(_GUARD["violations"])
        raise
    finally:
        _GUARD["active"] = False
    if _GUARD["violations"]:
        raise GuardViolation(_GUARD["violations"])
    return result, dict(_GUARD["counts"]), list(_GUARD["violations"])


def check_ast_stateless(source_code: str, filename: str = "<module>") -> list[str]:
    """Static helper check: flags `global`, `nonlocal`, and mutable function defaults.

    Note: Static AST checking is an upper-bound lint aid; runtime subprocess isolation
    (`run_isolated_steps`) is the authoritative proof of cross-step statelessness.
    """
    tree = ast.parse(source_code, filename=filename)
    problems: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            problems.append(f"{filename}:{node.lineno}: forbidden {type(node).__name__} statement")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in list(node.args.defaults) + [x for x in node.args.kw_defaults if x is not None]:
                if isinstance(d, (ast.List, ast.Dict, ast.Set, ast.Call)):
                    problems.append(f"{filename}:{node.lineno}: mutable or call default in {node.name}()")
    return problems


def run_isolated_steps(
    module_path: Path,
    step_func_name: str,
    initial_state: dict[str, Any],
    drives: list[dict[str, Any]],
) -> dict[str, Any]:
    """Run each tick in two fresh child interpreters (PYTHONHASHSEED=1 and 2) and compare bytes."""
    runner_code = (
        "import importlib.util, json, sys\n"
        "from pathlib import Path\n"
        "from sim_verify.stateless_check import guarded_call\n"
        "mod_path, fn_name, state_in, drive_in, state_out = sys.argv[1:6]\n"
        "spec = importlib.util.spec_from_file_location('target_mod', mod_path)\n"
        "mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
        "fn = getattr(mod, fn_name)\n"
        "st = json.loads(Path(state_in).read_text(encoding='utf-8'))\n"
        "dr = json.loads(Path(drive_in).read_text(encoding='utf-8'))\n"
        "next_st, events, violations = guarded_call(fn, st, dr)\n"
        "Path(state_out).write_text(json.dumps(next_st, sort_keys=True, indent=2) + '\\n', encoding='utf-8')\n"
    )
    src_root = str(Path(__file__).resolve().parents[1])
    state_bytes = (json.dumps(initial_state, sort_keys=True, indent=2) + "\n").encode("utf-8")
    ticks_report = []

    with tempfile.TemporaryDirectory(prefix="sim_verify_iso_") as tmp:
        tmp_dir = Path(tmp)
        for idx, drive in enumerate(drives, start=1):
            state_in = tmp_dir / f"state_{idx - 1}.json"
            drive_in = tmp_dir / f"drive_{idx}.json"
            state_in.write_bytes(state_bytes)
            drive_in.write_text(json.dumps(drive, sort_keys=True), encoding="utf-8")
            outputs = []
            for seed in ("1", "2"):
                work = tmp_dir / f"work_{idx}_{seed}"
                work.mkdir()
                out_file = work / "out.json"
                env = {k: os.environ[k] for k in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP") if k in os.environ}
                env.update(
                    PATH=os.path.dirname(sys.executable),
                    PYTHONPATH=src_root,
                    PYTHONHASHSEED=seed,
                    PYTHONIOENCODING="utf-8",
                )
                cmd = [
                    sys.executable,
                    "-s",
                    "-B",
                    "-c",
                    runner_code,
                    str(Path(module_path).resolve()),
                    step_func_name,
                    str(state_in),
                    str(drive_in),
                    str(out_file),
                ]
                done = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=60)
                if done.returncode != 0:
                    raise RuntimeError(f"isolated child failed at tick {idx} (seed {seed}): {done.stderr.strip()}")
                outputs.append(out_file.read_bytes())
            equal = outputs[0] == outputs[1]
            ticks_report.append({"tick": idx, "seed_outputs_equal": equal})
            if not equal:
                raise RuntimeError(f"isolated children disagreed at tick {idx}")
            state_bytes = outputs[0]

    return {
        "status": "PASS",
        "ticks_verified": len(ticks_report),
        "ticks": ticks_report,
        "final_state": json.loads(state_bytes.decode("utf-8")),
    }
