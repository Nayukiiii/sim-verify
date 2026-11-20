"""Run an offline command on Windows' highest EfficiencyClass cores only.

CPU Set structure: https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-system_cpu_set_information
Children inherit affinity: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-setprocessaffinitymask
This launcher changes only itself and children it starts; no persistent OS setting.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import subprocess


def select() -> dict:
    if os.name != "nt":
        raise RuntimeError("Windows required")
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.GetCurrentProcess.restype = w.HANDLE
    k.GetSystemCpuSetInformation.argtypes = [ctypes.c_void_p, w.ULONG, ctypes.POINTER(w.ULONG), w.HANDLE, w.ULONG]
    k.GetSystemCpuSetInformation.restype = w.BOOL
    k.GetProcessAffinityMask.argtypes = [w.HANDLE, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
    k.GetProcessAffinityMask.restype = w.BOOL
    k.SetProcessAffinityMask.argtypes = [w.HANDLE, ctypes.c_size_t]
    k.SetProcessAffinityMask.restype = w.BOOL
    n = w.ULONG()
    k.GetSystemCpuSetInformation(None, 0, ctypes.byref(n), None, 0)
    if not n.value:
        raise ctypes.WinError(ctypes.get_last_error())
    b = ctypes.create_string_buffer(n.value)
    if not k.GetSystemCpuSetInformation(b, n, ctypes.byref(n), None, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    data = b.raw
    offset = 0
    rows = []
    while offset < n.value:
        size = int.from_bytes(data[offset : offset + 4], "little")
        kind = int.from_bytes(data[offset + 4 : offset + 8], "little")
        if size < 8 or offset + size > n.value:
            raise RuntimeError("CPU Set record extent differs")
        if kind == 0:
            if size < 32:
                raise RuntimeError("CPU Set record too short")
            q = data[offset : offset + size]
            rows.append(
                dict(
                    group=int.from_bytes(q[12:14], "little"),
                    logical=q[14],
                    core=q[15],
                    efficiency=q[18],
                    flags=q[19],
                )
            )
        offset += size
    if not rows or {r["group"] for r in rows} != {0}:
        raise RuntimeError("This launcher requires one processor group")
    level = max(r["efficiency"] for r in rows)
    chosen = [r for r in rows if r["efficiency"] == level]
    if any(r["flags"] & 2 and not r["flags"] & 4 for r in chosen):
        raise RuntimeError("Performance CPU Set reserved by another process")
    mask = sum(1 << r["logical"] for r in chosen)
    handle = k.GetCurrentProcess()
    before, system = ctypes.c_size_t(), ctypes.c_size_t()
    if not k.GetProcessAffinityMask(handle, ctypes.byref(before), ctypes.byref(system)):
        raise ctypes.WinError(ctypes.get_last_error())
    if mask & system.value != mask:
        raise RuntimeError("Performance cores outside system affinity")
    if not k.SetProcessAffinityMask(handle, mask):
        raise ctypes.WinError(ctypes.get_last_error())
    after = ctypes.c_size_t()
    if not k.GetProcessAffinityMask(handle, ctypes.byref(after), ctypes.byref(system)):
        raise ctypes.WinError(ctypes.get_last_error())
    if after.value != mask:
        raise RuntimeError("Affinity readback differs")
    return dict(
        pid=os.getpid(),
        affinity_before=hex(before.value),
        affinity_after=hex(after.value),
        efficiency_class=level,
        physical_cores=len({r["core"] for r in chosen}),
        logical_processors=[r["logical"] for r in chosen],
        excluded_logical_processors=[r["logical"] for r in rows if r not in chosen],
        topology=rows,
    )


select_highest_efficiency_cpu_sets = select


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--record", type=Path)
    p.add_argument("command", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    command = a.command[1:] if a.command[:1] == ["--"] else a.command
    if not command:
        p.error("command required after --")
    if a.record and a.record.exists():
        p.error("record exists; choose a fresh path")
    value = select()
    value["command"] = command
    print(json.dumps(value, ensure_ascii=False), flush=True)
    result = subprocess.run(command)
    value["exit_code"] = result.returncode
    if a.record:
        a.record.parent.mkdir(parents=True, exist_ok=True)
        a.record.write_bytes((json.dumps(value, ensure_ascii=False, indent=2) + "\n").replace("\n", "\r\n").encode("utf-8"))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
