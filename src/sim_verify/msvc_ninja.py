"""MSVC + Ninja Multi-Config build helper.

Uses the ninja.exe bundled with Visual Studio and loads the x64 MSVC environment
once from vcvars64.bat so a single build directory serves both Debug and Release
configurations with bounded parallelism.
"""
from __future__ import annotations

import functools
import os
from pathlib import Path
import shutil
import subprocess

GENERATOR = "Ninja Multi-Config"
MAX_JOBS = 8


@functools.lru_cache(maxsize=None)
def install() -> Path:
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    path = subprocess.check_output(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        text=True,
    ).strip()
    if not path:
        raise RuntimeError("No installed MSVC C++ toolchain")
    return Path(path)


def cmake() -> str:
    bundled = install() / "Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe"
    return str(bundled) if bundled.is_file() else (shutil.which("cmake") or str(bundled))


def ninja() -> str:
    bundled = install() / "Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe"
    if not bundled.is_file():
        raise RuntimeError("Visual Studio bundled ninja.exe not found: " + str(bundled))
    return str(bundled)


@functools.lru_cache(maxsize=None)
def _env() -> tuple[tuple[str, str], ...]:
    vcvars = install() / "VC/Auxiliary/Build/vcvars64.bat"
    out = subprocess.run(
        f'call "{vcvars}" >nul && set',
        shell=True,
        capture_output=True,
        text=True,
        errors="replace",
        stdin=subprocess.DEVNULL,
    )
    if out.returncode:
        raise RuntimeError("vcvars64.bat failed: " + out.stderr[-500:])
    env_map = dict(line.split("=", 1) for line in out.stdout.splitlines() if "=" in line and not line.startswith("="))
    if not any(k.upper() == "INCLUDE" for k in env_map):
        raise RuntimeError("MSVC environment not set by vcvars64.bat")
    return tuple(sorted(env_map.items()))


def env(extra: dict[str, str] | None = None) -> dict[str, str]:
    e = dict(_env())
    e.pop("PSModulePath", None)
    e.pop("PSMODULEPATH", None)
    if extra:
        e.update(extra)
    return e


def configure_command(source: Path | str, build_dir: Path | str, defines: tuple[str, ...] | list[str] = ()) -> list[str]:
    return [
        cmake(),
        "-S",
        str(source),
        "-B",
        str(build_dir),
        "-G",
        GENERATOR,
        "-DCMAKE_MAKE_PROGRAM=" + ninja(),
        "-DCMAKE_CONFIGURATION_TYPES=Debug;Release",
        *map(str, defines),
    ]


def build_command(build_dir: Path | str, config: str, jobs: int = 4) -> list[str]:
    if not 1 <= int(jobs) <= MAX_JOBS:
        raise ValueError(f"parallelism must be 1..{MAX_JOBS}")
    return [cmake(), "--build", str(build_dir), "--config", config, "--parallel", str(int(jobs))]


def configure(source: Path | str, build_dir: Path | str, defines: tuple[str, ...] | list[str] = (), **kw):
    return subprocess.run(
        configure_command(source, build_dir, defines),
        env=env(),
        capture_output=True,
        text=True,
        errors="replace",
        stdin=subprocess.DEVNULL,
        **kw,
    )


def build(build_dir: Path | str, config: str, jobs: int = 4, **kw):
    return subprocess.run(
        build_command(build_dir, config, jobs),
        env=env(),
        capture_output=True,
        text=True,
        errors="replace",
        stdin=subprocess.DEVNULL,
        **kw,
    )
