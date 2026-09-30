"""Locate an original CFW Clash Premium core, without treating mihomo as compatible."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

from .core_locator import NO_WINDOW_KW


def find_cfw_core(explicit: str | None = None) -> str | None:
    requested = explicit or os.environ.get("CFW_BIN")
    if requested:
        path = shutil.which(requested) or requested
        if not _is_premium(path):
            raise ValueError(f"CFW 内核无效或不是原版 Clash Premium: {path}")
        return str(Path(path).resolve())
    roots = [Path.cwd(), Path.cwd() / "bin", Path.cwd() / "core"]
    for env in ("ProgramFiles", "LOCALAPPDATA"):
        if os.environ.get(env):
            root = Path(os.environ[env])
            roots.extend([root / "Clash for Windows", root / "Programs" / "Clash for Windows"])
    for root in roots:
        for rel in ("clash-win64.exe", "clash-win32.exe", "clash.exe", "clash",
                    "resources/static/files/win/x64/clash-win64.exe",
                    "resources/static/files/win/ia32/clash-win32.exe"):
            path = root / rel
            if path.is_file() and _is_premium(str(path)):
                return str(path.resolve())
    for command in ("clash-win64", "clash-win32", "clash"):
        path = shutil.which(command)
        if path and _is_premium(path):
            return path
    return None


def _is_premium(path: str) -> bool:
    try:
        result = subprocess.run([path, "-v"], capture_output=True, text=True, timeout=5,
                                encoding="utf-8", errors="replace", **NO_WINDOW_KW)
    except (OSError, subprocess.TimeoutExpired):
        return False
    version = (result.stdout + result.stderr).lower()
    # Original Premium uses a date version; OSS Clash uses v1.x, Meta includes Meta/Mihomo.
    return result.returncode == 0 and version.startswith("clash 20") and "meta" not in version and "mihomo" not in version


def copy_country_mmdb(binary: str, destination: Path) -> None:
    """Reuse the database shipped with CFW for temporary validation (no downloads)."""
    parent = Path(binary).resolve().parent
    candidates = [parent / "Country.mmdb", Path.home() / ".config" / "clash" / "Country.mmdb"]
    candidates.extend(p / "resources/static/files/default/Country.mmdb" for p in list(parent.parents)[:5])
    for path in candidates:
        if path.is_file():
            shutil.copyfile(path, destination / "Country.mmdb")
            return
