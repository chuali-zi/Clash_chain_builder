"""Locate a mihomo / Clash.Meta core binary on the current machine.

Sources are probed cheap-first: environment variables, files shipped next to
the project, PATH, the Windows registry, currently running Clash processes,
well-known install directories and finally a bounded scan of local drives.
Each candidate is confirmed by running ``-v`` so that a GUI wrapper or a
non-Meta clash build never gets picked up.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

IS_WIN = sys.platform == "win32"

#: Environment variables holding a full path (or a bare command name).
ENV_BIN_VARS = ("MIHOMO_BIN", "CLASH_META_BIN", "CLASH_CORE_BIN", "CLASH_BIN")
#: Environment variables holding a directory that may contain the core.
ENV_DIR_VARS = ("MIHOMO_HOME", "CLASH_HOME", "CLASH_DIR", "CLASH_VERGE_DIR")

#: Names looked up on PATH.
PATH_NAMES = (
    "mihomo",
    "mihomo-alpha",
    "verge-mihomo",
    "verge-mihomo-alpha",
    "clash-meta",
    "Clash.Meta",
    "clashmeta",
    "clash",
)

#: File stems accepted as a Meta core, e.g. ``mihomo-windows-amd64-v1.19.1``.
CORE_STEM_RE = re.compile(
    r"^(?:verge-)?(?:mihomo|clash[-._]?meta)(?:[-._][\w.+-]*)?$|^clash$",
    re.IGNORECASE,
)
#: Directory / process names worth looking inside.
HINT_RE = re.compile(r"clash|mihomo|verge|nyanpasu", re.IGNORECASE)

#: Generic parent folders people drop portable apps into.
PORTABLE_PARENTS = {
    "program files",
    "program files (x86)",
    "programs",
    "programfiles",
    "apps",
    "app",
    "software",
    "soft",
    "tools",
    "tool",
    "green",
    "portable",
    "downloads",
    "软件",
    "工具",
    "绿色软件",
}

_SKIP_DIRS = {".git", "node_modules", "__pycache__", "cache", "logs", "profiles"}
_MAX_ENTRIES_PER_DIR = 4000

#: Keep Windows from flashing a console window for every probe.
NO_WINDOW_KW: dict = (
    {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)} if IS_WIN else {}
)


@dataclass(frozen=True)
class CoreCandidate:
    path: str
    source: str


def _is_executable(p: Path) -> bool:
    try:
        if not p.is_file():
            return False
    except OSError:
        return False
    if IS_WIN:
        return p.suffix.lower() in (".exe", ".com")
    return os.access(p, os.X_OK)


def _looks_like_core(p: Path) -> bool:
    return bool(CORE_STEM_RE.match(p.stem)) and _is_executable(p)


def _rank(p: Path) -> tuple:
    """Prefer plain stable cores over alpha / debug builds."""
    stem = p.stem.lower()
    return (
        0 if stem in ("mihomo", "verge-mihomo", "clash-meta", "clash.meta") else 1,
        1 if "alpha" in stem or "debug" in stem or "beta" in stem else 0,
        len(stem),
        stem,
    )


def _scan_dir(root: Path, depth: int = 2) -> list[Path]:
    """Depth-limited search for core executables under ``root``."""
    found: list[Path] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        current, level = stack.pop()
        try:
            entries = list(os.scandir(current))[:_MAX_ENTRIES_PER_DIR]
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_file():
                    p = Path(entry.path)
                    if _looks_like_core(p):
                        found.append(p)
                elif level < depth and entry.is_dir(follow_symlinks=False):
                    if entry.name.lower() in _SKIP_DIRS:
                        continue
                    stack.append((Path(entry.path), level + 1))
            except OSError:
                continue
    return sorted(found, key=_rank)


def _env_candidates() -> Iterator[CoreCandidate]:
    import shutil

    for var in ENV_BIN_VARS:
        raw = (os.environ.get(var) or "").strip().strip('"')
        if not raw:
            continue
        p = Path(raw)
        if p.is_file():
            yield CoreCandidate(str(p), f"环境变量 {var}")
        elif p.is_dir():
            for hit in _scan_dir(p, depth=1):
                yield CoreCandidate(str(hit), f"环境变量 {var}")
        else:
            which = shutil.which(raw)
            if which:
                yield CoreCandidate(which, f"环境变量 {var} (PATH)")

    for var in ENV_DIR_VARS:
        raw = (os.environ.get(var) or "").strip().strip('"')
        if raw and Path(raw).is_dir():
            for hit in _scan_dir(Path(raw), depth=2):
                yield CoreCandidate(str(hit), f"环境变量 {var}")


def _local_candidates() -> Iterator[CoreCandidate]:
    """Cores shipped next to the project or the current working directory."""
    pkg_root = Path(__file__).resolve().parents[1]
    roots = [Path.cwd(), pkg_root, pkg_root / "bin", pkg_root / "core", pkg_root / "vendor"]
    seen: set[str] = set()
    for root in roots:
        key = str(root).lower()
        if key in seen or not root.is_dir():
            continue
        seen.add(key)
        for hit in _scan_dir(root, depth=1):
            yield CoreCandidate(str(hit), f"项目目录 {root}")


def _path_candidates() -> Iterator[CoreCandidate]:
    import shutil

    for name in PATH_NAMES:
        hit = shutil.which(name)
        if hit:
            yield CoreCandidate(hit, "PATH")


def _registry_dirs() -> Iterator[tuple[Path, str]]:
    """Install directories advertised by Clash installers in the registry."""
    if not IS_WIN:
        return
    import winreg

    uninstall = (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    )
    for hive, sub in uninstall:
        try:
            key = winreg.OpenKey(hive, sub)
        except OSError:
            continue
        with key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, name) as item:
                        display = _reg_value(item, "DisplayName")
                        location = _reg_value(item, "InstallLocation")
                        icon = _reg_value(item, "DisplayIcon")
                except OSError:
                    continue
                if not HINT_RE.search(f"{name} {display} {location} {icon}"):
                    continue
                for raw in (location, os.path.dirname(icon.strip('"')) if icon else ""):
                    if raw and Path(raw).is_dir():
                        yield Path(raw), f"注册表 {display or name}"

    app_paths = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            key = winreg.OpenKey(hive, app_paths)
        except OSError:
            continue
        with key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    name = winreg.EnumKey(key, i)
                    if not HINT_RE.search(name):
                        continue
                    with winreg.OpenKey(key, name) as item:
                        exe = _reg_value(item, "").strip('"')
                except OSError:
                    continue
                if exe and Path(exe).parent.is_dir():
                    yield Path(exe).parent, "注册表 App Paths"


def _reg_value(key, name: str) -> str:
    import winreg

    try:
        value, _ = winreg.QueryValueEx(key, name)
        return str(value)
    except OSError:
        return ""


def _running_clash_dirs() -> Iterator[tuple[Path, str]]:
    """Directories of Clash processes running right now (GUI included)."""
    for exe in _running_executables():
        p = Path(exe)
        if not HINT_RE.search(p.name):
            continue
        parent = p.parent
        if parent.is_dir():
            yield parent, f"运行中的进程 {p.name}"


def _running_executables() -> list[str]:
    try:
        import psutil  # type: ignore

        out = []
        for proc in psutil.process_iter(["exe"]):
            exe = proc.info.get("exe")
            if exe:
                out.append(exe)
        return out
    except Exception:
        pass

    if IS_WIN:
        script = (
            "Get-CimInstance Win32_Process | "
            "Where-Object { $_.ExecutablePath } | "
            "ForEach-Object { $_.ExecutablePath }"
        )
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
    else:
        cmd = ["ps", "-eo", "args="]
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=15, **NO_WINDOW_KW,
        )
    except Exception:
        return []
    lines = (r.stdout or "").splitlines()
    if IS_WIN:
        return [ln.strip() for ln in lines if ln.strip()]
    return [ln.strip().split(" ")[0] for ln in lines if ln.strip().startswith("/")]


def _install_dirs() -> Iterator[tuple[Path, str]]:
    """Well-known install locations per platform."""
    home = Path.home()
    if IS_WIN:
        roots = [
            os.environ.get("ProgramFiles"),
            os.environ.get("ProgramFiles(x86)"),
            os.environ.get("ProgramW6432"),
            os.environ.get("ProgramData"),
            os.environ.get("LOCALAPPDATA"),
            os.environ.get("APPDATA"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs"),
        ]
        direct = [
            home / "scoop" / "shims",
            home / "scoop" / "apps",
            Path(os.environ.get("ProgramData", "C:/ProgramData")) / "chocolatey" / "bin",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Packages",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WindowsApps",
        ]
    elif sys.platform == "darwin":
        roots = ["/Applications", str(home / "Applications"), "/opt"]
        direct = [
            Path("/usr/local/bin"),
            Path("/opt/homebrew/bin"),
            home / ".local" / "bin",
            home / ".config" / "clash",
            home / ".config" / "mihomo",
        ]
    else:
        roots = ["/opt", "/usr/share", str(home / ".local" / "share")]
        direct = [
            Path("/usr/bin"),
            Path("/usr/local/bin"),
            Path("/snap/bin"),
            home / ".local" / "bin",
            home / ".config" / "clash",
            home / ".config" / "mihomo",
        ]

    for d in direct:
        if d and Path(d).is_dir():
            yield Path(d), "常见安装目录"

    for root in roots:
        if not root:
            continue
        base = Path(root)
        if not base.is_dir():
            continue
        try:
            entries = list(os.scandir(base))[:_MAX_ENTRIES_PER_DIR]
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False) and HINT_RE.search(entry.name):
                    yield Path(entry.path), f"常见安装目录 {base}"
            except OSError:
                continue


def _fixed_drives() -> list[Path]:
    if not IS_WIN:
        return []
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        mask = kernel32.GetLogicalDrives()
        drives = []
        for i in range(26):
            if not (mask >> i) & 1:
                continue
            root = f"{chr(ord('A') + i)}:\\"
            # 2/3/6 = removable / fixed / ramdisk; network drives are skipped
            # because probing a dead share can block for seconds.
            if kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) in (2, 3, 6):
                drives.append(Path(root))
        return drives
    except Exception:
        return [Path("C:\\")]


def _drive_scan_dirs() -> Iterator[tuple[Path, str]]:
    """Portable installs such as ``E:\\Clash Verge`` or ``D:\\Apps\\mihomo``."""
    for drive in _fixed_drives():
        try:
            entries = list(os.scandir(drive))[:_MAX_ENTRIES_PER_DIR]
        except OSError:
            continue
        for entry in entries:
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            name = entry.name
            if HINT_RE.search(name):
                yield Path(entry.path), f"磁盘扫描 {drive}"
            elif name.lower() in PORTABLE_PARENTS:
                try:
                    subs = list(os.scandir(entry.path))[:_MAX_ENTRIES_PER_DIR]
                except OSError:
                    continue
                for sub in subs:
                    try:
                        if sub.is_dir(follow_symlinks=False) and HINT_RE.search(sub.name):
                            yield Path(sub.path), f"磁盘扫描 {entry.path}"
                    except OSError:
                        continue


def _dir_sources() -> Iterator[tuple[Path, str]]:
    yield from _registry_dirs()
    yield from _running_clash_dirs()
    yield from _install_dirs()
    yield from _drive_scan_dirs()


def iter_candidates(deadline: float | None = None) -> Iterator[CoreCandidate]:
    """Yield unique core candidates, cheapest sources first."""
    seen: set[str] = set()

    def _fresh(c: CoreCandidate) -> bool:
        key = os.path.normcase(os.path.abspath(c.path))
        if key in seen:
            return False
        seen.add(key)
        return True

    def _expired() -> bool:
        return deadline is not None and time.monotonic() > deadline

    for cand in _env_candidates():
        if _fresh(cand):
            yield cand
    for source in (_local_candidates, _path_candidates):
        for cand in source():
            if _expired():
                return
            if _fresh(cand):
                yield cand

    scanned: set[str] = set()
    for directory, label in _dir_sources():
        if _expired():
            return
        key = os.path.normcase(str(directory))
        if key in scanned:
            continue
        scanned.add(key)
        for hit in _scan_dir(directory, depth=3):
            cand = CoreCandidate(str(hit), label)
            if _fresh(cand):
                yield cand


def probe_version(path: str, timeout: float = 8.0) -> str | None:
    """Return the version banner if ``path`` is a Meta-compatible core."""
    try:
        r = subprocess.run(
            [str(path), "-v"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, **NO_WINDOW_KW,
        )
    except Exception:
        return None
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    low = out.lower()
    if "mihomo" in low or "meta" in low:
        return out.splitlines()[0].strip()
    return None


_cache: tuple[str | None, str] | None = None


def find_mihomo(refresh: bool = False, budget: float = 30.0) -> str | None:
    """Return the path of a usable mihomo core, or ``None``."""
    global _cache
    if _cache is not None and not refresh:
        return _cache[0]
    path, source, _ = locate_core(budget=budget)
    _cache = (path, source)
    return path


def locate_core(budget: float = 30.0) -> tuple[str | None, str, str]:
    """Return ``(path, source, version)``; empty strings when nothing works."""
    deadline = time.monotonic() + budget
    fallback: CoreCandidate | None = None
    for cand in iter_candidates(deadline=deadline):
        version = probe_version(cand.path)
        if version:
            return cand.path, cand.source, version
        if fallback is None and Path(cand.path).stem.lower() != "clash":
            fallback = cand
    if fallback is not None:
        return fallback.path, fallback.source + "（未通过 -v 校验）", ""
    return None, "", ""


def searched_locations() -> list[str]:
    """Human readable summary of where we look, for error messages."""
    items = [
        "环境变量 " + " / ".join(ENV_BIN_VARS),
        "项目目录 与 当前工作目录（含 bin/ core/ vendor/）",
        "PATH",
    ]
    if IS_WIN:
        items += [
            "注册表卸载项 / App Paths（Clash Verge、Nyanpasu 等）",
            "正在运行的 Clash 进程所在目录",
            "Program Files、LocalAppData\\Programs、scoop、chocolatey、winget",
            "各固定磁盘根目录下的 *clash* / *mihomo* / *verge* 目录",
        ]
    else:
        items += [
            "正在运行的 Clash 进程所在目录",
            "/usr/bin、/usr/local/bin、/opt、~/.local/bin、Applications",
        ]
    return items
