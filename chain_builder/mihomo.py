"""Locate and run a temporary mihomo/clash-meta process."""
from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path

import requests
import yaml

from .core_locator import (
    NO_WINDOW_KW,
    find_mihomo,
    locate_core,
    probe_version,
    searched_locations,
)

__all__ = [
    "find_mihomo",
    "locate_core",
    "probe_version",
    "searched_locations",
    "free_port",
    "MihomoTemp",
]


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class MihomoTemp:
    """Context manager: write config, start mihomo, expose API + mixed port."""

    def __init__(self, config: dict, binary: str | None = None, ready_timeout: float = 20.0):
        self.binary = binary or find_mihomo()
        if not self.binary:
            where = "\n".join(f"  - {x}" for x in searched_locations())
            raise RuntimeError(
                "未找到 mihomo 内核。已尝试以下位置：\n"
                f"{where}\n"
                "请安装 Clash Verge / mihomo，或设置环境变量 MIHOMO_BIN 指向内核可执行文件"
            )
        self.ready_timeout = ready_timeout
        self.mixed_port = free_port()
        self.api_port = free_port()
        self.config = dict(config)
        self.config["mixed-port"] = self.mixed_port
        self.config["external-controller"] = f"127.0.0.1:{self.api_port}"
        self.config.setdefault("secret", "")
        self.config["allow-lan"] = False
        self._proc: subprocess.Popen | None = None
        self._cfg_path: Path | None = None
        self._tmpdir: Path | None = None

    @property
    def api(self) -> str:
        return f"http://127.0.0.1:{self.api_port}"

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.mixed_port}"

    @property
    def socks_url(self) -> str:
        return f"socks5h://127.0.0.1:{self.mixed_port}"

    def __enter__(self) -> "MihomoTemp":
        import tempfile

        self._tmpdir = Path(tempfile.mkdtemp(prefix="chain-mihomo-"))
        self._cfg_path = self._tmpdir / "config.yaml"
        self._cfg_path.write_text(
            yaml.safe_dump(self.config, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        # Validate first
        test = subprocess.run(
            [self.binary, "-t", "-f", str(self._cfg_path), "-d", str(self._tmpdir)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            **NO_WINDOW_KW,
        )
        out = (test.stdout or "") + (test.stderr or "")
        if test.returncode != 0 and "successful" not in out.lower():
            raise RuntimeError(f"mihomo 配置校验失败:\n{out}")

        self._proc = subprocess.Popen(
            [self.binary, "-f", str(self._cfg_path), "-d", str(self._tmpdir)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **NO_WINDOW_KW,
        )
        deadline = time.time() + self.ready_timeout
        last_err = None
        while time.time() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError("mihomo 启动后立即退出")
            try:
                r = requests.get(f"{self.api}/version", timeout=1)
                if r.ok:
                    return self
            except Exception as e:
                last_err = e
            time.sleep(0.2)
        self.close()
        raise RuntimeError(f"mihomo API 未就绪: {last_err}")

    def close(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        if self._tmpdir and self._tmpdir.exists():
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None

    def __exit__(self, *exc) -> None:
        self.close()

    def proxy_delay(self, name: str, timeout_ms: int = 5000,
                    url: str = "http://www.gstatic.com/generate_204") -> int | None:
        from urllib.parse import quote

        try:
            r = requests.get(
                f"{self.api}/proxies/{quote(name, safe='')}/delay",
                params={"url": url, "timeout": timeout_ms},
                timeout=(timeout_ms / 1000) + 2,
            )
            if r.status_code == 200:
                return int(r.json().get("delay") or 0) or None
        except Exception:
            return None
        return None

    def select_proxy(self, group: str, name: str) -> None:
        from urllib.parse import quote

        requests.put(
            f"{self.api}/proxies/{quote(group, safe='')}",
            json={"name": name},
            timeout=5,
        ).raise_for_status()
