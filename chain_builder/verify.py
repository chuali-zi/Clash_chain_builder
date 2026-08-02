"""Verify chain by temporarily running mihomo and curling IP check sites."""
from __future__ import annotations

import re

import requests
from rich.console import Console

from .builder import build_chain_config, dump_yaml
from .hop2 import Hop2Creds, swap_user_pass
from .mihomo import MihomoTemp
from .plugins.registry import get_plugin

console = Console()

IP_CHECK_URLS = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
]


def _fetch_ip_via_proxy(proxy_url: str, timeout: float = 20.0) -> str | None:
    proxies = {"http": proxy_url, "https": proxy_url}
    for url in IP_CHECK_URLS:
        try:
            r = requests.get(url, proxies=proxies, timeout=timeout)
            text = r.text.strip()
            # ifconfig.me sometimes returns with newline / extras
            m = re.search(
                r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)",
                text,
            )
            if m:
                return m.group(0)
        except Exception:
            continue
    return None


def _verify_broken_hop2_is_closed(hop1: dict, hop2: Hop2Creds) -> None:
    """Inject an unreachable hop2 and ensure CHAIN never falls back to an IP."""
    broken = Hop2Creds(
        server="127.0.0.1",
        port=1,
        username=hop2.username,
        password=hop2.password,
    )
    cfg = build_chain_config(
        hop1,
        broken,
        plugins=[get_plugin("full")],
        match_default="chain",
    )
    with MihomoTemp(cfg) as m:
        try:
            response = requests.get(
                IP_CHECK_URLS[0],
                proxies={"http": m.proxy_url, "https": m.proxy_url},
                timeout=5,
            )
        except requests.exceptions.RequestException:
            return
        leaked_ip = re.search(
            r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)",
            response.text,
        )
        detail = leaked_ip.group(0) if leaked_ip else f"HTTP {response.status_code}"
        raise RuntimeError(f"第二跳故障时仍可访问公网，检测到旁路 {detail}")


def verify_chain(
    hop1: dict,
    hop2: Hop2Creds,
    *,
    try_swap_userpass: bool = True,
) -> tuple[Hop2Creds, str, dict]:
    """Start temp mihomo with full-chain config, confirm exit IP.

    Returns (effective_creds, exit_ip, config_used_for_verify).
    Tries swapped user/pass once if first attempt fails.
    """
    attempts = [hop2]
    if try_swap_userpass:
        attempts.append(swap_user_pass(hop2))

    last_err: Exception | None = None
    for i, creds in enumerate(attempts):
        label = "原始顺序" if i == 0 else "交换 user/pass 后"
        console.print(f"[cyan]验证链式出口[/]（{label}）…")
        cfg = build_chain_config(
            hop1,
            creds,
            plugins=[get_plugin("full")],
            match_default="chain",
            exit_ip=creds.exit_ip_hint,
        )
        try:
            with MihomoTemp(cfg) as m:
                # Ensure CHAIN/fallback picks hop2
                exit_ip = _fetch_ip_via_proxy(m.proxy_url)
                if not exit_ip:
                    raise RuntimeError("无法通过链式代理获取出口 IP")
                console.print(f"[green]出口 IP:[/] {exit_ip}")
                if creds.exit_ip_hint and creds.exit_ip_hint != exit_ip:
                    console.print(
                        f"[yellow]提示:[/] 凭证中的 IP 提示为 {creds.exit_ip_hint}，"
                        f"实际出口为 {exit_ip}"
                    )
                console.print("[cyan]验证故障闭锁[/]（注入不可达第二跳）…")
                _verify_broken_hop2_is_closed(hop1, creds)
                console.print("[green]故障闭锁通过:[/] 第二跳不可达时无公网出口")
                # Rebuild with confirmed exit ip in hop2 name
                final_cfg = build_chain_config(
                    hop1,
                    creds,
                    plugins=[get_plugin("full")],
                    match_default="chain",
                    exit_ip=exit_ip,
                )
                return creds, exit_ip, final_cfg
        except Exception as e:
            last_err = e
            console.print(f"[yellow]尝试失败:[/] {e}")

    raise RuntimeError(f"链式验证失败: {last_err}")


def validate_config_file(cfg: dict) -> str:
    """Run mihomo -t and return output; raise on failure."""
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    from .core_locator import NO_WINDOW_KW
    from .mihomo import find_mihomo

    binary = find_mihomo()
    if not binary:
        return "skip: no mihomo binary"

    tmp = Path(tempfile.mkdtemp(prefix="chain-test-"))
    try:
        path = tmp / "config.yaml"
        path.write_text(dump_yaml(cfg), encoding="utf-8")
        r = subprocess.run(
            [binary, "-t", "-f", str(path), "-d", str(tmp)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            **NO_WINDOW_KW,
        )
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        if r.returncode != 0 and "successful" not in out.lower():
            raise RuntimeError(out)
        return out.splitlines()[-1] if out else "ok"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
