"""Rich TUI for picking hop1 with latency display."""
from __future__ import annotations

import concurrent.futures
from typing import Callable

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text

from .mihomo import MihomoTemp

console = Console()


def _filter_proxies(proxies: list[dict], keyword: str | None) -> list[dict]:
    if not keyword:
        return list(proxies)
    keys = [k.strip().lower() for k in keyword.split() if k.strip()]
    out = []
    for p in proxies:
        blob = f"{p.get('name','')} {p.get('type','')} {p.get('server','')}".lower()
        if all(k in blob for k in keys):
            out.append(p)
    return out


def measure_latencies(
    proxies: list[dict],
    *,
    concurrency: int = 20,
    timeout_ms: int = 4000,
    on_progress: Callable[[int, int], None] | None = None,
) -> dict[str, int | None]:
    """Start temp mihomo with all nodes, query delay API in parallel."""
    # Minimal config for delay testing only
    cfg = {
        "mode": "global",
        "log-level": "error",
        "ipv6": True,
        "unified-delay": True,
        "dns": {
            "enable": True,
            "enhanced-mode": "fake-ip",
            "nameserver": ["https://223.5.5.5/dns-query"],
            "default-nameserver": ["223.5.5.5", "8.8.8.8"],
        },
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "GLOBAL",
                "type": "select",
                "proxies": [p["name"] for p in proxies] + ["DIRECT"],
            }
        ],
        "rules": ["MATCH,GLOBAL"],
    }

    results: dict[str, int | None] = {p["name"]: None for p in proxies}
    with MihomoTemp(cfg) as m:
        names = [p["name"] for p in proxies]
        done = 0
        total = len(names)

        def one(name: str) -> tuple[str, int | None]:
            return name, m.proxy_delay(name, timeout_ms=timeout_ms)

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
            futs = [ex.submit(one, n) for n in names]
            for fut in concurrent.futures.as_completed(futs):
                name, delay = fut.result()
                results[name] = delay
                done += 1
                if on_progress:
                    on_progress(done, total)
    return results


def pick_hop1(
    proxies: list[dict],
    *,
    filter_keyword: str | None = None,
    skip_latency: bool = False,
    preselect: str | None = None,
) -> dict:
    """Interactive hop1 picker. Returns the chosen proxy dict."""
    if preselect:
        for p in proxies:
            if p.get("name") == preselect:
                console.print(f"[green]已选择 hop1:[/] {preselect}")
                return p
        raise SystemExit(f"找不到节点: {preselect}")

    filtered = _filter_proxies(proxies, filter_keyword)
    if not filtered:
        raise SystemExit(f"过滤后无节点（keyword={filter_keyword!r}）")

    latencies: dict[str, int | None] = {}
    if not skip_latency:
        console.print(Panel.fit(
            f"正在用临时 mihomo 测试 [cyan]{len(filtered)}[/] 个节点延迟…",
            title="Latency",
        ))
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("测速", total=len(filtered))

            def on_prog(done: int, total: int) -> None:
                progress.update(task, completed=done, total=total)

            try:
                latencies = measure_latencies(filtered, on_progress=on_prog)
            except Exception as e:
                console.print(f"[yellow]测速失败，改为仅列出节点:[/] {e}")
                latencies = {}

    # Sort: lowest delay first, timeout last
    def sort_key(p: dict):
        d = latencies.get(p["name"])
        return (d is None, d if d is not None else 10**9)

    ordered = sorted(filtered, key=sort_key)

    table = Table(title="选择第一跳 (hop1)", show_lines=False)
    table.add_column("#", style="bold cyan", justify="right", width=4)
    table.add_column("延迟", justify="right", width=8)
    table.add_column("类型", width=10)
    table.add_column("名称")
    table.add_column("服务器")

    for i, p in enumerate(ordered):
        d = latencies.get(p["name"]) if latencies else None
        if latencies:
            if d is None:
                delay_txt = Text("timeout", style="red")
            elif d < 150:
                delay_txt = Text(f"{d}ms", style="green")
            elif d < 400:
                delay_txt = Text(f"{d}ms", style="yellow")
            else:
                delay_txt = Text(f"{d}ms", style="red")
        else:
            delay_txt = Text("-", style="dim")
        table.add_row(
            str(i),
            delay_txt,
            str(p.get("type", "?")),
            str(p.get("name", "")),
            f"{p.get('server')}:{p.get('port')}",
        )

    console.print(table)
    console.print(
        "[dim]输入序号选择；或输入节点名关键字再过滤；"
        "空回车选延迟最低可用节点[/]"
    )

    while True:
        raw = console.input("[bold]hop1> [/]").strip()
        if raw == "" and ordered:
            # first with valid latency, else first
            for p in ordered:
                if latencies.get(p["name"]) is not None:
                    console.print(f"[green]自动选择:[/] {p['name']}")
                    return p
            console.print(f"[green]自动选择:[/] {ordered[0]['name']}")
            return ordered[0]
        if raw.isdigit():
            idx = int(raw)
            if 0 <= idx < len(ordered):
                console.print(f"[green]已选择:[/] {ordered[idx]['name']}")
                return ordered[idx]
            console.print("[red]序号越界[/]")
            continue
        # treat as filter refine
        refined = _filter_proxies(ordered, raw)
        if len(refined) == 1:
            console.print(f"[green]已选择:[/] {refined[0]['name']}")
            return refined[0]
        if not refined:
            console.print("[red]无匹配[/]")
            continue
        # show refined subset
        ordered = refined
        table = Table(title=f"过滤: {raw}")
        table.add_column("#", justify="right")
        table.add_column("延迟", justify="right")
        table.add_column("名称")
        for i, p in enumerate(ordered):
            d = latencies.get(p["name"])
            delay = f"{d}ms" if d is not None else "timeout"
            table.add_row(str(i), delay, p["name"])
        console.print(table)
