"""CLI entry — simple wizard by default, advanced flags available."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .builder import (
    PRESET_ALIASES,
    build_chain_config,
    dump_yaml,
    is_simple_full_chain,
    resolve_rules_source,
)
from .fetch import fetch_and_parse
from .geo import lookup_country, output_filename, sanitize_output_name
from .hop2 import parse_hop2
from .plugins.registry import list_plugins
from .ruleset import load_all_packs, load_all_presets
from .tui import filter_proxies, measure_latencies, pick_hop1
from .verify import validate_config_file, verify_chain

console = Console()
DEFAULT_OUT_DIR = Path(__file__).resolve().parent.parent / "output"


def resolve_output_path(args: argparse.Namespace, exit_ip: str, country: str) -> Path:
    """--out (full path) > --name (basename) > IP_region[_full-chain].yaml."""
    out_dir = Path(args.out_dir) if getattr(args, "out_dir", None) else DEFAULT_OUT_DIR
    if getattr(args, "out", None):
        return Path(args.out)
    if getattr(args, "name", None):
        return out_dir / sanitize_output_name(args.name)
    preset = getattr(args, "preset", None)
    suffix = preset if preset in {"full-chain", "full-chain-auto"} else None
    return out_dir / output_filename(exit_ip, country, suffix=suffix)


def apply_mode_flags(args: argparse.Namespace) -> argparse.Namespace:
    """Resolve which YAML mode to emit. --full-chain wins over --preset."""
    if getattr(args, "full_chain", False):
        args.preset = "full-chain"
    elif not getattr(args, "preset", None) and not getattr(args, "packs", None):
        args.preset = "default"
    return args


def _prompt(msg: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    val = console.input(f"[bold]{msg}{suffix}: [/]").strip()
    if not val and default is not None:
        return default
    return val


def _load_custom_rules(path: str | None) -> list[str] | None:
    if not path:
        return None
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def _resolve_build_rules(args: argparse.Namespace):
    """Return (ruleset, plugins, label, match_default, strict)."""
    extra = _load_custom_rules(getattr(args, "rules_file", None))
    ruleset, plugins, label = resolve_rules_source(
        getattr(args, "preset", None),
        packs=getattr(args, "packs", None),
        match=getattr(args, "match_default", None),
        extra_rules=extra,
    )

    # Custom rules already folded into ruleset when ruleset path is used.
    custom_for_builder = None if ruleset is not None else extra

    if ruleset is not None:
        # Split routing (DIRECT / MATCH→HOP1) is the point of config presets.
        # --unsafe-split-routing kept for legacy; --strict-full-chain forces tunnel.
        # full-chain is a first-class all-tunnel preset (no split rules).
        if getattr(args, "strict_full_chain", False) or is_simple_full_chain(ruleset):
            strict = True
            match_default = "chain"
        else:
            strict = False
            match_default = ruleset.match
        return ruleset, plugins, label, match_default, strict, custom_for_builder

    # Legacy plugins
    strict = not getattr(args, "unsafe_split_routing", False)
    if strict and args.match_default not in (None, "chain", "hop2"):
        raise ValueError(
            "严格全隧道只允许 MATCH=chain；分流请用 config 预设（如 default），"
            "或显式 --unsafe-split-routing"
        )
    if strict:
        match_default = "chain"
    else:
        plugin_names = {p.name for p in (plugins or [])}
        default_target = "chain" if "full" in plugin_names else "hop1"
        match_default = args.match_default or default_target
    return ruleset, plugins, label, match_default, strict, custom_for_builder


def _prepare_hop1(proxies: list[dict], args: argparse.Namespace) -> tuple[dict, list[dict] | None]:
    if args.preset != "full-chain-auto":
        return pick_hop1(
            proxies, filter_keyword=args.filter, skip_latency=args.no_latency,
            preselect=args.hop1,
        ), None

    candidates = filter_proxies(proxies, args.filter)
    if not candidates:
        raise ValueError("过滤后没有可用的机场节点")
    if args.hop1:
        selected = next((p for p in candidates if p.get("name") == args.hop1), None)
        if selected is None:
            raise ValueError(f"验证用节点不在候选列表中: {args.hop1}")
    elif args.no_latency:
        selected = candidates[0]
    else:
        console.print(f"[cyan]正在测试 {len(candidates)} 个第一跳候选节点…[/]")
        try:
            delays = measure_latencies(candidates)
        except Exception as exc:
            console.print(f"[yellow]测速失败，验证时先用第一个节点:[/] {exc}")
            delays = {}
        selected = min(candidates, key=lambda p: delays.get(p["name"]) or float("inf"))
    console.print(
        f"[green]自动第一跳:[/] {len(candidates)} 个候选；"
        f"用 {selected['name']} 验证第二跳，导入后由 mihomo 定期测速选择"
    )
    return selected, candidates


def cmd_wizard(args: argparse.Namespace) -> None:
    apply_mode_flags(args)
    is_full = args.preset in {"full-chain", "full-chain-auto"}
    flow = (
        "订阅 → 填第二跳 → 自动筛选第一跳 → 验证出口 → 输出 YAML"
        if args.preset == "full-chain-auto" else
        "订阅 → 填第二跳 → 选第一跳 → 验证出口 → 输出 YAML"
    )
    console.print(Panel.fit(
        "[bold]Clash 链式代理构建器[/]\n" + flow,
        title=f"chain-builder v{__version__}",
    ))
    if is_full:
        console.print(
            "[cyan]模式:[/] 全链 — 全部走第二跳，不设分流；"
            "导入后在 Verge 里切全局、开 TUN、选 CHAIN"
        )
    else:
        console.print(
            "[dim]模式:[/] 分流  ·  全链请加 [bold]--full-chain[/]"
        )

    url = args.url or _prompt("机场订阅 URL")
    if not url:
        raise SystemExit("需要订阅 URL")

    hop2_raw = args.hop2 or _prompt(
        "第二跳凭证（任意顺序: ip/host port user pass）"
    )
    hop2 = parse_hop2(hop2_raw)
    console.print(
        f"[dim]解析结果:[/] server={hop2.server} port={hop2.port} "
        f"user={hop2.username} pass=***"
        + (f" exit_hint={hop2.exit_ip_hint}" if hop2.exit_ip_hint else "")
    )

    console.print("[cyan]正在拉取订阅…[/]")
    data = fetch_and_parse(url)
    proxies = data["proxies"]
    console.print(f"共 [green]{len(proxies)}[/] 个节点")

    hop1, hop1_candidates = _prepare_hop1(proxies, args)

    ruleset, plugins, label, match_default, strict, custom = _resolve_build_rules(args)

    if args.no_verify:
        exit_ip = hop2.exit_ip_hint or hop2.server
        console.print(f"[yellow]跳过验证，使用[/] {exit_ip}")
        effective = hop2
    else:
        effective, exit_ip, _ = verify_chain(hop1, hop2)

    cfg = build_chain_config(
        hop1,
        effective,
        plugins=plugins,
        ruleset=ruleset,
        match_default=match_default,
        exit_ip=exit_ip,
        custom_rules=custom,
        strict_leak_protection=strict,
        hop1_candidates=hop1_candidates,
    )

    country = lookup_country(exit_ip)
    out_path = resolve_output_path(args, exit_ip, country)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    msg = validate_config_file(cfg)
    console.print(f"[dim]mihomo -t:[/] {msg}")
    out_path.write_text(dump_yaml(cfg), encoding="utf-8")

    rule_count = len(cfg.get("rules") or [])
    chain_summary = (
        "CHAIN = 仅第二跳（第二跳故障即断）" if is_full else
        "CHAIN = fallback[hop2, REJECT]（第二跳故障即断）"
    )
    console.print(Panel.fit(
        f"[green]已写入[/] {out_path}\n"
        f"hop1 = {'自动测速组' if hop1_candidates is not None else hop1.get('name')}\n"
        f"hop2 = {effective.server}:{effective.port} → 出口 {exit_ip} ({country})\n"
        f"规则源 = {label} | 规则数 = {rule_count}\n"
        f"MATCH → {match_default} | 严格全隧道 = {'开' if strict else '关（分流）'}\n"
        f"{chain_summary}",
        title="完成",
    ))
    if is_full:
        console.print(
            "[cyan]Clash Verge：[/]导入后切 [bold]全局[/] → 开 [bold]TUN[/] → 选 [bold]CHAIN[/]"
        )


def cmd_build(args: argparse.Namespace) -> None:
    """Non-interactive build (for scripting)."""
    apply_mode_flags(args)
    if not args.url or not args.hop2:
        raise SystemExit("build 需要 --url 与 --hop2")

    hop2 = parse_hop2(args.hop2)
    data = fetch_and_parse(args.url)
    hop1, hop1_candidates = _prepare_hop1(data["proxies"], args)

    ruleset, plugins, label, match_default, strict, custom = _resolve_build_rules(args)

    if args.no_verify:
        effective, exit_ip = hop2, (hop2.exit_ip_hint or hop2.server)
    else:
        effective, exit_ip, _ = verify_chain(hop1, hop2)

    cfg = build_chain_config(
        hop1,
        effective,
        plugins=plugins,
        ruleset=ruleset,
        match_default=match_default,
        exit_ip=exit_ip,
        custom_rules=custom,
        strict_leak_protection=strict,
        hop1_candidates=hop1_candidates,
    )
    msg = validate_config_file(cfg)
    console.print(f"mihomo -t: {msg}")
    country = lookup_country(exit_ip)
    out_path = resolve_output_path(args, exit_ip, country)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(dump_yaml(cfg), encoding="utf-8")
    console.print(
        f"Wrote {out_path}  exit={exit_ip} ({country})  rules={label}  n={len(cfg['rules'])}"
    )


def cmd_parse_hop2(args: argparse.Namespace) -> None:
    c = parse_hop2(args.hop2)
    console.print(c.as_dict())


def cmd_list_plugins(_: argparse.Namespace) -> None:
    console.print("[bold]Legacy 插件[/]")
    for p in list_plugins():
        console.print(f"  [cyan]{p.name:12}[/] {p.description}")
    console.print("\n[dim]legacy 别名:[/]", ", ".join(sorted(PRESET_ALIASES)))
    console.print("\n[dim]推荐改用[/] [cyan]python -m chain_builder presets[/]")


def cmd_list_presets(_: argparse.Namespace) -> None:
    presets = load_all_presets()
    packs = load_all_packs()

    table = Table(title="config/presets")
    table.add_column("ID", style="cyan")
    table.add_column("MATCH")
    table.add_column("compose")
    table.add_column("说明")
    for p in sorted(presets.values(), key=lambda x: x.id):
        table.add_row(p.id, p.match, ", ".join(p.compose), p.description[:48])
    console.print(table)

    table2 = Table(title="config/packs")
    table2.add_column("ID", style="cyan")
    table2.add_column("target")
    table2.add_column("pri", justify="right")
    table2.add_column("rules", justify="right")
    table2.add_column("说明")
    for p in sorted(packs.values(), key=lambda x: (-x.priority, x.id)):
        table2.add_row(
            p.id,
            p.target,
            str(p.priority),
            str(len(p.rules)),
            (p.description or "")[:40],
        )
    console.print(table2)


def cmd_find_core(args: argparse.Namespace) -> None:
    from .core_locator import iter_candidates, locate_core, probe_version, searched_locations

    if args.all:
        table = Table(title="mihomo 内核候选")
        table.add_column("路径", overflow="fold")
        table.add_column("来源")
        table.add_column("版本")
        count = 0
        for cand in iter_candidates():
            table.add_row(cand.path, cand.source, probe_version(cand.path) or "[red]不可用[/]")
            count += 1
        if count:
            console.print(table)
        else:
            console.print("[red]没有找到任何候选内核[/]")
    else:
        path, source, version = locate_core()
        if path:
            console.print(f"[green]内核:[/] {path}")
            console.print(f"[green]来源:[/] {source}")
            console.print(f"[green]版本:[/] {version or '未知'}")
        else:
            console.print("[red]未找到 mihomo 内核。已尝试:[/]")
            for item in searched_locations():
                console.print(f"  - {item}")
            console.print("可设置环境变量 MIHOMO_BIN 指向内核可执行文件")


def cmd_show_ruleset(args: argparse.Namespace) -> None:
    """Preview merged rules without building a full profile."""
    apply_mode_flags(args)
    args.rules_file = getattr(args, "rules_file", None)
    # reuse resolver with a tiny namespace
    ns = argparse.Namespace(
        preset=args.preset,
        packs=args.packs,
        match_default=args.match_default,
        rules_file=args.rules_file,
        strict_full_chain=False,
        unsafe_split_routing=True,
    )
    ruleset, plugins, label, match_default, strict, _ = _resolve_build_rules(ns)
    if ruleset is None:
        console.print(f"[yellow]legacy 插件路径[/] {label} — 无 config ruleset 可预览")
        console.print(f"plugins: {[p.name for p in (plugins or [])]}")
        return

    console.print(Panel.fit(
        f"源 = {label}\n"
        f"packs = {', '.join(ruleset.pack_ids)}\n"
        f"MATCH → {match_default} ({ruleset.match_group})\n"
        f"rules = {len(ruleset.rules)} | dns_policy = {len(ruleset.dns_nameserver_policy)} | "
        f"sniffer = {len(ruleset.sniffer_force_domains)}\n"
        f"split = {ruleset.is_split_routing}",
        title="MergedRuleset",
    ))
    if args.head:
        for line in ruleset.rules[: args.head]:
            console.print(f"  {line}")
        if len(ruleset.rules) > args.head:
            console.print(f"  … 另有 {len(ruleset.rules) - args.head} 条")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="chain-builder",
        description="机场订阅 + 第二跳 SOCKS5 → mihomo 链式配置（读取 config/ 分流包）",
    )
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd")

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--url", help="机场订阅 URL")
        p.add_argument("--hop2", help="第二跳凭证（任意顺序）")
        p.add_argument("--hop1", help="第一跳节点名；自动模式下仅指定验证用节点")
        p.add_argument("--filter", help="节点名过滤关键字，如 jp / 日本")
        p.add_argument(
            "--preset",
            default=None,
            help="config/presets 名（默认 default；自动第一跳用 full-chain-auto）",
        )
        p.add_argument(
            "--full-chain",
            action="store_true",
            help="全链模式：全部走第二跳、不设分流；YAML 不嵌入 TUN（向导流程不变）",
        )
        p.add_argument(
            "--packs",
            default=None,
            help="直接组合 pack id，逗号分隔，如 anthropic,openai,cn-direct",
        )
        p.add_argument(
            "--match-default",
            choices=["hop1", "hop2", "chain", "direct", "reject"],
            default=None,
            help="覆盖 MATCH 默认策略",
        )
        p.add_argument(
            "--strict-full-chain",
            action="store_true",
            help="强制全部 MATCH→CHAIN（忽略预设分流）",
        )
        p.add_argument(
            "--unsafe-split-routing",
            action="store_true",
            help="legacy 插件模式下允许分流（config 预设默认已分流）",
        )
        p.add_argument("--rules-file", help="额外自定义规则文件（每行一条，需含策略）")
        p.add_argument("--out", help="输出文件路径（最高优先，覆盖 --name 与默认命名）")
        p.add_argument("--name", help="输出文件名（不含目录；默认目录 ./output）")
        p.add_argument("--out-dir", help="输出目录（默认 ./output）")
        p.add_argument("--no-latency", action="store_true", help="TUI 不测延迟")
        p.add_argument("--no-verify", action="store_true", help="跳过临时内核验证")

    w = sub.add_parser("wizard", help="交互向导（默认）")
    add_common(w)
    w.set_defaults(func=cmd_wizard)

    b = sub.add_parser("build", help="构建配置（可脚本化）")
    add_common(b)
    b.set_defaults(func=cmd_build)

    p = sub.add_parser("parse-hop2", help="测试第二跳凭证解析")
    p.add_argument("hop2")
    p.set_defaults(func=cmd_parse_hop2)

    p = sub.add_parser("plugins", help="列出 legacy 规则插件")
    p.set_defaults(func=cmd_list_plugins)

    p = sub.add_parser("presets", help="列出 config/ 预设与规则包")
    p.set_defaults(func=cmd_list_presets)

    p = sub.add_parser("find-core", help="定位 mihomo 内核（排查用）")
    p.add_argument("--all", action="store_true", help="列出所有候选而非只取第一个可用的")
    p.set_defaults(func=cmd_find_core)

    p = sub.add_parser("show-ruleset", help="预览合并后的分流规则")
    p.add_argument("--preset", default="default")
    p.add_argument("--packs", default=None)
    p.add_argument("--match-default", choices=["hop1", "hop2", "chain", "direct", "reject"])
    p.add_argument("--rules-file", default=None)
    p.add_argument("--head", type=int, default=30, help="打印前 N 条规则")
    p.set_defaults(func=cmd_show_ruleset)

    ap.set_defaults(func=None)
    add_common(ap)
    return ap


def main(argv: list[str] | None = None) -> None:
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

    ap = build_parser()
    args = ap.parse_args(argv)
    if args.func is None:
        args.func = cmd_wizard
    try:
        args.func(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]已取消[/]")
        raise SystemExit(130)
    except Exception as e:
        console.print(f"[red]错误:[/] {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
