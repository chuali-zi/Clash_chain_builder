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
    resolve_rules_source,
)
from .fetch import fetch_and_parse
from .geo import lookup_country, output_filename
from .hop2 import parse_hop2
from .plugins.registry import list_plugins
from .ruleset import load_all_packs, load_all_presets
from .tui import pick_hop1
from .verify import validate_config_file, verify_chain

console = Console()
DEFAULT_OUT_DIR = Path(__file__).resolve().parent.parent / "output"


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
        if getattr(args, "strict_full_chain", False):
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


def cmd_wizard(args: argparse.Namespace) -> None:
    console.print(Panel.fit(
        "[bold]Clash 链式代理构建器[/]\n"
        "订阅 → 选第一跳 → 填第二跳 → 验证出口 → 输出 YAML",
        title=f"chain-builder v{__version__}",
    ))

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

    hop1 = pick_hop1(
        proxies,
        filter_keyword=args.filter,
        skip_latency=args.no_latency,
        preselect=args.hop1,
    )

    # 无额外参数 → 固定 default：AI→HOP2 / 国内 DIRECT / 其余 HOP1
    if not args.preset and not args.packs:
        args.preset = "default"
        console.print(
            "[dim]规则预设:[/] default（OpenAI/Anthropic→第二跳，国内→DIRECT，其余→第一跳）"
        )

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
    )

    country = lookup_country(exit_ip)
    fname = output_filename(exit_ip, country)
    out_dir = Path(args.out_dir) if args.out_dir else DEFAULT_OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = Path(args.out) if args.out else out_dir / fname

    msg = validate_config_file(cfg)
    console.print(f"[dim]mihomo -t:[/] {msg}")
    out_path.write_text(dump_yaml(cfg), encoding="utf-8")

    rule_count = len(cfg.get("rules") or [])
    console.print(Panel.fit(
        f"[green]已写入[/] {out_path}\n"
        f"hop1 = {hop1.get('name')}\n"
        f"hop2 = {effective.server}:{effective.port} → 出口 {exit_ip} ({country})\n"
        f"规则源 = {label} | 规则数 = {rule_count}\n"
        f"MATCH → {match_default} | 严格全隧道 = {'开' if strict else '关（分流）'}\n"
        f"CHAIN = fallback[hop2, REJECT]（第二跳故障即断）",
        title="完成",
    ))


def cmd_build(args: argparse.Namespace) -> None:
    """Non-interactive build (for scripting)."""
    if not args.url or not args.hop2:
        raise SystemExit("build 需要 --url 与 --hop2")

    hop2 = parse_hop2(args.hop2)
    data = fetch_and_parse(args.url)
    hop1 = pick_hop1(
        data["proxies"],
        filter_keyword=args.filter,
        skip_latency=args.no_latency,
        preselect=args.hop1,
    )

    if not args.preset and not args.packs:
        args.preset = "default"

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
    )
    msg = validate_config_file(cfg)
    console.print(f"mihomo -t: {msg}")
    country = lookup_country(exit_ip)
    out_dir = Path(args.out_dir) if args.out_dir else DEFAULT_OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = Path(args.out) if args.out else out_dir / output_filename(exit_ip, country)
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


def cmd_show_ruleset(args: argparse.Namespace) -> None:
    """Preview merged rules without building a full profile."""
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
        p.add_argument("--hop1", help="第一跳节点名（精确匹配，跳过 TUI）")
        p.add_argument("--filter", help="节点名过滤关键字，如 jp / 日本")
        p.add_argument(
            "--preset",
            default=None,
            help="config/presets 名（默认 default），或 legacy: basic|ai|anthropic",
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
        p.add_argument("--out", help="输出文件路径（默认按 出口IP_属地.yaml）")
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
