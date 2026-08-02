"""Build mihomo chain YAML with fail-closed CHAIN group."""
from __future__ import annotations

import copy
import re
from typing import Iterable

import yaml

from .hop2 import Hop2Creds
from .plugins.base import BuildContext, PluginContribution, RulePlugin
from .plugins.registry import get_plugin
from .ruleset import MergedRuleset, merge_packs, merge_preset, resolve_preset_name

PRIVATE_RULES = [
    "DOMAIN-SUFFIX,local,DIRECT",
    "DOMAIN-SUFFIX,lan,DIRECT",
    "DOMAIN-SUFFIX,localhost,DIRECT",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
    "IP-CIDR6,::1/128,DIRECT,no-resolve",
    "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
    "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
]

GEOX_URL = {
    "geoip": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
    "geosite": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
    "mmdb": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
}


def slugify(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").lower()
    return s or "hop1"


def dump_yaml(data: dict) -> str:
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False)


def _base_dns(chain_group: str, full_chain: bool) -> dict:
    dns = {
        "enable": True,
        "ipv6": True,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "use-hosts": True,
        "respect-rules": True,
        "default-nameserver": [
            "system",
            "119.29.29.29",
            "223.5.5.5",
            "114.114.114.114",
        ],
        "nameserver": [
            "https://223.5.5.5/dns-query#skip-cert-verify=true",
            "https://doh.pub/dns-query#skip-cert-verify=true",
            "https://dns.alidns.com/dns-query#skip-cert-verify=true",
        ],
        "proxy-server-nameserver": [
            "https://223.5.5.5/dns-query#skip-cert-verify=true",
            "https://doh.pub/dns-query#skip-cert-verify=true",
            "https://dns.alidns.com/dns-query#skip-cert-verify=true",
        ],
        "fake-ip-filter": [
            "*.lan",
            "*.local",
            "*.localhost",
            "*.home.arpa",
            "time.*.com",
            "ntp.*.com",
            "*.msftconnecttest.com",
            "*.msftncsi.com",
        ],
        "nameserver-policy": {},
    }
    if full_chain:
        # All DNS via CHAIN — if chain dies, DNS fails (no leak)
        dns["nameserver"] = [
            f"https://223.5.5.5/dns-query#{chain_group}&skip-cert-verify=true",
            f"https://doh.pub/dns-query#{chain_group}&skip-cert-verify=true",
        ]
    return dns


def _sniffer(force_domains: list[str]) -> dict:
    return {
        "enable": True,
        "force-dns-mapping": True,
        "parse-pure-ip": True,
        "override-destination": False,
        "sniff": {
            "HTTP": {"ports": [80, "8080-8880"], "override-destination": True},
            "TLS": {"ports": [443, 8443]},
            "QUIC": {"ports": [443, 8443]},
        },
        "force-domain": force_domains,
    }


def resolve_plugins(names: Iterable[str]) -> list[RulePlugin]:
    return [get_plugin(n) for n in names]


def build_chain_config(
    hop1: dict,
    hop2: Hop2Creds,
    plugins: list[RulePlugin] | None = None,
    *,
    ruleset: MergedRuleset | None = None,
    match_default: str = "hop1",
    exit_ip: str | None = None,
    custom_rules: list[str] | None = None,
    strict_leak_protection: bool | None = None,
) -> dict:
    """Build a complete mihomo config.

    Core no-leak design for HOP2 traffic (per mihomo dialer-proxy docs + ref):
      - hop2 node uses dialer-proxy → hop1
      - CHAIN group is fallback: [hop2, REJECT]  — never DIRECT / never bare hop1
      - Rules that must use hop2 point at CHAIN
      - DNS for those domains uses #CHAIN (respect-rules)
      - If hop1 or hop2 dies → CHAIN connection REJECT, no IP leak on that path

    Prefer `ruleset=` from config/ packs+presets. Legacy `plugins=` still works.

    When `ruleset` is provided and uses DIRECT/HOP1 split routing, strict
    full-tunnel mode is off unless explicitly forced via strict_leak_protection=True.

    match_default (legacy plugins path):
      - "hop1": MATCH → HOP1
      - "chain"/"hop2": MATCH → CHAIN
      - "direct": MATCH → DIRECT
      - "reject": MATCH → REJECT
    """
    if ruleset is not None:
        # Config packs drive routing; split by default when preset asks for it.
        if strict_leak_protection is None:
            strict_leak_protection = not ruleset.is_split_routing
        match_default = ruleset.match
    else:
        if strict_leak_protection is None:
            strict_leak_protection = True
        plugins = plugins or [get_plugin("full")]

    plugin_names = {p.name for p in (plugins or [])}
    full_chain = (
        strict_leak_protection
        or "full" in plugin_names
        or match_default in {"chain", "hop2"}
    )

    hop1_node = copy.deepcopy(hop1)
    hop1_display = hop1.get("name", "hop1")
    # Keep readable hop1 name (matches ref); sanitize only if empty.
    hop1_name = hop1_display or f"hop1-{slugify('node')}"
    hop1_node["name"] = hop1_name

    label_ip = exit_ip or hop2.exit_ip_hint or hop2.server
    hop2_name = f"HOP2 {label_ip} - SOCKS5 via hop1"
    hop2_node = {
        "name": hop2_name,
        "type": "socks5",
        "server": hop2.server,
        "port": hop2.port,
        "username": hop2.username,
        "password": hop2.password,
        "udp": True,
        "dialer-proxy": hop1_name,
    }

    chain_group = "CHAIN"
    hop1_group = "HOP1"

    # Fail-closed: if chain unhealthy → REJECT (never fall back to DIRECT/hop1)
    proxy_groups = [
        {
            "name": chain_group,
            "type": "fallback",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 60,
            "lazy": True,
            "proxies": [hop2_name, "REJECT"],
        },
    ]
    need_hop1_group = (not strict_leak_protection) and (
        match_default in {"hop1", "HOP1"}
        or (ruleset is not None and ruleset.uses_hop1)
        or match_default == "hop1"
    )
    if need_hop1_group:
        proxy_groups.append({
            "name": hop1_group,
            "type": "select",
            "proxies": [hop1_name],
        })

    ctx = BuildContext(
        hop1_name=hop1_name,
        hop2_name=hop2_name,
        chain_group=chain_group,
        hop1_group=hop1_group,
        exit_ip=exit_ip or hop2.exit_ip_hint,
    )

    contrib = PluginContribution()
    if ruleset is not None:
        contrib.rules.extend(ruleset.rules)
        contrib.dns_nameserver_policy.update(ruleset.dns_nameserver_policy)
        contrib.sniffer_force_domains.extend(ruleset.sniffer_force_domains)
    else:
        for p in plugins or []:
            if p.name == "full":
                continue  # MATCH handled below
            c = p.contribute(ctx)
            contrib.rules.extend(c.rules)
            contrib.dns_nameserver_policy.update(c.dns_nameserver_policy)
            contrib.sniffer_force_domains.extend(c.sniffer_force_domains)

    if custom_rules:
        contrib.rules.extend(custom_rules)

    match_map = {
        "hop1": hop1_group,
        "hop2": chain_group,
        "chain": chain_group,
        "direct": "DIRECT",
        "reject": "REJECT",
    }
    if strict_leak_protection or (full_chain and ruleset is None):
        match_target = chain_group
    elif ruleset is not None:
        match_target = ruleset.match_group
    else:
        match_target = match_map.get(match_default, hop1_group)

    if ruleset is not None:
        # Packs already include private-direct when composed; don't double-prepend.
        rules = list(contrib.rules) + [f"MATCH,{match_target}"]
    else:
        rules = list(PRIVATE_RULES) + contrib.rules + [f"MATCH,{match_target}"]

    dns = _base_dns(chain_group, full_chain=bool(strict_leak_protection and ruleset is None))
    dns["nameserver-policy"] = contrib.dns_nameserver_policy

    cfg = {
        "mixed-port": 7890,
        "allow-lan": not strict_leak_protection,
        "bind-address": "127.0.0.1" if strict_leak_protection else "*",
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "unified-delay": True,
        "tcp-concurrent": True,
        "find-process-mode": "strict",
        "profile": {
            "store-selected": not strict_leak_protection,
            "store-fake-ip": True,
        },
        "geox-url": GEOX_URL,
        "dns": dns,
        "proxies": [hop2_node, hop1_node],
        "proxy-groups": proxy_groups,
        "rules": rules,
        "sniffer": _sniffer(list(dict.fromkeys(contrib.sniffer_force_domains))),
    }
    # Always enforce hop2 fail-closed (even in default split routing).
    assert_hop2_fail_closed(cfg, hop1_name, hop2_name)

    if strict_leak_protection and ruleset is None:
        cfg["tun"] = {
            "enable": True,
            "stack": "mixed",
            "dns-hijack": ["any:53", "tcp://any:53"],
            "auto-route": True,
            "auto-detect-interface": True,
            "strict-route": True,
        }
        assert_fail_closed_config(cfg, hop1_name, hop2_name)
    elif ruleset is not None and not strict_leak_protection:
        assert_default_split_routing(cfg, ruleset)
    return cfg


def _rule_policy(rule: str) -> str:
    fields = [part.strip() for part in rule.split(",")]
    return fields[-2] if fields[-1] == "no-resolve" else fields[-1]


def assert_hop2_fail_closed(cfg: dict, hop1_name: str, hop2_name: str) -> None:
    """CHAIN path must never fall back to DIRECT / bare hop1 (anti-leak)."""
    proxies = {p.get("name"): p for p in cfg.get("proxies", [])}
    hop2 = proxies.get(hop2_name)
    if hop2 is None:
        raise ValueError("缺少第二跳节点")
    if hop2.get("dialer-proxy") != hop1_name:
        raise ValueError("第二跳必须 dialer-proxy 指向第一跳")
    if hop1_name not in proxies:
        raise ValueError("缺少第一跳节点")

    groups = {g.get("name"): g for g in cfg.get("proxy-groups", [])}
    chain = groups.get("CHAIN")
    if not chain:
        raise ValueError("缺少 CHAIN 策略组")
    if chain.get("proxies") != [hop2_name, "REJECT"]:
        raise ValueError(
            f"CHAIN 必须为 fallback[第二跳, REJECT] 以防漏 IP，实际={chain.get('proxies')}"
        )

    dns = cfg.get("dns", {})
    if not dns.get("respect-rules"):
        raise ValueError("防漏要求 dns.respect-rules=true")


def assert_default_split_routing(cfg: dict, ruleset: MergedRuleset) -> None:
    """Default split: AI→CHAIN, CN/private→DIRECT, MATCH→HOP1."""
    rules = cfg.get("rules") or []
    if not rules or rules[-1] != "MATCH,HOP1":
        raise ValueError(f"默认分流要求 MATCH,HOP1，实际末条={rules[-1] if rules else None}")

    if "HOP1" not in {g.get("name") for g in cfg.get("proxy-groups", [])}:
        raise ValueError("默认分流需要 HOP1 组（其余境外走机场第一跳）")

    rule_set = set(rules)
    required: list[str] = []
    if "anthropic" in ruleset.pack_ids:
        required += [
            "DOMAIN-SUFFIX,anthropic.com,CHAIN",
            "DOMAIN-SUFFIX,claude.ai,CHAIN",
        ]
    if "openai" in ruleset.pack_ids:
        required += [
            "DOMAIN-SUFFIX,openai.com,CHAIN",
            "DOMAIN-SUFFIX,chatgpt.com,CHAIN",
        ]
    if "cn-direct" in ruleset.pack_ids:
        required += [
            "DOMAIN-SUFFIX,bilibili.com,DIRECT",
            "GEOSITE,CN,DIRECT",
        ]
    for r in required:
        if r not in rule_set:
            raise ValueError(f"默认分流缺少规则: {r}")

    # First-party AI domains must not be DIRECT
    for rule in rules:
        if not rule.startswith("DOMAIN"):
            continue
        if any(
            x in rule
            for x in (
                "anthropic.com",
                "claude.ai",
                "claude.com",
                "openai.com",
                "chatgpt.com",
                "oaistatic.com",
                "oaiusercontent.com",
            )
        ):
            if _rule_policy(rule) != "CHAIN":
                raise ValueError(f"AI 域名必须走 CHAIN（第二跳）: {rule}")

    nsp = cfg.get("dns", {}).get("nameserver-policy") or {}
    for key in ("+.anthropic.com", "+.openai.com", "+.chatgpt.com", "+.claude.ai"):
        if key in nsp and any("#CHAIN" not in str(x) for x in nsp[key]):
            raise ValueError(f"AI DNS 必须经 CHAIN: {key}")


def assert_fail_closed_config(cfg: dict, hop1_name: str, hop2_name: str) -> None:
    """Reject a strict full-tunnel config if any path can bypass hop2."""
    assert_hop2_fail_closed(cfg, hop1_name, hop2_name)

    tun = cfg.get("tun", {})
    if not tun.get("enable") or not tun.get("strict-route"):
        raise ValueError("严格防漏要求启用 TUN strict-route")
    if cfg.get("allow-lan") or cfg.get("bind-address") != "127.0.0.1":
        raise ValueError("严格防漏只允许本机访问代理端口")

    proxies = cfg.get("proxies", [])
    if len(proxies) != 2 or {p.get("name") for p in proxies} != {
        hop1_name,
        hop2_name,
    }:
        raise ValueError("严格防漏配置必须且只能包含第一跳与第二跳")

    groups = {g.get("name"): g for g in cfg.get("proxy-groups", [])}
    if "HOP1" in groups:
        raise ValueError("严格防漏配置不得暴露可选 HOP1 组")

    rules = cfg.get("rules", [])
    if not rules or rules[-1] != "MATCH,CHAIN":
        raise ValueError("严格防漏要求最终规则为 MATCH,CHAIN")
    private_rules = set(PRIVATE_RULES)
    for rule in rules:
        if rule in private_rules:
            continue
        policy = _rule_policy(rule)
        if policy not in {"CHAIN", "REJECT"}:
            raise ValueError(f"严格防漏拒绝旁路规则: {rule}")

    dns = cfg.get("dns", {})
    routed_resolvers = list(dns.get("nameserver", []))
    for resolvers in dns.get("nameserver-policy", {}).values():
        routed_resolvers.extend(resolvers)
    if any("#CHAIN" not in str(resolver) for resolver in routed_resolvers):
        raise ValueError("业务 DNS 必须经 CHAIN；仅代理节点引导 DNS 可直连")


PRESET_ALIASES = {
    "basic": ["full"],
    "full": ["full"],
    "anthropic": ["anthropic"],
    "claude": ["anthropic"],
    "openai": ["openai"],
    "ai": ["anthropic", "openai"],
    "anthropic-openai": ["anthropic", "openai"],
}


def plugins_from_preset(preset: str) -> list[RulePlugin]:
    names = PRESET_ALIASES.get(preset.lower())
    if names is None:
        # allow comma-separated plugin names
        names = [n.strip() for n in preset.split(",") if n.strip()]
    if not names:
        names = ["full"]
    return resolve_plugins(names)


def resolve_rules_source(
    preset: str | None = None,
    *,
    packs: str | None = None,
    match: str | None = None,
    extra_rules: list[str] | None = None,
) -> tuple[MergedRuleset | None, list[RulePlugin] | None, str]:
    """Resolve CLI preset/packs into either a config ruleset or legacy plugins.

    Priority:
      1. --packs a,b,c  (ad-hoc compose)
      2. config/presets/<preset>.yaml
      3. legacy plugin aliases (basic/full/anthropic/…)

    Returns (ruleset|None, plugins|None, label).
    """
    if packs:
        ids = [x.strip() for x in packs.split(",") if x.strip()]
        if not ids:
            raise ValueError("--packs 不能为空")
        rs = merge_packs(
            ids,
            match=match or "hop1",
            extra_rules=extra_rules,
        )
        return rs, None, f"packs:{','.join(rs.pack_ids)}"

    name = (preset or "default").strip()
    cfg_id = resolve_preset_name(name)
    if cfg_id:
        rs = merge_preset(cfg_id, extra_rules=extra_rules)
        if match:
            # allow CLI override of MATCH
            rs = merge_packs(
                rs.pack_ids,
                match=match,
                preset_id=rs.preset_id,
                extra_rules=extra_rules,
            )
        return rs, None, f"preset:{cfg_id}"

    # Legacy plugin path
    plugins = plugins_from_preset(name)
    return None, plugins, f"plugin:{name}"
