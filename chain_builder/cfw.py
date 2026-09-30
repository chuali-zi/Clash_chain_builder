"""Generate standalone YAML for the original Clash for Windows Premium core."""
from __future__ import annotations

import copy
from functools import lru_cache
import ipaddress
from pathlib import Path
import re
import time
import warnings

import requests
import yaml

from .hop2 import Hop2Creds
from .plugins.base import BuildContext, RulePlugin
from .ruleset import MergedRuleset

SUPPORTED_PROTOCOLS = {"ss", "ssr", "vmess", "trojan", "snell", "http", "socks5"}
SUPPORTED_RULES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6",
    "GEOIP", "SRC-IP-CIDR", "SRC-PORT", "DST-PORT", "PROCESS-NAME",
    "PROCESS-PATH", "MATCH", "RULE-SET",
}
PROCESS_EXTENSIONS = {"PROCESS-NAME-WILDCARD", "PROCESS-PATH-REGEX"}
DIRECT_DOH = "https://doh.pub/dns-query"
DNS_IP = "1.1.1.1"
DEFAULT_DNS_PORT = 10554


def compatible_node(node: dict) -> dict:
    """Reject protocols/features that cannot be downgraded without changing the wire protocol."""
    kind = node.get("type", "")
    if node.get("server") == DNS_IP:
        raise ValueError("第一跳地址与 CFW 链式 DNS 映射地址 1.1.1.1 冲突")
    if kind not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"CFW 不支持协议 {kind}")
    for field in ("dialer-proxy", "reality-opts", "shadow-tls-opts", "restls-opts", "smux"):
        if node.get(field):
            raise ValueError(f"CFW 不支持节点参数 {field}")
    if kind == "ss" and str(node.get("cipher", "")).startswith("2022-"):
        raise ValueError("CFW 不支持 Shadowsocks 2022 加密")
    if kind == "vmess" and node.get("network", "tcp") not in {"tcp", "ws", "http", "h2", "grpc"}:
        raise ValueError(f"CFW 不支持 VMess 传输 {node['network']}")
    result = copy.deepcopy(node)
    # Meta-only optional tuning; connection-critical options above are rejected.
    for field in ("client-fingerprint", "tfo", "mptcp", "ip-version", "packet-encoding"):
        if field == "packet-encoding" and result.get(field):
            raise ValueError("CFW 不支持 packet-encoding")
        result.pop(field, None)
    return result


def filter_compatible_nodes(nodes: list[dict]) -> tuple[list[dict], list[str]]:
    accepted, rejected = [], []
    for node in nodes:
        try:
            accepted.append(compatible_node(node))
        except ValueError as exc:
            rejected.append(f"{node.get('name', '?')}: {exc}")
    return accepted, rejected


@lru_cache(maxsize=32)
def load_geosite(tag: str) -> list[str]:
    """Fetch readable domain snapshots at generation time; exported YAML is self-contained."""
    tag = tag.lower()
    if not re.fullmatch(r"[a-z0-9_-]+", tag):
        raise ValueError(f"CFW 无法展开 GEOSITE 标签: {tag}")
    cache = Path(__file__).resolve().parents[1] / ".cache" / "cfw-geosite" / f"{tag}.yaml"
    content = None
    if cache.exists() and time.time() - cache.stat().st_mtime < 86400:
        content = cache.read_text(encoding="utf-8")
    if content is None:
        url = f"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/{tag}.yaml"
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            content = response.text
        except requests.RequestException as exc:
            if not cache.exists():
                raise RuntimeError(f"CFW 展开 GEOSITE,{tag} 失败: {exc}") from exc
            warnings.warn(f"GEOSITE,{tag} 下载失败，使用本地缓存", stacklevel=2)
            content = cache.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
        if not isinstance(data, dict) or not isinstance(data.get("payload"), list) or not data["payload"]:
            raise ValueError(f"GEOSITE,{tag} 域名列表无效")
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(content, encoding="utf-8")
    payload = yaml.safe_load(content)["payload"]
    if any(not isinstance(domain, str) for domain in payload):
        raise ValueError(f"GEOSITE,{tag} 含无效域名条目")
    return payload


def domain_rule(domain: str, policy: str) -> str:
    if domain.startswith("+."):
        return f"DOMAIN-SUFFIX,{domain[2:]},{policy}"
    if "*" in domain or "," in domain or domain.startswith(("regexp:", "keyword:")):
        raise ValueError(f"CFW 无法等价展开域名模式: {domain}")
    return f"DOMAIN,{domain},{policy}"


def validate_custom_rules(rules: list[str]) -> None:
    for rule in rules:
        kind = rule.split(",", 1)[0]
        if kind not in SUPPORTED_RULES | {"GEOSITE"}:
            raise ValueError(f"CFW 不支持自定义规则: {rule}")


def convert_rules(rules: list[str]) -> list[str]:
    from .builder import PRIVATE_RULES

    converted = []
    omitted = 0
    for rule in rules:
        fields = rule.split(",")
        kind = fields[0]
        policy = fields[-2] if fields[-1] == "no-resolve" else fields[-1]
        if kind in PROCESS_EXTENSIONS:
            omitted += 1
        elif kind == "GEOSITE":
            converted.extend(domain_rule(domain, policy) for domain in load_geosite(fields[1]))
        elif kind == "GEOIP" and fields[1].lower() == "private":
            converted.extend(r.replace(",DIRECT", f",{policy}") for r in PRIVATE_RULES if r.startswith("IP-CIDR"))
        elif kind in SUPPORTED_RULES:
            converted.append(rule)
        else:
            raise ValueError(f"CFW 不支持规则: {rule}")
    if omitted:
        warnings.warn(
            f"CFW 无法保留 {omitted} 条进程通配符/正则规则，已保留精确进程名和域名规则；覆盖范围较 mihomo 小",
            stacklevel=2,
        )
    return list(dict.fromkeys(converted))


def build_cfw_config(
    hop1: dict, hop2: Hop2Creds, plugins: list[RulePlugin] | None = None, *,
    ruleset: MergedRuleset | None = None, match_default: str = "hop1",
    exit_ip: str | None = None, custom_rules: list[str] | None = None,
    strict_leak_protection: bool | None = None, hop1_candidates: list[dict] | None = None,
    dns_port: int = DEFAULT_DNS_PORT,
) -> dict:
    from .builder import AUTO_HOP1_GROUP, PRIVATE_RULES, is_simple_full_chain
    from .plugins.registry import get_plugin

    if not 1024 <= dns_port <= 65535 or dns_port in {7890, 1053}:
        raise ValueError("CFW DNS 隧道端口须为 1024–65535，且不能是 7890 / 1053")
    simple_full = is_simple_full_chain(ruleset)
    if ruleset is not None and ruleset.preset_id == "full-chain-auto" and hop1_candidates is None:
        raise ValueError("full-chain-auto 需要机场节点列表")
    strict = (not ruleset.is_split_routing if ruleset else True) if strict_leak_protection is None else strict_leak_protection
    full = simple_full or strict
    if ruleset is None:
        plugins = plugins or [get_plugin("full")]
        full = full or any(p.name == "full" for p in plugins)
    candidates = [compatible_node(p) for p in (hop1_candidates if hop1_candidates is not None else [hop1])]
    if not candidates:
        raise ValueError("CFW 没有兼容的第一跳节点")
    hop2_name = f"HOP2 {exit_ip or hop2.exit_ip_hint or hop2.server} - SOCKS5 via hop1"
    names = [p.get("name") for p in candidates]
    reserved = {"CHAIN", "HOP1", "HOP1-AUTO", "GLOBAL", "DIRECT", "REJECT", hop2_name}
    if any(not name or name in reserved for name in names) or len(set(names)) != len(names):
        raise ValueError("CFW 第一跳名称为空、重复或与策略组冲突")
    first = AUTO_HOP1_GROUP if hop1_candidates is not None else names[0]
    groups = []
    if hop1_candidates is not None:
        groups.append({"name": first, "type": "url-test", "proxies": names,
                       "url": "https://www.gstatic.com/generate_204", "interval": 300, "lazy": False})
    groups.extend([
        {"name": "CHAIN", "type": "relay", "proxies": [first, hop2_name]},
        {"name": "HOP1", "type": "select", "proxies": [first]},
    ])
    raw_rules, policy_keys = [], []
    if not simple_full:
        if ruleset:
            raw_rules = list(ruleset.rules)
            policy_keys = list(ruleset.dns_nameserver_policy)
        else:
            ctx = BuildContext(hop1_name=names[0], hop2_name=hop2_name, exit_ip=exit_ip)
            raw_rules = list(PRIVATE_RULES)
            for plugin in plugins or []:
                contribution = plugin.contribute(ctx)
                raw_rules.extend(contribution.rules)
                policy_keys.extend(contribution.dns_nameserver_policy)
    validate_custom_rules(custom_rules or [])
    raw_rules.extend(custom_rules or [])
    if full:
        # Strict CFW routing also covers the preset's DIRECT/HOP1 entries.
        raw_rules = [r if r.split(",")[-1] == "REJECT" else _with_policy(r, "CHAIN") for r in raw_rules]
    match = "CHAIN" if full else (ruleset.match_group if ruleset else {
        "hop1": "HOP1", "hop2": "CHAIN", "chain": "CHAIN", "direct": "DIRECT", "reject": "REJECT",
    }[match_default])
    rules = convert_rules(raw_rules + [f"MATCH,{match}"])
    chain_doh = f"https://{DNS_IP}:{dns_port}/dns-query"
    policy = {}
    for key in policy_keys:
        keys = load_geosite(key.split(":", 1)[1]) if key.lower().startswith("geosite:") else [key]
        for domain in keys:
            policy[domain] = chain_doh
    # Bootstrap airport hosts directly to avoid asking a chain to resolve its own first hop.
    for node in candidates:
        server = node["server"]
        try:
            ipaddress.ip_address(server)
        except ValueError:
            policy[server] = DIRECT_DOH
    dns = {
        "enable": True, "ipv6": True, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
        "use-hosts": True, "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        "nameserver": [chain_doh] if full else [DIRECT_DOH],
        "nameserver-policy": policy,
        "fake-ip-filter": ["*.lan", "*.local", "*.localhost", "*.home.arpa", "time.*.com", "ntp.*.com"],
    }
    return {
        "mixed-port": 7890, "allow-lan": False, "bind-address": "127.0.0.1", "mode": "rule",
        "log-level": "info", "ipv6": True,
        "profile": {"store-selected": False, "store-fake-ip": True},
        "hosts": {DNS_IP: "127.0.0.1"}, "dns": dns,
        "proxies": [{"name": hop2_name, "type": "socks5", "server": hop2.server, "port": hop2.port,
                     "username": hop2.username, "password": hop2.password, "udp": False}] + candidates,
        "proxy-groups": groups, "rules": rules,
        "tunnels": [{"network": ["tcp"], "address": f"127.0.0.1:{dns_port}",
                     "target": f"{DNS_IP}:443", "proxy": "CHAIN"}],
    }


def _with_policy(rule: str, policy: str) -> str:
    fields = rule.split(",")
    fields[-2 if fields[-1] == "no-resolve" else -1] = policy
    return ",".join(fields)
