"""Audit default preset routing + hop2 fail-closed anti-leak."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chain_builder.builder import build_chain_config, resolve_rules_source
from chain_builder.hop2 import parse_hop2
from chain_builder.verify import validate_config_file


def _policy(rule: str) -> str:
    fields = [p.strip() for p in rule.split(",")]
    return fields[-2] if fields[-1] == "no-resolve" else fields[-1]


def audit() -> None:
    rs, plugins, label = resolve_rules_source(None)  # no args → default
    assert plugins is None, label
    assert rs is not None
    assert rs.preset_id == "default"
    assert rs.match == "hop1"
    assert set(rs.pack_ids) >= {
        "private-direct",
        "anthropic",
        "anthropic-sidechannel",
        "openai",
        "openai-sidechannel",
        "cn-direct",
    }

    hop1 = {
        "name": "2x专线-日本-2",
        "type": "anytls",
        "server": "jp.example.com",
        "port": 7001,
        "password": "x",
        "udp": True,
        "skip-cert-verify": True,
        "client-fingerprint": "chrome",
    }
    hop2 = parse_hop2("9.9.9.9 1080 u p")
    cfg = build_chain_config(
        hop1, hop2, ruleset=rs, exit_ip="9.9.9.9", strict_leak_protection=False
    )

    # --- groups ---
    groups = {g["name"]: g for g in cfg["proxy-groups"]}
    assert "CHAIN" in groups and "HOP1" in groups
    assert groups["CHAIN"]["type"] == "fallback"
    hop2_name = next(p["name"] for p in cfg["proxies"] if p["type"] == "socks5")
    hop1_name = next(p["name"] for p in cfg["proxies"] if p["type"] != "socks5")
    assert groups["CHAIN"]["proxies"] == [hop2_name, "REJECT"], groups["CHAIN"]
    assert groups["HOP1"]["proxies"] == [hop1_name]
    assert next(p for p in cfg["proxies"] if p["name"] == hop2_name)["dialer-proxy"] == hop1_name

    rules = cfg["rules"]
    assert rules[-1] == "MATCH,HOP1"

    # sample probes
    probes = {
        "DOMAIN-SUFFIX,anthropic.com,CHAIN": False,
        "DOMAIN-SUFFIX,claude.ai,CHAIN": False,
        "DOMAIN-SUFFIX,openai.com,CHAIN": False,
        "DOMAIN-SUFFIX,chatgpt.com,CHAIN": False,
        "DOMAIN-SUFFIX,bilibili.com,DIRECT": False,
        "GEOSITE,CN,DIRECT": False,
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve": False,
    }
    for r in rules:
        if r in probes:
            probes[r] = True
    missing = [k for k, v in probes.items() if not v]
    assert not missing, f"missing expected rules: {missing}"

    # ordering: AI CHAIN before CN DIRECT catch-all
    i_ai = next(i for i, r in enumerate(rules) if r == "DOMAIN-SUFFIX,anthropic.com,CHAIN")
    i_cn = next(i for i, r in enumerate(rules) if r.startswith("GEOSITE,CN,"))
    assert i_ai < i_cn

    # no AI suffix accidentally DIRECT
    for r in rules:
        if any(x in r for x in ("anthropic.com", "claude.ai", "openai.com", "chatgpt.com")):
            if r.startswith("DOMAIN"):
                assert _policy(r) == "CHAIN", r

    # DNS for AI via CHAIN
    nsp = cfg["dns"]["nameserver-policy"]
    assert cfg["dns"].get("respect-rules") is True
    for key in ("+.anthropic.com", "+.claude.ai", "+.openai.com", "+.chatgpt.com"):
        assert key in nsp, key
        assert all("#CHAIN" in x for x in nsp[key]), (key, nsp[key])

    # sniffer force
    force = set(cfg["sniffer"]["force-domain"])
    for d in ("+.anthropic.com", "+.claude.ai", "+.openai.com", "+.chatgpt.com"):
        assert d in force

    msg = validate_config_file(cfg)
    print("mihomo -t:", msg)
    print("OK default routing:")
    print("  Anthropic/OpenAI → CHAIN(hop2→REJECT)")
    print("  CN/private → DIRECT")
    print("  MATCH → HOP1")
    print(f"  rules={len(rules)} dns_policy={len(nsp)} label={label}")


if __name__ == "__main__":
    audit()
