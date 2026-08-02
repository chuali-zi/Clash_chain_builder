"""Tests for config/ pack loading and merge."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chain_builder.builder import build_chain_config, resolve_rules_source
from chain_builder.hop2 import parse_hop2
from chain_builder.ruleset import (
    materialize_rule,
    merge_preset,
    merge_packs,
)
from chain_builder.verify import validate_config_file


def test_materialize_no_resolve():
    assert (
        materialize_rule("IP-CIDR,10.0.0.0/8,no-resolve", "DIRECT")
        == "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"
    )
    assert materialize_rule("DOMAIN-SUFFIX,bilibili.com", "DIRECT") == (
        "DOMAIN-SUFFIX,bilibili.com,DIRECT"
    )


def test_default_preset_merge():
    rs = merge_preset("default")
    assert rs.match == "hop1"
    assert rs.match_group == "HOP1"
    assert rs.is_split_routing
    assert "anthropic" in rs.pack_ids
    assert "cn-direct" in rs.pack_ids
    # hop2 rules present
    assert any(r.endswith(",CHAIN") or ",CHAIN,no-resolve" in r for r in rs.rules)
    # direct rules present
    assert any(r.endswith(",DIRECT") or ",DIRECT,no-resolve" in r for r in rs.rules)
    # priority: process/claude before GEOSITE,CN
    idx_claude = next(i for i, r in enumerate(rs.rules) if "claude.exe" in r)
    idx_cn = next(i for i, r in enumerate(rs.rules) if r.startswith("GEOSITE,CN,"))
    assert idx_claude < idx_cn
    # dns for anthropic goes through CHAIN
    assert any("#CHAIN" in v for vs in rs.dns_nameserver_policy.values() for v in vs)


def test_adhoc_packs():
    rs = merge_packs(["private-direct", "anthropic"], match="hop1")
    assert rs.pack_ids[0] == "private-direct"  # higher priority first in sort... 
    # private-direct pri 400 > anthropic 320, so private first in selected sort
    assert "private-direct" in rs.pack_ids
    assert any("DOMAIN-SUFFIX,anthropic.com,CHAIN" == r for r in rs.rules)


def test_resolve_and_build_default():
    rs, plugins, label = resolve_rules_source("default")
    assert rs is not None
    assert plugins is None
    assert label.startswith("preset:")

    hop1 = {
        "name": "2x专线-日本-2",
        "type": "anytls",
        "server": "v4-aws-jp2.example.com",
        "port": 7001,
        "password": "x",
        "udp": True,
        "sni": "127.0.0.1",
        "skip-cert-verify": True,
        "client-fingerprint": "chrome",
    }
    hop2 = parse_hop2("1.2.3.4 1080 user pass")
    cfg = build_chain_config(
        hop1,
        hop2,
        ruleset=rs,
        exit_ip="1.2.3.4",
        strict_leak_protection=False,
    )
    assert cfg["rules"][-1] == "MATCH,HOP1"
    assert any(g["name"] == "CHAIN" for g in cfg["proxy-groups"])
    assert any(g["name"] == "HOP1" for g in cfg["proxy-groups"])
    chain = next(g for g in cfg["proxy-groups"] if g["name"] == "CHAIN")
    assert chain["proxies"][-1] == "REJECT"
    assert any("anthropic.com" in r and r.endswith(",CHAIN") for r in cfg["rules"])
    assert any("bilibili.com" in r and ",DIRECT" in r for r in cfg["rules"])
    msg = validate_config_file(cfg)
    assert "successful" in msg.lower() or msg.startswith("skip")


if __name__ == "__main__":
    test_materialize_no_resolve()
    test_default_preset_merge()
    test_adhoc_packs()
    test_resolve_and_build_default()
    print("all ok")
