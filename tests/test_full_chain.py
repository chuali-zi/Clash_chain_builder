"""full-chain mode: MATCH,CHAIN only, TUN on, DNS via CHAIN."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chain_builder.builder import build_chain_config, resolve_rules_source
from chain_builder.cli import _resolve_build_rules
from chain_builder.hop2 import parse_hop2
from chain_builder.verify import validate_config_file


HOP1 = {
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


def _hop2():
    return parse_hop2("1.2.3.4 1080 user pass")


def test_resolve_full_chain_preset():
    ruleset, plugins, label = resolve_rules_source("full-chain")
    assert plugins is None
    assert label == "preset:full-chain"
    assert ruleset is not None
    assert ruleset.preset_id == "full-chain"
    assert ruleset.rules == []
    assert ruleset.pack_ids == []
    assert ruleset.match == "hop2"
    assert ruleset.match_group == "CHAIN"
    assert not ruleset.is_split_routing


def test_full_chain_rules_are_match_only():
    ruleset, _, _ = resolve_rules_source("full-chain")
    cfg = build_chain_config(
        HOP1,
        _hop2(),
        ruleset=ruleset,
        exit_ip="1.2.3.4",
    )
    assert cfg["rules"] == ["MATCH,CHAIN"]
    assert cfg["mode"] == "rule"


def test_full_chain_has_tun_and_no_hop1_group():
    ruleset, _, _ = resolve_rules_source("full-chain")
    cfg = build_chain_config(
        HOP1,
        _hop2(),
        ruleset=ruleset,
        exit_ip="1.2.3.4",
    )
    assert cfg["tun"]["enable"] is True
    assert cfg["tun"]["strict-route"] is True
    assert "any:53" in cfg["tun"]["dns-hijack"]
    assert cfg["allow-lan"] is False
    assert cfg["bind-address"] == "127.0.0.1"
    assert {g["name"] for g in cfg["proxy-groups"]} == {"CHAIN"}
    chain = cfg["proxy-groups"][0]
    assert chain["type"] == "fallback"
    assert chain["proxies"][-1] == "REJECT"
    assert "geox-url" not in cfg


def test_full_chain_dns_goes_through_chain():
    ruleset, _, _ = resolve_rules_source("full-chain")
    cfg = build_chain_config(
        HOP1,
        _hop2(),
        ruleset=ruleset,
        exit_ip="1.2.3.4",
    )
    dns = cfg["dns"]
    assert dns["respect-rules"] is True
    assert dns["enhanced-mode"] == "fake-ip"
    assert all("#CHAIN" in str(r) for r in dns["nameserver"])
    assert not dns.get("nameserver-policy")
    hop2 = next(p for p in cfg["proxies"] if p["type"] == "socks5")
    hop1 = next(p for p in cfg["proxies"] if p["name"] == HOP1["name"])
    assert hop2["dialer-proxy"] == hop1["name"]


def test_cli_full_chain_is_strict():
    ns = argparse.Namespace(
        preset="full-chain",
        packs=None,
        match_default=None,
        rules_file=None,
        strict_full_chain=False,
        unsafe_split_routing=False,
    )
    ruleset, plugins, label, match_default, strict, custom = _resolve_build_rules(ns)
    assert ruleset is not None
    assert plugins is None
    assert label == "preset:full-chain"
    assert match_default == "chain"
    assert strict is True
    assert custom is None


def test_full_chain_validates_with_mihomo():
    ruleset, _, _ = resolve_rules_source("full-chain")
    cfg = build_chain_config(
        HOP1,
        _hop2(),
        ruleset=ruleset,
        exit_ip="1.2.3.4",
    )
    msg = validate_config_file(cfg)
    assert "successful" in msg.lower() or msg.startswith("skip")


if __name__ == "__main__":
    test_resolve_full_chain_preset()
    test_full_chain_rules_are_match_only()
    test_full_chain_has_tun_and_no_hop1_group()
    test_full_chain_dns_goes_through_chain()
    test_cli_full_chain_is_strict()
    test_full_chain_validates_with_mihomo()
    print("all ok")
