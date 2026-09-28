"""full-chain mode: MATCH,CHAIN, Verge-friendly YAML, DNS via CHAIN."""
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


def _full_chain_cfg():
    ruleset, _, _ = resolve_rules_source("full-chain")
    return build_chain_config(
        HOP1,
        _hop2(),
        ruleset=ruleset,
        exit_ip="1.2.3.4",
    )


def _group(cfg: dict, name: str) -> dict:
    return next(g for g in cfg["proxy-groups"] if g["name"] == name)


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
    cfg = _full_chain_cfg()
    assert cfg["rules"] == ["MATCH,CHAIN"]
    assert cfg["mode"] == "rule"


def test_full_chain_does_not_embed_tun():
    """Verge owns the TUN toggle; YAML must not force tun.enable true."""
    cfg = _full_chain_cfg()
    tun = cfg.get("tun")
    assert tun is None or tun.get("enable") is False
    assert "strict-route" not in (tun or {})


def test_full_chain_matches_airport_lan_bind():
    cfg = _full_chain_cfg()
    assert cfg["allow-lan"] is True
    assert cfg["bind-address"] == "*"


def test_full_chain_global_select_defaults_to_chain():
    """Clash Verge Global mode uses GLOBAL; first entry must be CHAIN."""
    cfg = _full_chain_cfg()
    groups = {g["name"]: g for g in cfg["proxy-groups"]}
    assert "HOP1" not in groups
    assert "CHAIN" in groups
    global_g = groups["GLOBAL"]
    assert global_g["type"] == "select"
    assert global_g["proxies"][0] == "CHAIN"
    assert HOP1["name"] in global_g["proxies"]
    chain = groups["CHAIN"]
    assert chain["type"] == "select"
    hop2 = next(p for p in cfg["proxies"] if p["type"] == "socks5")
    assert chain["proxies"] == [hop2["name"]]
    assert hop2.get("udp") is False
    assert "DIRECT" not in chain["proxies"]
    assert HOP1["name"] not in chain["proxies"]
    assert "REJECT" not in chain["proxies"]
    assert "geox-url" not in cfg


def test_full_chain_dns_uses_direct_doh():
    cfg = _full_chain_cfg()
    dns = cfg["dns"]
    assert dns["respect-rules"] is True
    assert dns["enhanced-mode"] == "fake-ip"
    # DoH must not ride CHAIN: a hop1 blip would kill DNS and look like "节点断了".
    assert all("#CHAIN" not in str(r) for r in dns["nameserver"])
    assert all("#DIRECT" in str(r) for r in dns["nameserver"])
    assert not dns.get("nameserver-policy")
    hop2 = next(p for p in cfg["proxies"] if p["type"] == "socks5")
    hop1 = next(p for p in cfg["proxies"] if p["name"] == HOP1["name"])
    assert hop2["dialer-proxy"] == hop1["name"]


def test_generated_config_keeps_mihomo_tcp_keepalive_defaults():
    """Non-zero overrides make AnyTLS unstable under Clash Verge TUN."""
    cfg = _full_chain_cfg()
    assert "keep-alive-interval" not in cfg
    assert "keep-alive-idle" not in cfg
    assert "disable-keep-alive" not in cfg
    chain = _group(cfg, "CHAIN")
    assert chain["type"] == "select"
    assert "url" not in chain

    default_rs, _, _ = resolve_rules_source("default")
    default_cfg = build_chain_config(
        HOP1, _hop2(), ruleset=default_rs, exit_ip="1.2.3.4",
        strict_leak_protection=False,
    )
    assert "keep-alive-interval" not in default_cfg
    assert "keep-alive-idle" not in default_cfg
    assert "disable-keep-alive" not in default_cfg
    default_chain = _group(default_cfg, "CHAIN")
    assert default_chain["type"] == "fallback"
    assert default_chain["interval"] >= 300


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
    cfg = _full_chain_cfg()
    msg = validate_config_file(cfg)
    assert "successful" in msg.lower() or msg.startswith("skip")


if __name__ == "__main__":
    test_resolve_full_chain_preset()
    test_full_chain_rules_are_match_only()
    test_full_chain_does_not_embed_tun()
    test_full_chain_matches_airport_lan_bind()
    test_full_chain_global_select_defaults_to_chain()
    test_full_chain_dns_uses_direct_doh()
    test_cli_full_chain_is_strict()
    test_full_chain_validates_with_mihomo()
    print("all ok")
