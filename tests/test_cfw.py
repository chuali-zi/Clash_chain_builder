"""CFW compatibility: routing, DNS bootstrap, conversions and target selection."""
from __future__ import annotations

import os
from contextlib import nullcontext
from argparse import Namespace

import pytest

from chain_builder import cfw
from chain_builder.builder import build_chain_config, resolve_rules_source
from chain_builder.cli import apply_mode_flags, build_parser, resolve_output_path, _prepare_hop1
from chain_builder.hop2 import Hop2Creds
from chain_builder.mihomo import MihomoTemp
from chain_builder.verify import validate_config_file

NODES = [
    {"name": "airport-a", "type": "ss", "server": "a.example.com", "port": 443,
     "cipher": "aes-128-gcm", "password": "one"},
    {"name": "airport-b", "type": "ss", "server": "b.example.com", "port": 443,
     "cipher": "aes-128-gcm", "password": "two"},
]
HOP2 = Hop2Creds("198.51.100.20", 1080, "user", "pass")


@pytest.fixture
def domain_snapshots(monkeypatch):
    monkeypatch.setattr(cfw, "load_geosite", lambda tag: {
        "anthropic": ["+.claude.ai", "+.anthropic.com"],
        "openai": ["+.openai.com", "openaiassets.blob.core.windows.net"],
        "apple-cn": ["apps.apple.com"], "cn": ["+.cn", "+.qq.com"],
    }[tag.lower()])


def config(preset="default", **kwargs):
    ruleset, plugins, _ = resolve_rules_source(preset)
    return build_chain_config(NODES[0], HOP2, plugins, ruleset=ruleset, target="cfw", **kwargs)


def test_default_preserves_split_and_expands_ai_dns(domain_snapshots):
    with pytest.warns(UserWarning, match="进程通配符"):
        cfg = config()
    groups = {g["name"]: g for g in cfg["proxy-groups"]}
    assert groups["CHAIN"]["type"] == "relay"
    assert groups["CHAIN"]["proxies"] == ["airport-a", cfg["proxies"][0]["name"]]
    assert cfg["rules"][-1] == "MATCH,HOP1"
    assert "DOMAIN-SUFFIX,claude.ai,CHAIN" in cfg["rules"]
    assert "DOMAIN-SUFFIX,qq.com,DIRECT" in cfg["rules"]
    assert not any(r.startswith(("GEOSITE,", "PROCESS-NAME-WILDCARD,", "PROCESS-PATH-REGEX,")) for r in cfg["rules"])
    policy = cfg["dns"]["nameserver-policy"]
    assert all(isinstance(v, str) for v in policy.values())
    assert policy["+.claude.ai"] == "https://1.1.1.1:10554/dns-query"
    assert policy["a.example.com"] == cfw.DIRECT_DOH
    assert not any(k.startswith("geosite:") for k in policy)
    assert "dialer-proxy" not in cfg["proxies"][0]
    assert "sniffer" not in cfg and "geox-url" not in cfg and "GLOBAL" not in groups


@pytest.mark.parametrize("auto", [False, True])
def test_full_chain_and_auto_have_chain_dns_with_direct_airport_bootstrap(auto):
    cfg = config("full-chain-auto" if auto else "full-chain", hop1_candidates=NODES if auto else None)
    assert cfg["rules"] == ["MATCH,CHAIN"]
    assert cfg["dns"]["nameserver"] == ["https://1.1.1.1:10554/dns-query"]
    assert cfg["tunnels"][0]["proxy"] == "CHAIN"
    assert cfg["hosts"] == {"1.1.1.1": "127.0.0.1"}
    assert cfg["proxies"][0]["udp"] is False
    assert cfg["mode"] == "rule" and "tun" not in cfg
    if auto:
        groups = {g["name"]: g for g in cfg["proxy-groups"]}
        assert groups["HOP1-AUTO"]["proxies"] == ["airport-a", "airport-b"]
        assert groups["CHAIN"]["proxies"][0] == "HOP1-AUTO"
        assert cfg["dns"]["nameserver-policy"]["b.example.com"] == cfw.DIRECT_DOH


def test_protocols_cannot_be_silently_downgraded():
    bad = [{**NODES[0], "type": "anytls"}, {**NODES[0], "cipher": "2022-blake3-aes-128-gcm"},
           {**NODES[0], "dialer-proxy": "DIRECT"}]
    accepted, rejected = cfw.filter_compatible_nodes(NODES + bad)
    assert accepted == NODES and len(rejected) == 3
    assert NODES[0] == cfw.compatible_node(NODES[0])


def test_custom_unsupported_rules_and_patterns_are_actionable():
    with pytest.raises(ValueError, match="自定义规则"):
        cfw.validate_custom_rules(["PROCESS-PATH-REGEX,.*claude.*,CHAIN"])
    with pytest.raises(ValueError, match="无法等价"):
        cfw.domain_rule("*.example.com", "CHAIN")
    with pytest.raises(ValueError, match="策略组冲突"):
        build_chain_config({**NODES[0], "name": "DIRECT"}, HOP2, target="cfw")


def test_private_geoip_is_explicit_cidr():
    rules = cfw.convert_rules(["GEOIP,PRIVATE,DIRECT,no-resolve", "GEOIP,CN,DIRECT,no-resolve"])
    assert "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve" in rules
    assert "IP-CIDR6,fc00::/7,DIRECT,no-resolve" in rules
    assert "GEOIP,CN,DIRECT,no-resolve" in rules
    assert not any(r.startswith("GEOIP,PRIVATE") for r in rules)


def test_cli_filenames_separate_target_and_preset():
    parser = build_parser()
    for flags, name in [(["--target", "cfw"], "1.2.3.4_US_cfw.yaml"),
                        (["--target", "cfw", "--full-chain"], "1.2.3.4_US_full-chain_cfw.yaml"),
                        (["--target", "cfw", "--preset", "full-chain-auto"], "1.2.3.4_US_full-chain-auto_cfw.yaml")]:
        args = apply_mode_flags(parser.parse_args(flags))
        assert resolve_output_path(args, "1.2.3.4", "US").name == name
    assert apply_mode_flags(parser.parse_args(["build"])).target == "mihomo"
    assert apply_mode_flags(parser.parse_args(["--target", "cfw", "build"])).target == "cfw"


def test_cfw_picker_filters_before_preselection(monkeypatch):
    from chain_builder import cfw_core
    monkeypatch.setattr(cfw_core, "find_cfw_core", lambda _: None)
    args = Namespace(target="cfw", cfw_core=None, no_verify=True, no_latency=True,
                     preset="full-chain-auto", filter=None, hop1=None)
    selected, candidates = _prepare_hop1([{**NODES[0], "type": "anytls"}, NODES[1]], args)
    assert selected == NODES[1] and candidates == [NODES[1]]


def test_temporary_core_rewrites_all_tunnel_references_without_mutating_export():
    exported = config("full-chain", cfw_dns_port=10555)
    temp = MihomoTemp(exported, binary="placeholder")
    port = temp.config["tunnels"][0]["address"].rsplit(":", 1)[1]
    assert temp.config["dns"]["nameserver"] == [f"https://1.1.1.1:{port}/dns-query"]
    assert exported["dns"]["nameserver"] == ["https://1.1.1.1:10555/dns-query"]
    assert temp.config["dns"]["nameserver-policy"]["a.example.com"] == cfw.DIRECT_DOH


@pytest.mark.skipif(not os.environ.get("CFW_BIN"), reason="Set CFW_BIN to run original Premium validation")
def test_generated_configs_load_in_original_premium(domain_snapshots):
    for preset in ("default", "full-chain", "full-chain-auto"):
        with pytest.warns(UserWarning) if preset == "default" else nullcontext():
            cfg = config(preset, hop1_candidates=NODES if preset == "full-chain-auto" else None)
        assert "successful" in validate_config_file(cfg, target="cfw").lower()
