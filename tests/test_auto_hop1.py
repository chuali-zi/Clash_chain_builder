"""The optional full-chain-auto preset chooses its first hop at runtime."""
from __future__ import annotations

import pytest
from argparse import Namespace

from chain_builder.builder import build_chain_config, resolve_rules_source
from chain_builder.cli import _prepare_hop1, apply_mode_flags, build_parser, resolve_output_path
from chain_builder.hop2 import parse_hop2


NODES = [
    {"name": "airport-a", "type": "ss", "server": "a.example.com", "port": 443,
     "cipher": "aes-128-gcm", "password": "one"},
    {"name": "airport-b", "type": "ss", "server": "b.example.com", "port": 443,
     "cipher": "aes-128-gcm", "password": "two"},
]


def test_auto_hop1_dials_via_latency_group():
    ruleset, _, _ = resolve_rules_source("full-chain-auto")
    cfg = build_chain_config(
        NODES[0], parse_hop2("1.2.3.4 1080 user pass"),
        ruleset=ruleset, exit_ip="1.2.3.4", hop1_candidates=NODES,
    )
    groups = {g["name"]: g for g in cfg["proxy-groups"]}
    hop2 = cfg["proxies"][0]
    assert hop2["dialer-proxy"] == "HOP1-AUTO"
    assert [p["name"] for p in cfg["proxies"][1:]] == ["airport-a", "airport-b"]
    assert groups["HOP1-AUTO"]["type"] == "url-test"
    assert groups["HOP1-AUTO"]["proxies"] == ["airport-a", "airport-b"]
    assert groups["HOP1-AUTO"]["interval"] == 300
    assert groups["CHAIN"]["proxies"] == [hop2["name"]]
    assert cfg["rules"] == ["MATCH,CHAIN"]


def test_auto_hop1_requires_candidates():
    ruleset, _, _ = resolve_rules_source("full-chain-auto")
    with pytest.raises(ValueError, match="机场节点列表"):
        build_chain_config(NODES[0], parse_hop2("1.2.3.4 1080 user pass"), ruleset=ruleset)


def test_auto_mode_filters_candidates_and_uses_separate_filename():
    args = Namespace(
        preset="full-chain-auto", filter="airport-b", no_latency=True, hop1=None,
        out=None, name=None, out_dir=None,
    )
    selected, candidates = _prepare_hop1(NODES, args)
    assert selected["name"] == "airport-b"
    assert candidates == [NODES[1]]
    assert resolve_output_path(args, "1.2.3.4", "US").name == "1.2.3.4_US_full-chain-auto.yaml"


def test_auto_preset_is_selectable_from_cli():
    args = apply_mode_flags(build_parser().parse_args(["--preset", "full-chain-auto"]))
    assert args.preset == "full-chain-auto"
