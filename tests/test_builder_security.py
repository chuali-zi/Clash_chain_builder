"""Security invariants for generated fail-closed configurations."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chain_builder.builder import build_chain_config
from chain_builder.hop2 import Hop2Creds
from chain_builder.plugins.registry import get_plugin
from chain_builder import verify


HOP1 = {
    "name": "airport-jp-1",
    "type": "ss",
    "server": "hop1.example.com",
    "port": 443,
    "cipher": "aes-128-gcm",
    "password": "hop1-secret",
}
HOP2 = Hop2Creds("198.51.100.20", 1080, "user", "pass")


def test_strict_config_has_no_bypass_path():
    cfg = build_chain_config(
        HOP1,
        HOP2,
        plugins=[get_plugin("anthropic")],
        match_default="hop1",
    )

    assert cfg["tun"]["enable"] is True
    assert cfg["tun"]["strict-route"] is True
    assert cfg["allow-lan"] is False
    assert cfg["bind-address"] == "127.0.0.1"
    assert cfg["rules"][-1] == "MATCH,CHAIN"
    assert {group["name"] for group in cfg["proxy-groups"]} == {"CHAIN"}

    hop2 = cfg["proxies"][0]
    assert hop2["dialer-proxy"] == cfg["proxies"][1]["name"]
    assert hop2["dialer-proxy"].startswith("__HOP1_")
    assert cfg["proxy-groups"][0]["proxies"] == [hop2["name"], "REJECT"]
    assert all("#CHAIN" in resolver for resolver in cfg["dns"]["nameserver"])


def test_strict_config_rejects_public_direct_custom_rule():
    with pytest.raises(ValueError, match="旁路规则"):
        build_chain_config(
            HOP1,
            HOP2,
            custom_rules=["DOMAIN,claude.ai,DIRECT"],
        )


def test_split_routing_requires_explicit_opt_out():
    cfg = build_chain_config(
        HOP1,
        HOP2,
        plugins=[get_plugin("anthropic")],
        match_default="hop1",
        strict_leak_protection=False,
    )

    assert "tun" not in cfg
    assert cfg["rules"][-1] == "MATCH,HOP1"
    assert "HOP1" in {group["name"] for group in cfg["proxy-groups"]}


class _DummyMihomo:
    proxy_url = "http://127.0.0.1:7890"

    def __init__(self, _cfg):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass


def test_broken_hop2_expected_disconnect_passes(monkeypatch):
    monkeypatch.setattr(verify, "MihomoTemp", _DummyMihomo)

    def disconnected(*_args, **_kwargs):
        raise requests.exceptions.ProxyError("closed")

    monkeypatch.setattr(verify.requests, "get", disconnected)
    verify._verify_broken_hop2_is_closed(HOP1, HOP2)


def test_broken_hop2_any_public_response_fails(monkeypatch):
    monkeypatch.setattr(verify, "MihomoTemp", _DummyMihomo)
    monkeypatch.setattr(
        verify.requests,
        "get",
        lambda *_args, **_kwargs: SimpleNamespace(text="blocked", status_code=403),
    )

    with pytest.raises(RuntimeError, match="仍可访问公网"):
        verify._verify_broken_hop2_is_closed(HOP1, HOP2)
