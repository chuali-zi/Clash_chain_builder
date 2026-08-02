"""Unit tests for order-agnostic hop2 parsing."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chain_builder.hop2 import parse_hop2, swap_user_pass


def test_ipdeep_colon():
    c = parse_hop2("proxy.ipdeep.com:7085:stcPCTUzAJ0qE:stcvuWV0eVkF8")
    assert c.server == "proxy.ipdeep.com"
    assert c.port == 7085
    assert c.username == "stcPCTUzAJ0qE"
    assert c.password == "stcvuWV0eVkF8"


def test_space_any_order():
    a = parse_hop2("1.2.3.4 1080 alice secret")
    b = parse_hop2("secret alice 1080 1.2.3.4")
    assert a.server == b.server == "1.2.3.4"
    assert a.port == b.port == 1080
    assert a.username == "alice" and a.password == "secret"
    assert b.username == "secret" and b.password == "alice"
    swapped = swap_user_pass(b)
    assert swapped.username == "alice" and swapped.password == "secret"


def test_colon_and_at():
    a = parse_hop2("1.2.3.4:1080:alice:secret")
    b = parse_hop2("alice:secret@1.2.3.4:1080")
    assert a.server == b.server == "1.2.3.4"
    assert a.username == b.username == "alice"
    assert a.password == b.password == "secret"


def test_socks_url():
    a = parse_hop2("socks5://alice:secret@proxy.ipdeep.com:7085")
    assert a.server == "proxy.ipdeep.com"
    assert a.port == 7085
    assert a.username == "alice"
    assert a.password == "secret"
    b = parse_hop2("socks5://proxy.ipdeep.com:7085:alice:secret")
    assert b.server == "proxy.ipdeep.com"
    assert b.username == "alice"
    assert b.password == "secret"


def test_password_with_colon():
    c = parse_hop2("1.2.3.4:1080:alice:sec:ret")
    assert c.username == "alice"
    assert c.password == "sec:ret"


def test_labeled():
    c = parse_hop2("pass=secret port=7085 user=alice ip=10.0.0.1")
    assert c.server == "10.0.0.1"
    assert c.port == 7085
    assert c.username == "alice"
    assert c.password == "secret"


def test_gateway_plus_exit_hint():
    c = parse_hop2("167.253.38.151 proxy.ipdeep.com 7085 alice secret")
    assert c.server == "proxy.ipdeep.com"
    assert c.exit_ip_hint == "167.253.38.151"
    assert c.username == "alice"
    assert c.password == "secret"


def test_trailing_whitespace_and_quotes():
    c = parse_hop2('  "proxy.ipdeep.com:7085:stcPCTUzAJ0qE:stcvuWV0eVkF8"  ')
    assert c.server == "proxy.ipdeep.com"
    assert c.port == 7085


def test_semicolon_csv():
    c = parse_hop2("proxy.ipdeep.com;7085;alice;secret")
    assert c.server == "proxy.ipdeep.com"
    assert c.port == 7085
    assert c.username == "alice"


if __name__ == "__main__":
    test_ipdeep_colon()
    test_space_any_order()
    test_colon_and_at()
    test_socks_url()
    test_password_with_colon()
    test_labeled()
    test_gateway_plus_exit_hint()
    test_trailing_whitespace_and_quotes()
    test_semicolon_csv()
    print("all ok")
