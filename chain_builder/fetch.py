"""Fetch airport subscription with Clash User-Agent."""
from __future__ import annotations

import time

import requests
import yaml

CLASH_UA = "clash-verge/v2.0.0"
DEFAULT_TIMEOUT = 30
FETCH_RETRIES = 3


def fetch_subscription(url: str) -> str:
    sep = "&" if "?" in url else "?"
    target = url if "flag=" in url else f"{url}{sep}flag=clash"
    last_err: Exception | None = None
    for attempt in range(FETCH_RETRIES):
        try:
            resp = requests.get(
                target,
                headers={"User-Agent": CLASH_UA},
                timeout=DEFAULT_TIMEOUT,
            )
            resp.raise_for_status()
            text = resp.text
            if "proxies:" not in text:
                raise RuntimeError("响应不像 Clash YAML（缺少 proxies:）")
            return text
        except (
            requests.exceptions.SSLError,
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            RuntimeError,
        ) as e:
            last_err = e
            if attempt < FETCH_RETRIES - 1:
                time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"拉取订阅失败（{FETCH_RETRIES} 次）: {last_err}")


def parse_subscription(text: str) -> dict:
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or "proxies" not in data:
        raise RuntimeError("解析结果缺少 proxies")
    if not isinstance(data["proxies"], list) or not data["proxies"]:
        raise RuntimeError("proxies 为空")
    return data


def fetch_and_parse(url: str) -> dict:
    return parse_subscription(fetch_subscription(url))
