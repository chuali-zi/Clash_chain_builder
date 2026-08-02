"""IP geolocation helpers for output filename."""
from __future__ import annotations

import re

import requests

SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def lookup_country(ip: str, timeout: float = 8.0) -> str:
    """Return short country/region code for naming, e.g. US / JP / HK."""
    # ip-api.com — free, no key, HTTP
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,countryCode,regionName,city",
            timeout=timeout,
        )
        data = r.json()
        if data.get("status") == "success" and data.get("countryCode"):
            code = data["countryCode"]
            region = data.get("regionName") or data.get("city") or ""
            # Keep filename compact: IP_US or IP_US-California
            if region and region.replace(" ", "") and len(region) <= 24:
                slug = SAFE_NAME_RE.sub("-", region).strip("-")
                return f"{code}-{slug}" if slug else code
            return code
    except Exception:
        pass

    # fallback
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=timeout)
        data = r.json()
        code = data.get("country") or "UNKNOWN"
        region = data.get("region") or data.get("city") or ""
        if region:
            slug = SAFE_NAME_RE.sub("-", region).strip("-")
            return f"{code}-{slug}" if slug else code
        return code
    except Exception:
        return "UNKNOWN"


def output_filename(exit_ip: str, country: str | None = None) -> str:
    country = country or lookup_country(exit_ip)
    country = SAFE_NAME_RE.sub("-", country).strip("-") or "UNKNOWN"
    ip_part = SAFE_NAME_RE.sub("-", exit_ip).strip("-")
    return f"{ip_part}_{country}.yaml"
