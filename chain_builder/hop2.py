"""Order-agnostic parser for hop2 SOCKS5 credentials."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
# host.example.com / proxy.ipdeep.com (require at least one dot)
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
)
# Single-label hostname like "localhost" or provider short names
HOST_LOOSE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
IPV6_BRACKET_RE = re.compile(
    r"^\[(?P<ip>[0-9a-fA-F:]+)\]:(?P<port>\d+):(?P<a>[^:]+):(?P<b>.+)$"
)
LABEL_RE = re.compile(
    r"^(?P<key>ip|host|server|port|user|username|pass|password|pwd)\s*[=:]\s*(?P<val>.+)$",
    re.IGNORECASE,
)
USER_PASS_AT_RE = re.compile(
    r"^(?P<user>[^:@\s]+):(?P<password>[^@\s]+)@(?P<host>\[[^\]]+\]|[^:\s]+):(?P<port>\d+)$"
)
# Classic provider paste: host:port:user:pass  (host may be ipv4 or domain)
COLON4_RE = re.compile(
    r"^(?P<host>\[[^\]]+\]|(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})"
    r":(?P<port>\d{1,5})"
    r":(?P<a>[^:\s]+)"
    r":(?P<b>.+)$"
)


@dataclass
class Hop2Creds:
    server: str
    port: int
    username: str
    password: str
    # Sticky/exit IP when server is a gateway hostname
    exit_ip_hint: str | None = None

    def as_dict(self) -> dict:
        return {
            "server": self.server,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "exit_ip_hint": self.exit_ip_hint,
        }


def _strip_scheme(raw: str) -> str:
    s = raw.strip().strip("'\"")
    # socks5:// socks5h:// socks:// http:// https://
    for prefix in (
        "socks5h://",
        "socks5://",
        "socks4a://",
        "socks4://",
        "socks://",
        "http://",
        "https://",
    ):
        if s.lower().startswith(prefix):
            return s[len(prefix) :]
    return s


def _try_url_parse(raw: str) -> Hop2Creds | None:
    """Parse socks5://user:pass@host:port or socks5://host:port:user:pass."""
    text = raw.strip().strip("'\"")
    if "://" not in text:
        return None
    # Normalize bare scheme variants
    lower = text.lower()
    if lower.startswith("socks5h://"):
        text = "socks5://" + text.split("://", 1)[1]
    elif lower.startswith("socks://") or lower.startswith("socks4"):
        text = "socks5://" + text.split("://", 1)[1]

    # Form: scheme://host:port:user:pass (non-standard but common in residential paste)
    after = text.split("://", 1)[1]
    if "@" not in after:
        got = _try_colon4(after)
        if got is not None:
            return got

    try:
        u = urlparse(text if "://" in text else f"socks5://{text}")
    except Exception:
        return None
    if not u.hostname or not u.port:
        return None
    user = unquote(u.username or "")
    password = unquote(u.password or "")
    if not user or not password:
        return None
    return Hop2Creds(
        server=u.hostname,
        port=int(u.port),
        username=user,
        password=password,
    )


def _try_colon4(raw: str) -> Hop2Creds | None:
    """host:port:user:pass / ip:port:user:pass / [ipv6]:port:user:pass."""
    s = _strip_scheme(raw).strip()
    m = IPV6_BRACKET_RE.match(s)
    if m:
        return Hop2Creds(
            server=m.group("ip"),
            port=int(m.group("port")),
            username=unquote(m.group("a")),
            password=unquote(m.group("b")),
        )
    m = COLON4_RE.match(s)
    if not m:
        # Fallback: split into 4 parts (password may contain ':')
        if s.count(":") >= 3 and "=" not in s and "@" not in s:
            host, port_s, user, password = s.split(":", 3)
            if _is_port(port_s) and host and user and password:
                return Hop2Creds(
                    server=host.strip("[]"),
                    port=int(port_s),
                    username=unquote(user),
                    password=unquote(password),
                )
        return None
    if not _is_port(m.group("port")):
        return None
    return Hop2Creds(
        server=m.group("host").strip("[]"),
        port=int(m.group("port")),
        username=unquote(m.group("a")),
        password=unquote(m.group("b")),
    )


def _try_user_pass_at(raw: str) -> Hop2Creds | None:
    s = _strip_scheme(raw).replace(" ", "")
    m = USER_PASS_AT_RE.match(s)
    if not m:
        return None
    host = m.group("host").strip("[]")
    return Hop2Creds(
        server=host,
        port=int(m.group("port")),
        username=unquote(m.group("user")),
        password=unquote(m.group("password")),
    )


def _tokenize(raw: str) -> list[str]:
    raw = raw.strip().strip("'\"")
    if not raw:
        return []
    # Normalize whitespace / separators for free-form input
    # Keep labeled key=val / key:val intact when possible
    if re.search(r"\b(ip|host|server|port|user|username|pass|password|pwd)\s*[=:]", raw, re.I):
        # Split on whitespace / commas / semicolons only
        parts = re.split(r"[\s,;]+", raw)
        return [p for p in parts if p]

    compact = raw.replace(" ", "")
    m = USER_PASS_AT_RE.match(compact)
    if m:
        return [
            f"user={m.group('user')}",
            f"pass={m.group('password')}",
            f"host={m.group('host').strip('[]')}",
            f"port={m.group('port')}",
        ]

    # host:port:user:pass — prefer structured parse upstream; tokenize as 4 fields
    if ":" in raw and "=" not in raw and "@" not in raw:
        # password may contain colon → split max 3 times from left after host:port
        m4 = COLON4_RE.match(_strip_scheme(raw).strip())
        if m4:
            return [
                m4.group("host").strip("[]"),
                m4.group("port"),
                m4.group("a"),
                m4.group("b"),
            ]
        parts = [p for p in raw.split(":") if p != ""]
        if len(parts) == 4:
            return parts
        if len(parts) > 4:
            # ip:port:user:pass:with:colons
            return [parts[0], parts[1], parts[2], ":".join(parts[3:])]

    if "," in raw and "=" not in raw:
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        if len(parts) >= 4:
            return parts[:3] + [",".join(parts[3:])] if len(parts) > 4 else parts
    if ";" in raw and "=" not in raw:
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        if len(parts) >= 4:
            return parts[:3] + [";".join(parts[3:])] if len(parts) > 4 else parts

    return re.split(r"[\s]+", raw.strip())


def _is_port(token: str) -> bool:
    if not token or not token.isdigit():
        return False
    return 1 <= int(token) <= 65535


def _is_server_token(token: str) -> bool:
    t = token.strip("[]")
    return bool(IPV4_RE.match(t) or HOST_RE.match(t) or (HOST_LOOSE_RE.match(t) and not _is_port(t)))


def _uniq(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def parse_hop2(raw: str) -> Hop2Creds:
    """Parse hop2 credentials in any field order / common paste formats.

    Accepted forms (non-exhaustive):
      - host:port:user:pass          (e.g. proxy.ipdeep.com:7085:u:p)
      - ip:port:user:pass
      - user:pass@host:port
      - socks5://user:pass@host:port
      - socks5://host:port:user:pass
      - ip port user pass             (any order)
      - host port user pass
      - ip host port user pass        (exit IP hint + gateway)
      - ip=x port=y user=z pass=w
      - [ipv6]:port:user:pass
    """
    raw = raw.strip().strip("'\"")
    if not raw:
        raise ValueError("空的第二跳凭证")

    # Fast paths for the most common residential / provider paste formats
    for try_fn in (_try_url_parse, _try_user_pass_at, _try_colon4):
        try:
            got = try_fn(raw)
        except Exception:
            got = None
        if got is not None:
            return got

    tokens = _tokenize(raw)
    if not tokens:
        raise ValueError("空的第二跳凭证")

    # URL-decode token values
    tokens = [unquote(t) for t in tokens]

    fields: dict[str, str] = {}
    unlabeled: list[str] = []
    for t in tokens:
        m = LABEL_RE.match(t)
        if not m:
            unlabeled.append(t.strip("[]"))
            continue
        key = m.group("key").lower()
        val = unquote(m.group("val")).strip("[]")
        if key == "ip":
            fields["ip"] = val
        elif key in ("host", "server"):
            fields["host"] = val
        elif key == "port":
            fields["port"] = val
        elif key in ("user", "username"):
            fields["user"] = val
        elif key in ("pass", "password", "pwd"):
            fields["pass"] = val

    ips: list[str] = []
    hosts: list[str] = []
    ports: list[str] = []
    others: list[str] = []

    for t in unlabeled:
        if IPV4_RE.match(t):
            ips.append(t)
        elif HOST_RE.match(t):
            hosts.append(t)
        elif _is_port(t):
            ports.append(t)
        elif HOST_LOOSE_RE.match(t) and not _is_port(t) and "." not in t:
            # ambiguous short token — treat as credential unless looks like host
            others.append(t)
        else:
            others.append(t)

    if "ip" in fields:
        (ips if IPV4_RE.match(fields["ip"]) else hosts).append(fields["ip"])
    if "host" in fields:
        (ips if IPV4_RE.match(fields["host"]) else hosts).append(fields["host"])
    if "port" in fields:
        ports.append(fields["port"])
    if "user" in fields:
        others.append(fields["user"])
    if "pass" in fields:
        others.append(fields["pass"])

    ips, hosts, ports, others = _uniq(ips), _uniq(hosts), _uniq(ports), _uniq(others)

    exit_hint: str | None = None
    server: str | None = None

    if hosts and ips:
        server = hosts[0]
        exit_hint = ips[0]
    elif ips:
        server = ips[0]
        if len(ips) > 1:
            exit_hint = ips[1]
    elif hosts:
        server = hosts[0]
    else:
        for t in unlabeled:
            if not _is_port(t) and _is_server_token(t):
                server = t.strip("[]")
                break
        if server is None:
            for t in unlabeled:
                if not _is_port(t):
                    server = t.strip("[]")
                    break

    if not server:
        raise ValueError(f"无法识别第二跳 server/IP: {raw!r}")
    if not ports:
        raise ValueError(
            f"无法识别第二跳端口: {raw!r}\n"
            "支持格式示例: host:port:user:pass  或  ip port user pass"
        )

    port = int(ports[0])
    for p in ports:
        n = int(p)
        if n >= 1024:
            port = n
            break

    user = fields.get("user")
    password = fields.get("pass")
    cred_tokens = [t for t in others if t not in {server, exit_hint} and not _is_port(t)]
    if user:
        cred_tokens = [t for t in cred_tokens if t != user]
    if password:
        cred_tokens = [t for t in cred_tokens if t != password]

    if user is None or password is None:
        if user and password is None:
            if not cred_tokens:
                raise ValueError(f"缺少 password: {raw!r}")
            password = cred_tokens[0]
        elif password and user is None:
            if not cred_tokens:
                raise ValueError(f"缺少 username: {raw!r}")
            user = cred_tokens[0]
        else:
            if len(cred_tokens) < 2:
                raise ValueError(
                    f"无法识别 username/password（需要两个凭证字段）: {raw!r}\n"
                    f"已识别 server={server} port={port} 剩余={cred_tokens}\n"
                    "推荐粘贴: host:port:user:pass"
                )
            user, password = _guess_user_pass(cred_tokens[0], cred_tokens[1], raw)

    return Hop2Creds(
        server=server,
        port=port,
        username=user,
        password=password,
        exit_ip_hint=exit_hint,
    )


def _guess_user_pass(a: str, b: str, original: str) -> tuple[str, str]:
    """Prefer original left-to-right appearance order (host:port:user:pass)."""
    ia = original.find(a)
    ib = original.find(b)
    if ia >= 0 and ib >= 0 and ia != ib:
        return (a, b) if ia < ib else (b, a)
    if len(a) != len(b):
        return (a, b) if len(a) < len(b) else (b, a)
    return a, b


def swap_user_pass(creds: Hop2Creds) -> Hop2Creds:
    return Hop2Creds(
        server=creds.server,
        port=creds.port,
        username=creds.password,
        password=creds.username,
        exit_ip_hint=creds.exit_ip_hint,
    )
