"""Load and merge composable rule packs from config/."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import yaml

DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

VALID_TARGETS = {"hop2", "hop1", "direct", "reject"}
VALID_MATCH = {"hop2", "hop1", "direct", "reject", "chain"}

TARGET_TO_GROUP = {
    "hop2": "CHAIN",
    "chain": "CHAIN",
    "hop1": "HOP1",
    "direct": "DIRECT",
    "reject": "REJECT",
}


@dataclass
class RulePack:
    id: str
    name: str
    target: str
    priority: int
    version: int = 1
    description: str = ""
    rules: list[str] = field(default_factory=list)
    dns_policy_keys: list[str] = field(default_factory=list)
    sniffer_force_domain: list[str] = field(default_factory=list)
    path: Path | None = None

    @classmethod
    def from_dict(cls, data: dict, path: Path | None = None) -> "RulePack":
        if not isinstance(data, dict):
            raise ValueError(f"规则包必须是 mapping: {path}")
        pid = data.get("id")
        if not pid:
            raise ValueError(f"规则包缺少 id: {path}")
        target = str(data.get("target", "")).lower()
        if target not in VALID_TARGETS:
            raise ValueError(
                f"规则包 {pid} 的 target 无效: {target!r}（可选 {sorted(VALID_TARGETS)}）"
            )
        rules = data.get("rules") or []
        if not isinstance(rules, list):
            raise ValueError(f"规则包 {pid} 的 rules 必须是列表")
        return cls(
            id=str(pid),
            name=str(data.get("name") or pid),
            target=target,
            priority=int(data.get("priority") or 0),
            version=int(data.get("version") or 1),
            description=str(data.get("description") or "").strip(),
            rules=[str(r).strip() for r in rules if str(r).strip()],
            dns_policy_keys=[
                str(k).strip() for k in (data.get("dns_policy_keys") or []) if str(k).strip()
            ],
            sniffer_force_domain=[
                str(k).strip()
                for k in (data.get("sniffer_force_domain") or [])
                if str(k).strip()
            ],
            path=path,
        )


@dataclass
class Preset:
    id: str
    name: str
    compose: list[str]
    match: str = "hop1"
    description: str = ""
    path: Path | None = None

    @classmethod
    def from_dict(cls, data: dict, path: Path | None = None) -> "Preset":
        if not isinstance(data, dict):
            raise ValueError(f"预设必须是 mapping: {path}")
        pid = data.get("id")
        if not pid:
            raise ValueError(f"预设缺少 id: {path}")
        compose = data.get("compose") or []
        if not isinstance(compose, list) or not compose:
            raise ValueError(f"预设 {pid} 的 compose 不能为空")
        match = str(data.get("match") or "hop1").lower()
        if match == "chain":
            match = "hop2"
        if match not in VALID_MATCH:
            raise ValueError(
                f"预设 {pid} 的 match 无效: {match!r}（可选 {sorted(VALID_MATCH)}）"
            )
        return cls(
            id=str(pid),
            name=str(data.get("name") or pid),
            compose=[str(x).strip() for x in compose if str(x).strip()],
            match=match,
            description=str(data.get("description") or "").strip(),
            path=path,
        )


@dataclass
class MergedRuleset:
    """Materialized rules ready for mihomo YAML."""

    rules: list[str]
    dns_nameserver_policy: dict[str, list[str]]
    sniffer_force_domains: list[str]
    match: str  # hop1|hop2|direct|reject
    pack_ids: list[str]
    preset_id: str | None = None
    uses_direct: bool = False
    uses_hop1: bool = False

    @property
    def match_group(self) -> str:
        return TARGET_TO_GROUP[self.match]

    @property
    def is_split_routing(self) -> bool:
        """True when traffic may leave CHAIN (DIRECT / HOP1 / reject match)."""
        return self.uses_direct or self.match != "hop2"


def config_dir(root: Path | None = None) -> Path:
    return Path(root) if root else DEFAULT_CONFIG_DIR


def _load_yaml(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"YAML 根节点必须是 mapping: {path}")
    return data


def list_pack_files(root: Path | None = None) -> list[Path]:
    d = config_dir(root) / "packs"
    if not d.is_dir():
        return []
    return sorted(d.glob("*.yaml")) + sorted(d.glob("*.yml"))


def list_preset_files(root: Path | None = None) -> list[Path]:
    d = config_dir(root) / "presets"
    if not d.is_dir():
        return []
    return sorted(d.glob("*.yaml")) + sorted(d.glob("*.yml"))


def load_pack(path: Path) -> RulePack:
    return RulePack.from_dict(_load_yaml(path), path=path)


def load_preset(path: Path) -> Preset:
    return Preset.from_dict(_load_yaml(path), path=path)


def load_all_packs(root: Path | None = None) -> dict[str, RulePack]:
    out: dict[str, RulePack] = {}
    for path in list_pack_files(root):
        pack = load_pack(path)
        if pack.id in out:
            raise ValueError(f"重复的规则包 id: {pack.id} ({path} vs {out[pack.id].path})")
        out[pack.id] = pack
    return out


def load_all_presets(root: Path | None = None) -> dict[str, Preset]:
    out: dict[str, Preset] = {}
    for path in list_preset_files(root):
        preset = load_preset(path)
        if preset.id in out:
            raise ValueError(f"重复的预设 id: {preset.id}")
        out[preset.id] = preset
    return out


def get_pack(pack_id: str, root: Path | None = None) -> RulePack:
    packs = load_all_packs(root)
    if pack_id not in packs:
        known = ", ".join(sorted(packs)) or "(无)"
        raise KeyError(f"未知规则包 '{pack_id}'，可选: {known}")
    return packs[pack_id]


def get_preset(preset_id: str, root: Path | None = None) -> Preset:
    presets = load_all_presets(root)
    if preset_id not in presets:
        known = ", ".join(sorted(presets)) or "(无)"
        raise KeyError(f"未知预设 '{preset_id}'，可选: {known}")
    return presets[preset_id]


def materialize_rule(rule: str, policy: str) -> str:
    """Append policy to a pack rule line.

    Handles trailing no-resolve:
      IP-CIDR,10.0.0.0/8,no-resolve → IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
    """
    rule = rule.strip()
    if not rule:
        raise ValueError("空规则")
    parts = [p.strip() for p in rule.split(",")]
    # Already has a known policy? keep as-is (advanced escape hatch)
    known = {"DIRECT", "REJECT", "CHAIN", "HOP1", "PROXY"}
    if parts[-1] in known:
        return rule
    if len(parts) >= 2 and parts[-1] == "no-resolve":
        # GEOIP,CN,no-resolve or IP-CIDR,...,no-resolve
        if parts[-2] in known:
            return rule
        return ",".join(parts[:-1] + [policy, "no-resolve"])
    return f"{rule},{policy}"


def _dns_resolvers_for(policy_group: str) -> list[str]:
    if policy_group in {"DIRECT", "REJECT"}:
        return []
    return [
        f"https://223.5.5.5/dns-query#{policy_group}&skip-cert-verify=true",
        f"https://doh.pub/dns-query#{policy_group}&skip-cert-verify=true",
    ]


def merge_packs(
    pack_ids: Iterable[str],
    *,
    match: str = "hop1",
    root: Path | None = None,
    preset_id: str | None = None,
    extra_rules: list[str] | None = None,
) -> MergedRuleset:
    """Merge packs by priority (desc), materialize policies, dedupe rules."""
    match = "hop2" if match == "chain" else match
    if match not in VALID_MATCH:
        raise ValueError(f"无效 match: {match}")

    packs_db = load_all_packs(root)
    selected: list[RulePack] = []
    for pid in pack_ids:
        if pid not in packs_db:
            known = ", ".join(sorted(packs_db)) or "(无)"
            raise KeyError(f"未知规则包 '{pid}'，可选: {known}")
        selected.append(packs_db[pid])

    selected.sort(key=lambda p: (-p.priority, p.id))

    rules: list[str] = []
    seen_rules: set[str] = set()
    dns_policy: dict[str, list[str]] = {}
    sniffer: list[str] = []
    seen_sniffer: set[str] = set()
    uses_direct = False
    uses_hop1 = match == "hop1"

    for pack in selected:
        policy = TARGET_TO_GROUP[pack.target]
        if pack.target == "direct":
            uses_direct = True
        if pack.target == "hop1":
            uses_hop1 = True

        for raw in pack.rules:
            line = materialize_rule(raw, policy)
            if line in seen_rules:
                continue
            seen_rules.add(line)
            rules.append(line)

        resolvers = _dns_resolvers_for(policy)
        if resolvers:
            for key in pack.dns_policy_keys:
                # First writer wins (higher priority pack already processed)
                dns_policy.setdefault(key, list(resolvers))

        for dom in pack.sniffer_force_domain:
            if dom not in seen_sniffer:
                seen_sniffer.add(dom)
                sniffer.append(dom)

    if extra_rules:
        for raw in extra_rules:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # custom rules are expected to already include policy
            if line in seen_rules:
                continue
            seen_rules.add(line)
            rules.append(line)
            # detect policies for flags
            fields = [p.strip() for p in line.split(",")]
            pol = fields[-2] if fields[-1] == "no-resolve" else fields[-1]
            if pol == "DIRECT":
                uses_direct = True
            if pol == "HOP1":
                uses_hop1 = True

    return MergedRuleset(
        rules=rules,
        dns_nameserver_policy=dns_policy,
        sniffer_force_domains=sniffer,
        match=match,
        pack_ids=[p.id for p in selected],
        preset_id=preset_id,
        uses_direct=uses_direct,
        uses_hop1=uses_hop1,
    )


def merge_preset(preset_id: str, *, root: Path | None = None,
                 extra_rules: list[str] | None = None) -> MergedRuleset:
    preset = get_preset(preset_id, root=root)
    return merge_packs(
        preset.compose,
        match=preset.match,
        root=root,
        preset_id=preset.id,
        extra_rules=extra_rules,
    )


def resolve_preset_name(name: str, root: Path | None = None) -> str | None:
    """Return config preset id if `name` matches a preset file, else None."""
    presets = load_all_presets(root)
    key = name.strip().lower()
    for pid in presets:
        if pid.lower() == key:
            return pid
    return None
