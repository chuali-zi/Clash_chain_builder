import yaml
from pathlib import Path

root = Path(__file__).parent
packs = list((root / "packs").glob("*.yaml"))
presets = list((root / "presets").glob("*.yaml"))
print("=== PACKS ===")
total_rules = 0
for p in sorted(packs):
    d = yaml.safe_load(p.read_text(encoding="utf-8"))
    n = len(d.get("rules") or [])
    total_rules += n
    dns = len(d.get("dns_policy_keys") or [])
    sn = len(d.get("sniffer_force_domain") or [])
    print(
        f"{d['id']:28} target={d['target']:6} pri={d['priority']:3} "
        f"rules={n:4} dns={dns:3} sniffer={sn:3}"
    )
print(f"Total pack rules: {total_rules}")
print("=== PRESETS ===")
for p in sorted(presets):
    d = yaml.safe_load(p.read_text(encoding="utf-8"))
    print(f"{d['id']:20} compose={d['compose']} match={d['match']}")
ids = yaml.safe_load((root / "presets/default.yaml").read_text(encoding="utf-8"))["compose"]
seen = set()
for pid in ids:
    d = yaml.safe_load((root / "packs" / f"{pid}.yaml").read_text(encoding="utf-8"))
    for r in d["rules"]:
        seen.add(r)
print(f"default preset unique rules: {len(seen)}")
