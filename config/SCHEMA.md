# Config Pack Schema

```yaml
id: string                 # 唯一 ID，presets.compose 引用此值
name: string               # 展示名
version: int               # 内容版本
target: hop2|hop1|direct   # 本包规则命中后的出口
priority: int              # 越大越靠前（建议：process/hop2 300+，direct 100，geosite 50）
description: string
sources: [string]          # 调研来源备注

rules:                     # Clash classical 规则，不含策略后缀
  - PROCESS-NAME,claude.exe
  - DOMAIN-SUFFIX,anthropic.com
  - GEOSITE,ANTHROPIC
  - IP-CIDR,10.0.0.0/8,no-resolve   # IP 规则可自带 no-resolve

dns_policy_keys:           # 将来写入 dns.nameserver-policy 的 key
  - +.anthropic.com
  - geosite:ANTHROPIC

sniffer_force_domain:      # 将来写入 sniffer.force-domain
  - +.anthropic.com

# 可选
notes: |
  人类可读说明
```

## Preset Schema

```yaml
id: string
name: string
description: string
compose:                   # pack id 列表（也可依赖 priority 自动排序）
  - private-direct
  - anthropic
match: hop1|hop2|direct|reject
```
