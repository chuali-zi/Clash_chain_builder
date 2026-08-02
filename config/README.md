# 分流规则 Config（可组合）

本目录存放**可组合的分流规则包**。由 `chain_builder/ruleset.py` 读取合并，CLI 默认 `--preset default`。

## 目录

```
config/
  README.md                 # 本说明
  SCHEMA.md                 # 字段约定
  packs/                    # 单个规则包（原子、可组合）
    private-direct.yaml     # 内网 / LAN → DIRECT
    cn-direct.yaml          # 国内常用站 → DIRECT
    anthropic.yaml          # Anthropic/Claude 一方域名 → HOP2
    anthropic-sidechannel.yaml  # Claude 侧信道（GCS/Datadog/…）→ HOP2（防漏）
    openai.yaml             # OpenAI/ChatGPT 一方域名 → HOP2
    openai-sidechannel.yaml # OpenAI 侧信道 → HOP2
  presets/                  # 组合预设
    default.yaml            # 推荐默认：AI→HOP2，国内→DIRECT，其余→HOP1
```

## 策略占位符

规则包里的 `target` 在将来合并时解析为：

| target | 含义 |
|--------|------|
| `hop2` | 第二跳链式代理（fail-closed / REJECT，不漏真实 IP / 机场 IP） |
| `hop1` | 第一跳机场节点 |
| `direct` | 直连 |

规则条目**不写**策略名（如 `,DIRECT`），只写匹配部分，例如：

```yaml
rules:
  - DOMAIN-SUFFIX,bilibili.com
  - PROCESS-NAME,claude.exe
```

合并器会追加 `,$TARGET`。

## 默认组合意图（`presets/default.yaml`）

1. **private-direct** — 内网绝不走代理  
2. **anthropic + anthropic-sidechannel** — Claude 相关（含官方文档要求的侧信道）强制 HOP2  
3. **openai + openai-sidechannel** — ChatGPT/OpenAI 强制 HOP2  
4. **cn-direct** — 国内常用（B 站等）+ `GEOSITE,CN` / `GEOIP,CN` → DIRECT  
5. **MATCH → hop1** — 其余境外默认走机场第一跳  

## 使用

```bash
# 列出预设 / 规则包
python -m chain_builder presets

# 预览合并结果（不生成完整 profile）
python -m chain_builder show-ruleset --preset default --head 40

# 构建时选用预设（默认就是 default）
python -m chain_builder build --url ... --hop2 "..." --preset default

# 临时组合若干 pack
python -m chain_builder show-ruleset --packs anthropic,openai,cn-direct
```

合并顺序：按各 pack 的 `priority` **从高到低**插入 rules（HOP2 包 priority 高于 DIRECT 包，避免被 CN 兜底误伤）。

## 维护原则

- Anthropic / OpenAI：**宁可误伤，不可漏 IP**  
- 侧信道单独成 pack，可在预设里去掉（若你接受遥测走别的出口）  
- 国内站：手维护高频后缀 + `GEOSITE,CN` / `GEOIP,CN` 兜底  
