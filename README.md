# Clash Chain Builder

用机场订阅节点做**第一跳（中转）**，用购买的 SOCKS5 落地做**第二跳**，一键生成可导入 [Clash Verge](https://github.com/clash-verge-rev/clash-verge-rev) / [mihomo](https://github.com/MetaCubeX/mihomo) 的链式 YAML。

> 🔰 **第一次接触链式代理 / Clash？** 请先看带配图的 **[链式代理保姆级教程](./链式代理教程.md)**，
> 从「Clash 为什么要读一个 YAML」讲起，本 README 更偏参数速查。

默认策略（无额外参数）：

| 流量 | 出口 |
|------|------|
| Claude / Anthropic、ChatGPT / OpenAI（含侧信道） | **第二跳**（挂了 → 断连，不漏真实 IP / 机场 IP） |
| 内网 + 国内常用站 | **DIRECT** |
| 其余境外 | **第一跳机场** |

License: [MIT](./LICENSE)（可自由使用、修改、分发）。

---

## 目录

- [功能一览](#功能一览)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [第二跳凭证格式](#第二跳凭证格式)
- [规则预设与 config/](#规则预设与-config)
- [防漏 IP 说明](#防漏-ip-说明)
- [常用命令](#常用命令)
- [CLI 参数](#cli-参数)
- [输出与导入](#输出与导入)
- [项目结构](#项目结构)
- [扩展规则](#扩展规则)
- [故障排查](#故障排查)
- [免责声明](#免责声明)

---

## 功能一览

- **两跳链式代理**：第二跳通过 mihomo `dialer-proxy` 经第一跳拨号（官方推荐写法；`relay` 已废弃）
- **任意顺序解析第二跳凭证**：`host:port:user:pass`、空格分隔、URL、标签形式等
- **TUI 选节点**：拉取订阅后测延迟，表格展示，按序号 / 关键字选择第一跳
- **自动第一跳（可选）**：`full-chain-auto` 把机场节点写入 YAML，由 mihomo 每 300 秒测速并选延迟最低的第一跳
- **出口验证**：临时启动本机 mihomo，访问 IP 检测站确认真实出口；并做第二跳故障闭锁检查
- **可组合分流包**：`config/packs` + `config/presets`，默认 AI 走落地、国内直连、其余走机场
- **命名输出**：分流、普通全链和自动全链分别输出独立文件；也可用 `--name` 自定义文件名

---

## 环境要求

| 项 | 说明 |
|----|------|
| uv | 包与虚拟环境（[安装](https://docs.astral.sh/uv/getting-started/installation/)） |
| Python | 3.9+（`uv sync` 按 `.python-version` 准备，推荐 3.12） |
| 依赖 | `uv sync`（`pyyaml` / `requests` / `rich`；开发含 pytest） |
| mihomo | 装了 Clash Verge / mihomo 即可，自动定位（见下），实在找不到再设 `MIHOMO_BIN` |
| 系统 | Windows / macOS / Linux；测速与验证需要能启动内核 |

Windows 下若节点名乱码，可先执行：

```powershell
$env:PYTHONIOENCODING = "utf-8"
```

### mihomo 内核自动定位

工具会按从快到慢的顺序找内核，并用 `-v` 验证候选确实是 Meta 内核（GUI 主程序、非 Meta 的
clash 不会被误选）：

1. 环境变量 `MIHOMO_BIN` / `CLASH_META_BIN` / `CLASH_CORE_BIN` / `CLASH_BIN`（文件、目录或命令名皆可），
   以及 `MIHOMO_HOME` / `CLASH_HOME` / `CLASH_DIR` / `CLASH_VERGE_DIR` 指定的目录
2. 项目目录与当前工作目录（含 `bin/`、`core/`、`vendor/`）
3. `PATH`
4. Windows 注册表：卸载项的 `InstallLocation`、`App Paths`（Clash Verge / Nyanpasu 等装到非默认盘也能找到）
5. 正在运行的 Clash 进程所在目录（GUI 在跑就能定位到它自带的内核）
6. 常见安装位置：Program Files、`LocalAppData\Programs`、scoop、chocolatey、winget；
   macOS 的 `/Applications`、Homebrew；Linux 的 `/opt`、`/usr/local/bin`、`~/.local/bin`
7. 各本地磁盘根目录下的 `*clash*` / `*mihomo*` / `*verge*` 目录，以及 `Apps`、`Software`、`Tools`
   这类常见便携软件父目录

排查用：

```bash
uv run python -m chain_builder find-core          # 显示选中的内核、来源、版本
uv run python -m chain_builder find-core --all    # 列出所有候选及其可用性
```

---

## 快速开始

先装依赖（只需一次）：

```bash
uv sync
```

没有 uv 时，PowerShell 先执行，然后**新开一个终端**：

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

默认分流和普通全链模式会询问订阅、落地凭证和第一跳节点。自动第一跳模式只询问订阅与落地凭证，生成时选一个节点验证链路，导入后由 mihomo 持续测速选择。

### 分流（日常科学上网）

```bash
uv run python -m chain_builder
```

Claude / ChatGPT 走第二跳落地，国内直连，其余走机场。

### 全链（开 Claude 时用）

```bash
uv run python -m chain_builder --full-chain
```

全部流量走第二跳，不设分流。YAML **不**嵌入 TUN（避免和 Verge 的 TUN 开关打架）。导入后在 Clash Verge 里：**切全局 → 开 TUN → 选 CHAIN**。不用这份配置时换回别的即可。

### 全链，第一跳自动选择

```bash
uv run python -m chain_builder --preset full-chain-auto
```

生成 `output/<第二跳出口IP>_<属地>_full-chain-auto.yaml`。这个模式会把订阅中的机场节点作为候选，`HOP1-AUTO` 组在 mihomo 运行时定期测速并选延迟最低的节点；第二跳始终是输入的 SOCKS5 地址。`--filter` 可以限定候选节点，`--hop1` 只指定生成时验证链路使用的节点。订阅节点列表是生成时的快照，订阅更新后需重新生成 YAML。导入后同样切全局、开 TUN、选 CHAIN。

例如只让名称包含“日本”的机场节点参与自动选择：

```bash
uv run python -m chain_builder --preset full-chain-auto --filter 日本
```

按提示输入：

1. **机场订阅 URL**
2. **第二跳凭证**（任意顺序，见下方格式）
3. **第一跳节点**（分流和普通全链模式；空回车 = 生成时延迟最低的可用节点）

完成后写入（同一落地 IP 的分流 / 全链不再互相覆盖）：

```text
output/<第二跳出口IP>_<属地>.yaml                 # 分流
output/<第二跳出口IP>_<属地>_full-chain.yaml      # --full-chain
output/<第二跳出口IP>_<属地>_full-chain-auto.yaml # --preset full-chain-auto
```

示例：`output/167.253.38.151_US-California.yaml`  
全链：`output/167.253.38.151_US-California_full-chain.yaml`  
自定义名：`--name my-full` → `output/my-full.yaml`（`--out` 仍可指定完整路径）

导入：Clash Verge → Profiles → 导入本地文件 → 选用该 YAML。全链配置再在 Verge 里 **切全局、开 TUN、选 CHAIN**（不要依赖配置文件里的 TUN）。

---

## 第二跳凭证格式

以下写法均可识别（住宅 / 静态 SOCKS 常见粘贴格式）：

```text
proxy.ipdeep.com:7085:user:pass
1.2.3.4:1080:user:pass
1.2.3.4 1080 user pass
pass user 1080 1.2.3.4
user:pass@1.2.3.4:1080
socks5://user:pass@proxy.example.com:7085
socks5://proxy.example.com:7085:user:pass
ip=1.2.3.4 port=1080 user=u pass=p
1.2.3.4 proxy.example.com 7085 user pass   # IP=出口提示，host=网关
```

说明：

- 同时出现 **IPv4 + 域名** 时：域名作 SOCKS 服务器，IP 作出口提示
- `user` / `pass` 顺序若猜错，验证阶段会**自动对调重试一次**
- 密码中含 `:`、首尾空格、引号、`;` / `,` 分隔也尽量兼容

自测解析：

```bash
uv run python -m chain_builder parse-hop2 "proxy.ipdeep.com:7085:user:pass"
```

---

## 规则预设与 config/

规则数据在 `config/`，由 `chain_builder/ruleset.py` 按 **priority 从高到低** 合并。

### 默认预设 `default`（无参数即用此）

| Pack | 作用 |
|------|------|
| `private-direct` | 内网 / LAN → DIRECT |
| `anthropic` + `anthropic-sidechannel` | Claude 一方域名 + 官方侧信道 → CHAIN（第二跳） |
| `openai` + `openai-sidechannel` | OpenAI / ChatGPT 一方域名 + 侧信道 → CHAIN |
| `cn-direct` | B 站等国内常用 + `GEOSITE,CN` / `GEOIP,CN` → DIRECT |
| `MATCH` | → **HOP1**（其余境外走机场） |

其它预设：

| 预设 | 说明 |
|------|------|
| `default` / `ai-strict` | 含侧信道，防漏优先（默认） |
| `ai-minimal` | 仅 AI 一方域名走第二跳，不劫持 GCS / Sentry 等 |
| `full-chain` | 固定第一跳；全部 `MATCH→CHAIN`，不嵌入 TUN；Verge 里切全局 / 开 TUN / 选 CHAIN |
| `full-chain-auto` | 第一跳从生成时的机场节点中定期测速自动选择，第二跳固定；其余全链设置同上 |

```bash
uv run python -m chain_builder presets
uv run python -m chain_builder show-ruleset --preset default --head 40
uv run python -m chain_builder show-ruleset --packs anthropic,openai,cn-direct
```

字段约定见 [`config/SCHEMA.md`](./config/SCHEMA.md)，目录说明见 [`config/README.md`](./config/README.md)。

### Legacy 插件别名

仍可用：`basic` / `full`（全走链）、`anthropic` / `openai` / `ai`。见：

```bash
uv run python -m chain_builder plugins
```

要全部走链、不设分流，用快速开始里的 `--full-chain`，不要抄带 `...` 的示例。

---

## 防漏 IP 说明

### 默认分流下的「AI 路径」防漏

对命中 CHAIN 的流量（Claude / OpenAI 等）：

1. 第二跳节点带 `dialer-proxy: <第一跳>`，必须经机场再连落地  
2. `CHAIN` 组为 `fallback: [第二跳, REJECT]` —— 第一跳或第二跳不可用时**直接拒绝**，不回落 DIRECT、不裸奔第一跳  
3. 相关域名 DNS 使用 `#CHAIN`，并开启 `dns.respect-rules`  
4. sniffer `force-domain` 覆盖主要 AI 域名，减少纯 IP / 嗅探绕过  
5. 进程规则兜底（如 `claude.exe` / `ChatGPT.exe`）  
6. 生成前断言 CHAIN 形态；验证阶段会注入不可达第二跳，若仍能拿到公网 IP 则拒绝写出  

**含义**：Claude / ChatGPT 业务在链路异常时宁可断连，也不应露出你家宽带 IP 或机场出口 IP。

普通全链和自动全链的 `CHAIN` 只包含第二跳，链路故障时连接失败，不回落到直连或单独的机场节点。自动全链中第二跳的 `dialer-proxy` 指向 `HOP1-AUTO`，该组只包含机场节点。全链配置的 DoH 解析器显式走 `DIRECT`，与默认分流的 AI 域名 DNS 策略不同。

### 默认分流不会保证的事情

- 走 **HOP1** 或 **DIRECT** 的流量本来就会露出机场 IP 或真实 IP（这是设计如此）  
- Clash / mihomo **进程退出**后，系统可能恢复直连；YAML 管不住已退出的内核  
- 侧信道包会把部分共享 SaaS（如 GCS / Sentry / Datadog）也送进 CHAIN，属于「宁可误伤」的取舍；可用 `ai-minimal` 关掉  

### 可选：Windows 防火墙 Kill Switch

进程退出后也要禁止旁路时，可用管理员 PowerShell：

```powershell
.\scripts\clash-chain-killswitch.ps1 Enable `
  -MihomoPath "C:\Program Files\Clash Verge\verge-mihomo.exe"

.\scripts\clash-chain-killswitch.ps1 Status
.\scripts\clash-chain-killswitch.ps1 Disable
```

会备份防火墙策略后收紧出站；影响其它直连软件。构建器**不会**自动执行此脚本。

### 严格全隧道模式（可选）

请用快速开始里的 `--full-chain`。`--strict-full-chain` 是旧开关，会叠在现有分流预设上强制 `MATCH→CHAIN`，生成的 YAML 更重，一般不用。

---

## 常用命令

```bash
# 分流（日常）
uv run python -m chain_builder

# 固定第一跳的全链
uv run python -m chain_builder --full-chain

# 第一跳按延迟自动选择的全链
uv run python -m chain_builder --preset full-chain-auto

# 只测第二跳解析
uv run python -m chain_builder parse-hop2 "proxy.ipdeep.com:7085:user:pass"
```

---

## CLI 参数

| 参数 | 说明 |
|------|------|
| `--url` | 机场订阅 URL |
| `--hop2` | 第二跳凭证字符串 |
| `--hop1` | 第一跳节点名（精确匹配，跳过 TUI；自动模式仅用于生成时的链路验证） |
| `--filter` | 节点名过滤关键字（如 `日本` / `jp`） |
| `--full-chain` | 全链模式：全部走第二跳、不设分流；YAML 不嵌入 TUN（向导流程不变） |
| `--preset` | `config/presets` 名，默认 `default`；或 legacy 插件名 |
| `--packs` | 逗号分隔 pack id，临时组合 |
| `--match-default` | 覆盖 `MATCH`：`hop1` / `hop2` / `chain` / `direct` / `reject` |
| `--strict-full-chain` | 强制全隧道 `MATCH→CHAIN` |
| `--rules-file` | 追加自定义规则（每行一条，需已含策略名） |
| `--name` | 输出文件名（写到 `--out-dir`，默认 `./output`；可省略 `.yaml`） |
| `--out` / `--out-dir` | 完整输出路径（优先于 `--name`） / 输出目录 |
| `--no-latency` | 跳过生成时的机场测速；自动模式导入后仍会由 mihomo 定期测速 |
| `--no-verify` | 跳过临时内核出口验证（不推荐） |
| `MIHOMO_BIN` | 环境变量，指定 mihomo / verge-mihomo 路径（自动定位失败时才需要） |

子命令：`wizard`（默认）、`build`、`parse-hop2`、`presets`、`show-ruleset`、`plugins`、`find-core`。

---

## 输出与导入

1. 打开 Clash Verge → **Profiles** → 导入刚生成的 YAML  
2. 选中该配置。全链：在 Verge 里 **切全局、开 TUN、代理列表选 CHAIN**（配置不写死 TUN）。分流：按习惯开系统代理 / TUN，规则会把 AI 送进 CHAIN  
3. 策略组含义：  
   - **CHAIN**：第二跳链式；分流配置故障时回落 REJECT，全链配置故障时连接失败
   - **GLOBAL**（全链）：全局模式列表，默认第一项是 CHAIN  
   - **HOP1**（分流）：默认境外流量走的第一跳  
   - **HOP1-AUTO**（自动全链）：定期测速，在机场候选节点中选择第一跳
4. 自测出口（应看到**第二跳落地 IP**，而不是机场 IP）：

```bash
curl --proxy http://127.0.0.1:7890 https://api.ipify.org
```

生成前会尽量跑 `mihomo -t`；未找到内核时会提示跳过校验，但仍会写出文件。

---

## 项目结构

```text
clash/
├── README.md
├── LICENSE                 # MIT
├── pyproject.toml          # 依赖与项目元数据（uv）
├── uv.lock
├── chain_builder/          # 主程序
│   ├── cli.py              # 命令行 / 向导
│   ├── hop2.py             # 第二跳凭证解析
│   ├── fetch.py            # 订阅拉取
│   ├── tui.py              # 节点选择 + 测速
│   ├── builder.py          # YAML 组装 + 防漏断言
│   ├── ruleset.py          # 读取合并 config/
│   ├── verify.py           # 临时内核验证出口
│   ├── mihomo.py           # 查找 / 拉起 mihomo
│   └── plugins/            # legacy 规则插件
├── config/
│   ├── packs/              # 原子规则包
│   └── presets/            # 组合预设
├── scripts/                # 可选 kill switch 等
├── ref/                    # 手工参考配置
├── tests/                  # 解析 / 规则 / 防漏审计
└── output/                 # 生成结果（默认 gitignore）
```

---

## 扩展规则

1. 在 `config/packs/` 新增 YAML（见 `SCHEMA.md`：`id` / `target` / `priority` / `rules` …）  
2. 在 `config/presets/*.yaml` 的 `compose` 里引用  
3. `uv run python -m chain_builder show-ruleset --preset your-preset` 预览  

也可继续用 legacy `RulePlugin`（`chain_builder/plugins/builtin/` + `registry.py`），但新规则优先放 `config/`。

---

## 故障排查

| 现象 | 可能原因 / 处理 |
|------|----------------|
| 订阅拉不到 | 需 Clash UA；检查 URL、网络；脚本会重试并尝试 `flag=clash` |
| 第二跳解析失败 | 用 `parse-hop2` 自测；推荐 `host:port:user:pass` |
| 验证出口失败 | 第一跳延迟过高 / 落地凭证反了（会自动对调一次）/ 网关不可达 |
| `assert_fail_closed_*` | 生成逻辑自检失败，属程序问题或规则被改坏 |
| mihomo 找不到 | 先跑 `uv run python -m chain_builder find-core --all` 看候选；仍找不到就设 `MIHOMO_BIN` |
| Claude 仍露机场 IP | 确认用了生成的配置且走 CHAIN；检查是否未开系统代理/TUN；进程是否被规则命中 |
| 国内站变慢 | 确认命中 DIRECT / `GEOSITE,CN`；必要时加域名到 `cn-direct.yaml` |

---

## 免责声明

本工具仅供学习与个人网络调试。请遵守当地法律法规及服务商条款；不要将配置用于未授权访问或侵犯他人权益。作者不对使用后果承担责任。软件按 MIT 许可「按现状」提供，无任何担保。

---

## License

[MIT License](./LICENSE) — 可自由使用、复制、修改、合并、发布、再许可与销售，只需保留版权与许可声明。
# Clash_chain_builder
