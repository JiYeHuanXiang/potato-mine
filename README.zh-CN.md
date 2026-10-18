# Potato Mine（土豆地雷）

**一个会保护自己的应用流量监视器。**

**版本 V0.01** · [English](README.md)

Potato Mine 由两个小工具和一个网页控制台组成：

| 组件 | 作用 |
|---|---|
| `netwatch.py` | 监视目标应用的**出站 TCP** 连接：它联系谁、有没有碰对象存储/日志/遥测基础设施。上传**字节数**来自 `deep` 抓包；`watch` 和 `record` 只记录去向。纯观察，不拦截。 |
| `potato_mine.py`（土豆地雷） | 监视“监视工具本身”。任何进程试图把守护目录复制或打包到目录之外（窃取证据的第一步），地雷立即触发并留下完整取证：进程名、PID、父进程 PID 与映像名、祖先链、命令行、触碰的文件。 |
| `webui.py` | 网页控制台：选择被观察的主进程与“永不击杀”的宿主应用、开关出站目标记录、增删守护目录、为每个目录设置触发动作（**警告 / 爆炸**），并运行与 `--check` 相同的体检。 |

想法很简单：能被悄悄打包带走的监视工具，算不上监视工具。所以工具要保护自己。

---

## 为什么需要它

如果你在用一款能访问你文件的闭源桌面应用，想**核实**它到底做了什么，
你需要在机器上放一个独立的观察者。但这个观察者本身也会成为目标：
最省事的打败方式，就是在任何人读到结果之前把它复制走（或打包上传）。

Potato Mine 把这个闭环补上：`netwatch.py` 提供证据，`potato_mine.py`
保证证据留在你放它的地方。

---

## 环境要求

- Windows 10/11
- Python 3.10+（只用标准库，无第三方依赖）
- `potato_mine.py`（Security 审计日志与文件系统审计 ACE）和
  `netwatch.py deep`（抓包）需要**管理员权限**。
  `netwatch.py watch` / `record` 无需提权。

---

## 快速开始

### 1. 配置

```bash
copy watch-config.example.json watch-config.json
```

然后编辑 `watch-config.json`：

```json
{
  "monitor_processes": ["yourapp.exe"],
  "host_apps": ["yourapp.exe"],
  "marker_groups": [
    {
      "label": "云 / 对象存储 / CDN",
      "suspicious": true,
      "markers": [["example-cloud.com", "示例云"], ["oss-", "对象存储"]]
    },
    {
      "label": "广告 / 统计 / 追踪",
      "suspicious": false,
      "markers": [["example-ads.example", "示例广告"]]
    }
  ],
  "cloud_cidrs": ["203.0.113.0/24"],
  "cloud_cidr_files": ["vendor-ranges.json"]
}
```

| 键 | 含义 |
|---|---|
| `monitor_processes` | 要归因的可执行文件名。Electron 应用会派生许多同名子进程，全部纳入。 |
| `host_apps` | 你**做分析时使用**的程序（IDE、被观察应用、远控工具）。这些进程读取守护目录只会告警，永不因读取被击杀。由另一个映像名不同的可执行文件执行的复制仍会被 Layer B 拦下；宿主应用自己进程内的复制只告警。 |
| `marker_groups` | 按组标注的域名特征。`suspicious: true` 的组视为可能的外传目的地，进入 `watch-candidates.txt` / `watch-blockable.txt`；`suspicious: false` 的组**只标注**，单独成节、永不进封禁清单——广告/统计/追踪类域名放这里。域名按**最长命中**分类。 |
| `cloud_cidrs` | 可选。IP 段只是**兜底**：拿不到域名时才用来判断。真正起作用的是域名特征。 |
| `cloud_cidr_files` | 可选。大块 IP 段放独立文件，避免把配置撑成一面墙。加载时合并区间，查询走二分，几万条也很便宜。 |
| `cloud_domain_markers` | 旧版扁平列表，仍然兼容，等价于一个 `suspicious: true` 组。 |
| `service_kinds` | 可选。`[["子串", "标签"]]`，给已知服务起名字。 |

两个工具都从各自所在目录读取这份配置。代码里不内置任何厂商特征；
名单本身由你填写，仓库只提供 schema。

**规则的类别名是固定词汇。** `rules.txt` 的格式是
`类别 | 域名模式 | 备注`，类别必须是 `BENIGN_CATEGORIES` /
`LABEL_ONLY_CATEGORIES` 里的名字（或你故意想让它进“需查证”的名字）。
写成 `Model API` 这样的英文标签**不会**被当成良性，会被导出到封禁清单。
`rules.example.txt` 列出了规范类别名。

**IP 段从哪来**：有官方清单的厂商（AWS、Google、Cloudflare）发布机器可读数据；
其余厂商可按 ASN 从 RIPEstat 拉取。`vendor-fetch.py`（留在本地，配合你填好的
`vendors.local.json`）会生成 `vendor-ranges.json`，隔段时间重跑一次，网段会漂移。

### 2. 看流量

```bash
python netwatch.py watch                 # 实时观察，免管理员
python netwatch.py record                # 长期监听，累积出站目标
python netwatch.py deep --seconds 300    # 抓包：真实域名 + 上传字节数
```

各模式写什么：

| 模式 | 输出 |
|---|---|
| `watch` | 实时控制台输出 + 带时间戳的 `netwatch-*.jsonl`。不生成累积清单。 |
| `record` | `watch-ips.json`、`watch-candidates.txt`、`watch-blockable.txt`、`targets-alerts.txt`。长期记录去向并导出封禁清单。**不统计字节数**。 |
| `deep` | `pktmon` 抓包、TLS SNI、按目的地统计上传/下载字节数。需要管理员。 |

`watch` / `record` 采样 Windows TCP 连接表。QUIC/HTTP3 走 UDP，不在采样范围内；
`deep` 能抓到 UDP 包，但无法按进程归因，也读不到 QUIC 加密的 SNI，所以纯 QUIC
应用看起来会比实际安静。入站连接被排除：本地端口同时是监听端口的连接按入站处理。

### 3. 布雷

```bash
python potato_mine.py --check     # 体检：权限/审计策略/Security 日志/ACE
python potato_mine.py --arm       # 布雷：File System + Process Creation + 审计 ACE
python potato_mine.py --run       # 运行（加 --dry-run 只记录不击杀）
```

或者用会自动提权的启动器：

```bash
arm-potato.cmd                    # 布雷 + 后台运行
stop-potato.cmd                   # 停止 + 排雷
```

`--strict-orphans` 改变“父进程已退出、来源无法确认”时的默认动作：
默认只告警，加这个参数才击杀。两层探测都适用。

日志：`potato-mine.log`（JSONL 全事件）与 `potato-mine-kills.txt`
（击杀记录，含警告动作的触发）。

### 4. 网页控制台

```bash
python webui.py --open           # http://127.0.0.1:8756
webui.cmd                        # 同上，自动请求管理员权限
```

控制台把这些操作包在一起：

- **监视的主进程** —— 从运行中的进程列表选择（或手动输入），写回
  `watch-config.json`，`netwatch.py` 同样使用。
- **宿主应用** —— “永不击杀”名单，可增删可执行文件名。它们的读取只留告警；
  被观察应用通常也应放在这里。
- **可疑上传行为监视** —— 开关。开启后托管 `netwatch.py record`，累积出站目标，
  进程意外退出会自动拉起。它记录的是**去向**，不是字节数；要看上传量请用 `deep`。
- **触发地雷后的行为** —— **警告**（只留全档，不杀任何进程）或
  **爆炸**（终止执行搬运的那一个进程）。这是**新增地雷**的默认值；
  每行可单独覆盖，**应用到全部地雷** 会把当前全局选择写到所有现有行。
- **正在运行的地雷** —— 每个守护目录一行：`总计 x 个 · y 个正在运行`，
  各自有开关、触发动作，以及 运行中 / 已布雷·守护未运行 / 未布雷·等待守护 /
  已停用 / 目录缺失 徽标。
- **体检** —— 与 `--check` 相同：管理员权限、主进程、宿主应用、文件系统与
  进程创建审计、4688 命令行策略、Security 日志可读性与容量、每个地雷的 ACE、
  以及守护是否在运行。

控制台默认只监听 `127.0.0.1`——它能终止进程，不要绑定 `0.0.0.0` 或暴露到网络。
非管理员仍可改配置，但布雷与运行会被拒绝，页面会明确提示。写操作会校验
浏览器 `Origin` 与控制台自身主机是否一致，别的网站无法用跨站 POST 停掉地雷。

---

## 地雷怎么工作

两层独立探测，因为单独任何一层都不够：

**Layer A —— 读绊网（文件系统审计）。**
布雷会给守护目录加一条 `Everyone:ReadData / ListDirectory` 审计 ACE
（并向已存在的文件显式传播——程序化改 ACL 不会替你自动做这件事）。
启用 `File System` 审计子类别后，Windows 会为该路径下的每次内容读取和目录
枚举写一条 **4663** 事件。它能抓到命令行扫描抓不到的东西：程序化
`CopyFile`、打包器遍历目录、备份代理。地雷通过 `wevtapi.dll` 在进程内读取
Security 日志，并按读取者的进程祖先链分类。

**Layer B —— 出生检查（进程创建审计）。**
Windows 用 4688 记录进程创建；地雷在进程内读取 Security 日志，检查每个新进程。
命令行同时满足 (a) 含守护目录内的路径、(b) 有复制/打包/上传语义、
(c) 有目录外的目的地（路径或非回环 URL）时立即处置。4688 自带父进程映像路径
和子进程命令行，所以即使进程在分类前已经退出也能判断。

两层都用**进程内** `wevtapi.dll` 读取，而不是每次轮询起一个 `wevtutil` 子进程：
后者本身会产生新的 4688 事件，把固定容量的 Security 日志越填越快，事件还没读到
就被覆盖——一个会悄悄弄瞎地雷的自我加剧反馈环。启动时的进程快照同样用于避免
为每个祖先逐个起 PowerShell 查询，并记录地雷自己的祖先链。

### 击杀策略

| 情况 | 动作 |
|---|---|
| Layer B：源在守护目录 **且** 目的地在目录外 | **击杀**（除非命中下方任一例外：宿主应用 / 来源未知 / 会话内 shell；GUI 文件管理器的复制是你亲手操作，也排除） |
| Layer B：会话树内的 shell（cmd/bash/powershell） | 只告警——真正的搬运者会以自己的出生事件被击杀 |
| Layer B：父进程已退出、来源未知 | 只告警；`--strict-orphans` 才击杀 |
| Layer A：无头树（`services.exe` / `svchost.exe` / `WmiPrvSE.exe` …）运行已知的复制/打包/上传工具 | **击杀** |
| Layer A：宿主应用、编辑器、终端、文件管理器、杀软、索引器 | 只告警 |
| Layer A：孤儿或来源未知 | 告警；`--strict-orphans` 才击杀已知的复制/打包/上传工具 |
| 无法确认进程身份的任何情况 | 只告警——“不知道”不等于“可疑” |

无论动作是什么，每次触发都完整落档：进程名、PID、映像路径、命令行、
**父 PID 与父映像名**、完整祖先链、触碰的文件。

### 威力上限（硬边界）

这是防御工具，所以对最坏情况要足够无聊。**爆炸只杀一个进程**：
`taskkill /F /PID <pid>`，永不带 `/T`。

- **不杀父进程。** 父进程通常是会话的壳——终端、IDE、远控。杀它会把手伸到
  事件之外，还会打断你自己的工作。永远不碰。
- **不杀子进程。** 搬运者的子进程可能完全是你的其它工作，与本次复制无关。
  永远不碰。
- **不杀系统命脉。** `SYSTEM_PROTECTED` 覆盖 `csrss.exe`、`lsass.exe`、
  `services.exe`、`wininit.exe`、`svchost.exe`、`explorer.exe`、`conhost.exe`
  等，在每条代码路径上强制生效。
- **不杀宿主应用。** `host_apps` 里的编辑器、被观察应用、远控通道永不击杀；
  由另一个映像名不同的可执行文件执行的复制仍会被 Layer B 拦下；
  宿主应用自己进程内的复制只告警。
- **不自伤。** 地雷启动时记录自己的完整祖先链，拒绝击杀其中任何一个；
  它打不穿自己所在的会话。
- **不猜。** 查不到映像路径或祖先来源时，那不叫证据。只告警，到此为止。
- 取证补上威力收窄的代价：记录里保留父 PID、父映像名和完整祖先链，
  你仍然能看出是谁派来的搬运者。
- 结果：最坏情况只是某个用户态进程被终止（可以重开）。工具里不存在不可逆操作。

---

## 局限（请务必读）

- **静态观察，不是拦截。** `netwatch` 报告的是 OS 连接表和抓包看到的东西。
  短命连接可能落在两次采样之间。没看到不等于不存在。
- **以 TCP 为主。** `watch` / `record` 只读 TCP 连接表；QUIC/HTTP3 走 UDP，
  `deep` 能抓到但无法按进程归因，也读不到 QUIC 加密的 SNI。纯 QUIC 应用只能
  算“部分可见”。
- **上传字节数需要 `deep`。** `record` 和网页控制台的上传监视记录的是去向与
  建连状态，不是流量大小。
- **Layer A 有延迟。** Security 日志大约每 0.5–0.6 秒读一次。极短命进程复制一个
  小文件，可能在分类前就完成。批量操作、目录遍历、打包——真正的外传形态——
  会在进行中被截断。Layer B 用 4688 自带的命令行补上大部分空档：复制从它出生
  的那一刻就能被发现，而不是等它读完。
- **Security 日志容量很重要。** 布雷会打开进程创建审计，全机器的每个新进程都会
  往里写。日志小且接近满时，旧事件会被循环覆盖；`--check` 会报告最大容量与记录数。
  发现缺口就调大：`wevtutil sl Security /ms:67108864`。
- **Layer B 匹配命令行。** 只认真正的复制/打包/上传语义：`curl`/`wget` 必须带
  上传参数（`-T`、`-F`、`--form`、`--upload-file`、`--post-file`、`-d @file`）。
  访问回环地址不算目录外目的地。只是“提到”复制的 shell 按会话树内 shell 处理，
  只告警；来源未知默认也只告警——这都是为了避免误杀。代价是：父进程已退出、
  又不带可识别上传参数的搬运者可能被漏掉。愿意承担这个风险时再用
  `--strict-orphans`。
- **需要管理员权限**做审计，而且以 SYSTEM 运行的任何东西都能移除 ACE。
  这提高了悄悄搬运的成本，但不能让它变得不可能。
- **不是沙箱。** 它不阻止网络访问，只观察和记录。
- **停止语义。** 优雅停止（Ctrl+C 或网页控制台的停止按钮）会移除审计 ACE 并
  还原 4688 命令行策略。硬 `--stop` 用 `taskkill`，ACE 和策略可能残留，之后要
  跑 `--disarm`（`stop-potato.cmd` 会做）。如果地雷由网页控制台托管，请用
  控制台的停止按钮——`--stop` 会把控制台进程一起结束。审计子类别无论如何都
  保持启用，但没有 ACE 时不会产生文件读取事件。

---

## 文件

```
netwatch.py                  出站连接监视器
test_netwatch_classify.py    目标定性回归测试
test_mine_core.py            地雷引擎回归测试
potato_mine.py               自保护地雷（命令行）
mine_core.py                 共享引擎：地雷、判定、取证
webui.py                     网页控制台后端（标准库 HTTP + JSON API）
webui.html                   网页控制台页面
webui.cmd                    提权并启动控制台
watch-config.example.json    复制为 watch-config.json 后编辑
mines.example.json           复制为 mines.json 后编辑
rules.example.txt            目标分类规则（类别|域名模式|备注）
exclusions.example.txt       要忽略的良性目的地
arm-potato.cmd               提权 + 布雷 + 后台运行
stop-potato.cmd              停止 + 排雷
```

运行时产物（首次运行创建，不进版本库）：`watch-config.json`、
`mines.json`、`potato-mine.log`、`potato-mine-kills.txt`、`potato-mine.pid`、
`potato-mine-auditpol-state.json`、`netwatch-webui.log`、`watch-ips.json`、
`watch-candidates.txt`、`watch-blockable.txt`、`targets-alerts.txt`、
`rules.txt`、`exclusions.txt`、`netwatch-*.jsonl`、
`targets-capture-*.etl/.pcapng`、`_sni.*`。

`mines.json` 可以手改。控制台保存时会保留已有的 `_comment` / `_field_guide`
键；显式的空 `mines: []` 表示“不要任何地雷”，只有 `mines.json` 不存在时才
回退到守护工具目录。

---

## 许可证

MIT —— 见 [LICENSE](LICENSE)。
