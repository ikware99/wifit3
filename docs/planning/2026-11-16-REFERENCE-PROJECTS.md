# 参考项目清单 · 板载无线适配扩展（2026-11-16）

> 目标：为本 fork 的三条工作线（虚拟适配器 / 9462 探测 / 能力体检）找**可直接落地**的上游参考。
> 取数时间 2026-11-16，star / 活跃度为当日 GitHub API 实测值，未估算。
> 入选门槛：仓库真实存在、与需求一一对应、能给出具体执行动作。

---

## 1. 结论先行

**优先跑通 `mac80211_hwsim` 这一系，再对照 `hcxdumptool`/`hcxtools` 校验格式。** 理由：

1. 我们的 `chips/sim` 是**用户态**仿真，只证明产品逻辑链路通，不证明「真实内核协议栈会这样应答」。
   `mac80211_hwsim` + `hostapd` 是内核级真协议栈，能交叉验证我们的帧构造是否符合真实 AP 行为。
2. PMKID / `.hc22000` 的格式正确性，最终解释权在 `hcxtools` 与 hashcat。用它们校验我们能避免
   「自洽但不通用」的假阳性。
3. CNVi 的现实上限是**被动嗅探**，落地工具是 Kismet（Linux）/ Npcap（Windows），不是注入类工具。

---

## 2. 清单（按可执行性排序）

| # | 项目 | 语言 | ★ | 最近更新 | 对应需求 | 可执行性 |
|---|---|---|---|---|---|---|
| 1 | [intrig-unicamp/mininet-wifi](https://github.com/intrig-unicamp/mininet-wifi) | Python | 542 | 2026-11-15 | 虚拟适配器（内核级） | **最高**：pip 装、Python API 建 AP/STA 拓扑 |
| 2 | [ZerBea/hcxdumptool](https://github.com/ZerBea/hcxdumptool) | C | 2228 | 2026-11-16 | PMKID 采集语义 | **高**：行为对照基准 |
| 3 | [ZerBea/hcxtools](https://github.com/ZerBea/hcxtools) | C | 2477 | 2026-11-15 | `.hc22000` 格式校验 | **高**：命令行即用 |
| 4 | [aircrack-ng/aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) | C | 7918 | 2026-11-16 | 能力体检对照 | **高**：`airmon-ng` 能力矩阵 |
| 5 | [kismetwireless/kismet](https://github.com/kismetwireless/kismet) | C++ | 2263 | 2026-11-15 | CNVi 被动嗅探 | **高**：Linux 直接跑 |
| 6 | [nmap/npcap](https://github.com/nmap/npcap) | C | 3641 | 2026-11-16 | Windows 抓包栈 | **高**：装完即验 |
| 7 | [Raizo62/vwifi](https://github.com/Raizo62/vwifi) | C++ | 105 | 2026-10-26 | 无内核模块的虚拟接口 | **中高**：需编内核模块 |
| 8 | [r4ulcl/WiFiChallengeLab](https://github.com/r4ulcl/WiFiChallengeLab) | Shell | 64 | 2026-09-09 | 无网卡靶场 | **中**：脚本可直接抄，**已归档** |

**内核自带，无需找仓库**：`mac80211_hwsim` 是 Linux 内核模块（`drivers/net/wireless/virtual/mac80211_hwsim.c`），
`modprobe mac80211_hwsim radios=2` 即可得到两个虚拟 wlan 接口。GitHub 上的
[jlopex/mac80211_hwsim](https://github.com/jlopex/mac80211_hwsim)（25★，2026-05）只是改动版，
提供信号强度等扩展，**不是必需项**。

---

## 3. 逐项落地路径

### 3.1 mininet-wifi —— 用真内核协议栈验证我们的合成帧

- **为什么选它**：把 `mac80211_hwsim` 封装成 Python API，能在几十行内建出「1 个 AP + N 个 STA」，
  且 AP 侧跑真实 `hostapd`，STA 侧跑真实 `wpa_supplicant`。这是验证我们 `dot11/ap.py` 帧构造最硬的手段。
- **具体动作**：
  1. Linux 主机装 mininet-wifi，建一个 `ssid=sim-lab-2g` 的 WPA2-AP。
  2. 用我们 `chips/sim/radio.py::build_beacon` 产出的信标，与 hostapd 真实信标逐 IE 比对
     （SSID / rates / DS / RSN 顺序与长度）。
  3. 用 `Association` 对 hostapd 走一遍 auth/assoc，确认我们的 `assoc_resp` 解析能处理真实 IE 集
     （HT/VHT/HE 扩展），这是当前 sim 环境覆盖不到的。
- **置信度**：高。活跃（昨日有提交），Python 3 可装，文档完整。
- **限制**：需 Linux + root；Windows 上只能跑在 WSL2（hwsim 需内核模块，WSL2 默认内核可能未编译该模块）。

### 3.2 hcxdumptool —— PMKID 采集行为基准

- **为什么选它**：我们 `campaigns/pmkid.py` 的文件头注释本身就写明对齐 hcxdumptool 的时序
  （Auth → Assoc → M1 → deauth 终止）。它是这个流程的事实标准实现。
- **具体动作**：读它的 `--exitoneapol` / PMKID 处理路径，核对我们的三处判定：
  「PMKID-less M1 不重试」「成功后立即 deauth」「AP 静默才换 MAC」。
- **置信度**：高。2.2k★，当日有提交，issue 长期保持 0。

### 3.3 hcxtools —— 校验我们产出的 `.hc22000` 是否真通用

- **为什么选它**：`hcxpcapngtool` 是 pcap→hc22000 的权威实现。我们自写的 hashline 若与它不一致，
  hashcat 可能读不了而我们的单测发现不了（因为自测用的是自家 parser）。
- **具体动作**：把我们跑出的 `WPA*01*...` 行交给 `hcxhashtool` / hashcat `--show` 流程过一遍；
  有条件时把 sim 采到的 pcap 交给 `hcxpcapngtool` 生成 hashline，与我们的逐字段比对。
- **置信度**：高。2.4k★，长期维护。

### 3.4 aircrack-ng —— 能力体检的对照源

- **为什么选它**：`airmon-ng` 列出的芯片/驱动能力矩阵，是社区最广的实测集合；我们的
  `wireless_capabilities` 判 `injection_capable` 时用的驱动白名单（ath9k/rtw88/mt76…）应与它一致。
- **具体动作**：拉它的 `patches/` 与 `src/airmon-ng`，把驱动名单与我们的 `_IW_MONITOR_DRIVERS` 对齐，
  差异项逐条查证后再改。
- **置信度**：高。7.9k★，当日有提交。
- **限制**：GPL 系许可，**只做事实对照，不复制代码进本仓库**。

### 3.5 Kismet —— CNVi「只能被动」的现实落地

- **为什么选它**：它是被动嗅探与 WIDS 的成熟实现，且数据源抽象覆盖 linux-wifi / winpcap / npcap，
  正好对应我们「9462 只能被动」的结论要落到什么工具上。
- **具体动作**：Linux 下用 iwlwifi 的 passive monitor VIF 起 Kismet，确认能收到信标但无法注入；
  把这套限制写进 `host_radios` 的 note（当前 note 是文档推断，可升级为实测引用）。
- **置信度**：高。2.2k★，活跃。
- **限制**：GPLv2；Windows 侧数据源依赖 Npcap。

### 3.6 Npcap —— Windows 唯一现实的 802.11 抓包栈

- **为什么选它**：我们 `wireless_capabilities.find_npcap()` 已经在检测它，但结论只写了「可被动抓包」，
  没有验证。它是 Windows 上提供 raw 802.11 的唯一常用方案（安装时勾选相应选项）。
- **具体动作**：确认本机 Npcap 安装是否勾选 raw 802.11 支持，用 Wireshark 抓 802.11 帧验证
  DLT 是否为 105；若不是，明确写进报告「本机仅以太网 DLT，仍无法看 802.11 头」。
- **置信度**：高。3.6k★，当日有提交。
- **限制**：**许可为自定义条款，商业/再分发受限**，落地前须核对 LICENSE；不可与 WinPcap 混装。

### 3.7 vwifi —— 没有内核头文件时的替代

- **为什么选它**：纯用户态实现虚拟 802.11 接口（配 `vwifi-dkms`），不依赖 `mac80211_hwsim`，
  适合内核模块不便编译的环境（如部分云主机、受限容器）。
- **具体动作**：在无法 `modprobe mac80211_hwsim` 的机器上，用 vwifi 建虚拟接口后重跑同一套验证。
- **置信度**：中高。105★，2026-10 有更新。
- **限制**：仍需编译内核模块（DKMS）；功能集小于 hwsim。

### 3.8 WiFiChallengeLab —— 可直接抄的靶场脚本

- **为什么选它**：它把 `mac80211_hwsim` + `vwifi` 组合成一个开箱可用的无线靶场，
  正好是我们「无网卡跑通全链路」的同类目标，脚本可直接借鉴。
- **具体动作**：取其建靶场的 shell 步骤（模块加载顺序、接口命名、hostapd 配置），
  在 Linux 上复现一次，确认我们的 sim 与它的行为差异。
- **置信度**：中。**仓库已归档（archived）**，内容仍可执行但不再更新，不应作为长期依赖。

---

## 4. 建议的落地顺序（3 步）

| 步 | 动作 | 产出 | 成本 |
|---|---|---|---|
| 1 | 装 Npcap 并验证 DLT，确认本机 Windows 侧到底能看到什么 | 一条实测结论，替换当前推断 | 10 分钟 |
| 2 | Linux + `mac80211_hwsim` + hostapd 起真 AP，用我们的 `Association` 跑一遍 | 合成帧 vs 真实帧的 IE 差异清单 | 半天 |
| 3 | 用 `hcxpcapngtool` / hashcat 校验我们产出的 `.hc22000` | 格式兼容性结论（或修正项） | 1 小时 |

---

## 5. 低置信度项（列出但不推荐）

| 项目 | 原因 |
|---|---|
| [vchakour/wmediumd](https://github.com/vchakour/wmediumd)（3★） | 2015 年后停更，用户态介质模拟思路可参考，代码不宜直接用 |
| [jlopex/mac80211_hwsim](https://github.com/jlopex/mac80211_hwsim)（25★） | 内核模块改动版，仅在需要信号强度/干扰建模时才需要 |
| hostapd / wpa_supplicant 官方 | **不在 GitHub**（上游为 w1.fi git），GitHub 上只有个人 fork，不宜引用 |

---

## 6. 与本次交付的关系

| 我们的模块 | 主要参考 | 作用 |
|---|---|---|
| `chips/sim/radio.py` | mininet-wifi / hostapd（真协议栈） | 校验合成帧的 IE 与状态机应答 |
| `campaigns/pmkid.py`（既有） | hcxdumptool | 时序与终止条件对照 |
| `persist/save.py`（既有） | hcxtools | hashline 通用性校验 |
| `wireless_capabilities.py` | aircrack-ng / Npcap | 驱动白名单与 Windows 抓包能力 |
| `device/host_radios.py` | Kismet | 被动嗅探可达性由推断升级为实测 |
