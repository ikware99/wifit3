# wifit3 — 板载无线适配扩展（团队协作区）

> 本 fork 用于推进 **wifit3 对非 USB 无线适配器的支持**，当前聚焦两条路径：
> **A. 虚拟 WiFi 适配器**（无实体网卡跑通全链路）、
> **B. Intel Wireless-AC 9462 独立探测通路**（板载 CNVi 设备）。
> 上游主仓：`derv82/wifit3`（本 fork 定期 rebase）。**USB 通路功能保持原样，不做任何删改。**

---

## 快速入口

| 内容 | 位置 |
|---|---|
| **完整任务上下文移交文档** | [`docs/planning/INTEL-9462-HANDOFF.md`](docs/planning/INTEL-9462-HANDOFF.md) |
| **本轮实施进度（2026-11-16）** | [`docs/planning/2026-11-16-PROGRESS.md`](docs/planning/2026-11-16-PROGRESS.md) |
| 任务 A：虚拟 WiFi 适配器 | [issue #1](https://github.com/ikware99/wifit3/issues/1) |
| 任务 B：9462 独立探测通路 | [issue #2](https://github.com/ikware99/wifit3/issues/2) |
| 任务 C：无线能力体检工具 | [issue #3](https://github.com/ikware99/wifit3/issues/3) |
| 移交分支 | `feature/intel-9462-virtual-adapter` |

---

## 核心结论（已实测，勿重复验证）

**"用 PyUSB 走 USB 总线适配板载 9462"在物理层不可能**——但"独立开发一条适配通路"可行，能力上限已被固件锁死。

### 硬事实

1. **9462 是 CNVi 架构**：802.11 MAC + 基带 + 固件在 CPU/PCH 内部，板载 M.2 模块只是射频前端（CRF）。
2. **固件层直接拒绝注入**（本机 `netsh wlan show wirelesscapabilities`）：
   ```
   网络监视模式 : 不支持     ← 决定性
   混杂模式     : 不支持
   软 AP        : 不支持
   IBSS         : 不支持
   ```
   → wifit3 的 deauth / WPS / WEP / PMKID 主动采集**全部不可用**，只能被动嗅探。
3. **USB 总线上的 `8087:0aaa` 是蓝牙**，不是 Wi-Fi（`bDeviceClass=0xE0` 极易误判）。
4. **上游 381 个受支持 VID:PID 中 Intel 为 0 项**（`0x8086`/`0x8087` 均为 0）。

### 已排除的方案

| 方案 | 结论 | 依据 |
|---|---|---|
| PyUSB 直连 9462 | ❌ | MAC 在 PCH 内，USB 总线上只有蓝牙 |
| USB-to-PCIe 桥 + libusb | ❌ | libusb 不透传 PCIe TLP，访问 BAR 需桥芯片内核驱动 |
| 拆下 CRF 插到别机 | ❌ | Intel 明确 CRF 仅限 CNVi 平台，拆走无 MAC |
| Windows 驱动侧 monitor mode | ❌ | 固件拒绝（见上） |
| Linux iwlwifi monitor | ⚠️ 仅被动 | 内核文档：passive-only, no TX |
| 买 USB 网卡 | ✅ ¥25–110 | 见移交文档 §5 |

---

## 硬件采购建议（性价比优先）

| 频段 | 型号 | 芯片 | 项目评级 | 参考价 |
|---|---|---|---|---|
| 2.4G | **TP-Link TL-WN722N v2/v3** | RTL8188EUS `0bda:817f` | A | ¥25–40 |
| 双频 | **ALFA AWUS036ACM** | MT7612U `0cf3:7612` | A (93%) | ¥80–110 |

⚠️ TL-WN722N **务必买 v2/v3**（v1 是 AR9271，假货多）。到手用 `.workbuddy/tmp/usb_inventory_probe.py` 核验 VID:PID。

---

## 协作方式

- **认领工作项**：在对应 issue 下留言认领，避免多人同时改同一模块。
- **代码落点**：`src/wifit3/chips/<name>/` 是移植主体；`device/manager.py` 仅在同 VID:PID 需区分芯片时才动。完整规则见上游 `docs/porting/METHODOLOGY.md`「What a port may edit」。
- **硬性要求**：USB 通路行为零变化；`uv run pytest -q` 不回归（基线 **5042 passed / 42 skipped / 10 xfailed**）。
- **上游协同**：`Driver.from_usb_device()` 签名写死 `usb.core.Device`，非 USB 通路要接入需改 Driver ABC —— 属上游核心变更，需 `derv82` 同意。已获邀为仓库协作者。

---

## 环境

```bash
uv sync --group dev
uv run wifit3          # 入口
uv run pytest -q       # 基线：5042 passed / 42 skipped / 10 xfailed
```

若 venv 失效（uv 托管的 Python 被清理）：`uv python install 3.12 --reinstall && uv sync --group dev`。

---

## 踩坑速查

1. `usb.core.find()` 裸调抛 `NoBackendError` → 必须传 `backend=libusb_package.get_libusb1_backend()`。
2. `supported_ids()` 返回 **dict**（`{(vid,pid): Claim}`），迭代要 `.items()`，否则匹配表静默为 0。
3. 字符串描述符常抛 `ValueError: The device has no langid` → 逐字段 try/except。
4. `netsh` / `Get-PnpDevice` 输出是**本地化中文**，解析需按中文关键词匹配。
5. `pcap_open_live` 打开 WLAN 适配器会**段错误**（WinPcap 老版本）→ 须子进程隔离。
6. `gh issue list --search` 输出与 JSON 混排，**issue 编号极易误读** → 一律用 `gh api` 精确取。
