# 板载 Intel 9462 适配 · 任务上下文移交文档

> 状态：**已暂停，等待多用户团队接手**
> 日期：2026-11-16
> 仓库：`F:/haha-work/WIFIT3解密`（上游 `derv82/wifit3`，本地已快进至 `6f3f8ae8`）
> 基线：`uv run pytest -q` → **5042 passed, 42 skipped, 15 deselected, 10 xfailed**（移交前干净）

---

## 1. 一句话结论

**"用 PyUSB 走 USB 总线适配板载 9462"在物理层不可能**，但**"独立开发一条适配 9462 的通路"可行且已探明边界**——只是能力上限被固件锁死在**纯被动嗅探**。

---

## 2. 硬件事实（本机实测，不可推翻）

| 项 | 实测值 | 采集方式 |
|---|---|---|
| 网卡 | Intel(R) Wireless-AC 9462 | `Get-PnpDevice` |
| PCI 身份 | `PCI\VEN_8086&DEV_A0F0&SUBSYS_42A48086` | `DEVPKEY_Device_HardwareIds` |
| 位置 | PCI 总线 0 / 设备 20 / 功能 3，父 `ACPI\PNP0A08` | `DEVPKEY_Device_LocationInfo` |
| 架构 | **CNVi** —— MAC+基带+固件在 CPU/PCH 内部，板载 M.2 2230 模块只是 CRF 射频前端 | Intel 官方 CNVi 文档 |
| 驱动 | `Netwtw10.sys`（Intel 闭源），INF `oem243.inf`，段名 `Install_GEN_QSR_JfP1_9462_AC_no_160_1x1_WinT` | `Win32_PnPSignedDriver` |
| 固件 | `D4.DF`；WDI(Win) 0.1.1.10 / WDI(IHV) 0.1.1.12 | `netsh wlan show wirelesscapabilities` |
| 空间流 | Tx 1 / Rx 1，1x1 80MHz | 同上 |
| 当前连接 | SSID `Enhua_a`，信道 149，802.11ac，CCMP | `netsh wlan show interfaces` |

### 2.1 致命约束：固件层直接否决注入

`netsh wlan show wirelesscapabilities` 的**无线设备功能**段：

```
网络监视模式 : 不支持        ← 决定性
混杂模式     : 不支持
软 AP        : 不支持
IBSS         : 不支持
动作帧       : 支持          ← 仅此一项可用
```

**这是固件/驱动自报的能力，不是推测。** 交叉验证：

- Intel 官方支持答复原文：「Windows Monitor mode and package injection are **not supported** on Intel® wireless adapters. This also applies to the promiscuous mode.」
- Linux 侧 iwlwifi 的 monitor VIF 是**纯被动**（内核文档：`this monitor mode is a passive-only mode, no packets are transmitted`）。
- 第三方实测表把 **Intel Tiger Lake PCH CNVi** 列为 `No (not recommended)`：30s monitor 模式延迟、**无法注入 EAPOL**、覆写序列号、无 workaround。

> **直接后果**：wifit3 的 deauth / WPS / WEP / PMKID 主动采集全部依赖 `inject_frame()`，在 9462 上**一个都跑不了**。能做的是被动嗅探 + AP 清单。

### 2.2 USB 总线侧的实测

libusb 枚举到的 4 个设备里，与 9462 相关的**只有蓝牙**：

| VID:PID | 身份 | 备注 |
|---|---|---|
| `8087:0aaa` | Intel 无线蓝牙（9462 的 BT 部分） | bDeviceClass `0xE0`(无线)，**极易误判为 Wi-Fi**，实为 BT |
| `0bda:5520` | Realtek 摄像头 | 字符串描述符无 langid，读不出 |
| `8086:a0ed` | USB 3.0 xHCI 根 Hub | libusb 枚举残留，**不是网卡** |
| `093a:2510` | PixArt 鼠标 | — |

**`8087:0aaa` 是关键陷阱**：它在 USB 总线上、是"无线"类设备，但只承载蓝牙，不承载 802.11。

### 2.3 其他通路均已实测排除

| 通路 | 实测结果 |
|---|---|
| pcap/WinPcap 裸 802.11 | 枚举到 WLAN 适配器但 **datalink = 1 (EN10MB)**，即以太网帧；未装 Npcap 的 802.11 选项 |
| USB-to-PCIe 桥 | libusb 的 vendor control transfer **只到桥接芯片**，不透传 PCIe TLP；访问 BAR MMIO 必须靠桥接芯片自己的内核驱动 → **"PyUSB"与"PCIe 设备"互斥** |
| CNVi 模块移植到别机 | Intel 明确：CRF 只能用于为 CNVi 设计的平台，**单独拆走没有 MAC 可用** |

---

## 3. 仓库架构扩展点（已逐个读源码确认）

这是接手者最需要的部分——**改动落点**。

### 3.1 发现机制（pkgutil 走 `chips/*`）

`src/wifit3/device/manager.py`：

- `supported_ids()` — 遍历 `chips/*` 包的 `__init__.py`，读 `SUPPORTED_IDS`（**不 import driver.py**，轻量），返回 `{(vid,pid): Claim}`。`Claim` 是 NamedTuple `(entry, key, import_driver)`，`entry` 才是 `DeviceID`。
- `devices()` — 走 `UsbBackend.enumerate()` 拿 USB 设备，按 `(vid,pid)` 匹配 `supported_ids()`，打上 `bus`/`address` 后返回 `DeviceID`。
- `wlan_iface(device_id)` — 匹配 → `resolve_driver()` → `driver_cls.from_usb_device(dev, device_id)` → 构造 `WlanInterface`。
- `DeviceManager.bringup()` → `setup.install()`（WinUSB/udev）→ `_connect_and_attach()` → `wlan_iface()` → `iface.connect()`。

### 3.2 USB 抽象层（**这是加新通路的正门**）

`src/wifit3/device/backend.py`：

```python
class UsbBackend(ABC):
    def enumerate(self) -> List[usb.core.Device]: ...
    def find(self, vid, pid, bus=None, address=None) -> Optional[usb.core.Device]: ...
    def find_all(self, vid, pid) -> List[usb.core.Device]: ...
    def node_path(self, dev) -> Optional[str]: ...

class LibusbBackend(UsbBackend): ...          # 桌面 libusb 实现
def set_usb_backend_factory(factory) -> None  # ← 已预留的替换钩子
def usb_backend() -> UsbBackend
```

`set_usb_backend_factory()` 是**官方预留的扩展点**，注释原文即「Override the backend factory, e.g. for an alternative USB transport.」

### 3.3 驱动契约（`chips/driver.py` 的 `Driver` ABC）

抽象方法：`from_usb_device` / `register_rx_callback` / `register_disconnect_callback` / `connect` / `set_channel` / `close` / `_inject_frame` / `_stamp_tx_seq` / `_enable_rx_acks` / `_disable_rx_acks`。

类级常量：`SUPPORTED_CHANNELS`、`FAKE_MAC`（`FakeMacSupport` 枚举）、`CONFLICTING_LINUX_MODULES`、`LINUX_REPLUG_AFTER_MODPROBE`、`DEVICE_REENUMERATES`、`MAX_ACK_DELAY`。

> **关键约束**：`from_usb_device(cls, dev: usb.core.Device, ...)` 签名里写死了 `usb.core.Device`。非 USB 通路要接进来，必须改这个 ABC 签名，或另开一条继承链。**改 ABC 属于上游核心变更，`docs/porting/METHODOLOGY.md` 明确写了 port 不许改 `chips/driver.py`**——需要上游 maintainer（derv82）同意。

### 3.4 帧层（纯 802.11 规范，无 I/O）

`src/wifit3/dot11/`：`parser.py`（`WlanFrameParser.parse_80211_frame`）、`ap.py`（`auth_resp`/`assoc_resp`/`eapol_m1`/`beacon_clone`）、`probe.py`、`ie.py`（`ssid_ie`/`rates_ie`/`ds_param_ie`/`GENERIC_RSN_IE`/`force_psk_akm`）、`eapol.py`、`mac.py`、`rsn.py`、`wpa.py`。

`src/wifit3/wlan/`：`interface.py`（`WlanInterface`，卡级抽象）、`array.py`（`WlanArray`，多卡池 + `lease()`）、`station.py`（`Association` 关联流程）、`sink.py`（`WlanSink` 802.11 状态机）。

`src/wifit3/campaigns/`：`deauth.py`/`pmkid.py`/`wps/`/`wep/`/`eviltwin/`（`FakeAP` 是最完整的 AP 侧实现范式，`fake_ap.py`）。

### 3.5 三个 TUI 屏幕

`ui/screens/`：`splash.py`（设备列表，`device_list_labels()`）→ `scanner.py` → `focus_v2/`。

### 3.6 上游准入规则（**决定方案可行性**）

`docs/porting/METHODOLOGY.md`「What a port may edit」明确允许改动的范围：

```
src/wifit3/chips/<chip>/          # 移植主体
src/wifit3/device/manager.py      # 仅当同一 VID:PID 有多个芯片时做区分
scripts/chips/<chip>/             # 验证脚本
src/wifit3/chips/products.py      # 零售型号
docs/SUPPORTED-HARDWARE.md
```

**明令不许改**：`chips/driver.py`（Driver ABC）、`wlan/`、别的芯片包。
FINAL-CHECKLIST 阶段才可改：`docs/CREDITS.md`、`docs/FIRMWARE.md`、`README.md#supported-hardware`、`tests/chips/<chip>/`。

> 也就是说：**新增一个芯片包（走 USB）完全符合上游规则；新增一条非 USB 通路则需要动 `Driver` ABC，必须先与 derv82 达成一致。**

---

## 4. 已排除的方案（含理由，避免重复劳动）

| 方案 | 结论 | 依据 |
|---|---|---|
| PyUSB 直连 9462 | ❌ 不可能 | MAC 在 PCH 内部，USB 总线上只有蓝牙 |
| USB-to-PCIe 桥 + libusb | ❌ 不可能 | libusb 不透传 PCIe TLP，需桥芯片内核驱动 |
| 拆下 CRF 插到别的机器 | ❌ 不可能 | Intel 明确 CRF 仅限 CNVi 平台 |
| Windows 驱动侧 monitor mode | ❌ 固件拒绝 | `netsh` 报"网络监视模式：不支持" |
| Linux iwlwifi monitor | ⚠️ 仅被动 | 内核文档：passive-only, no TX |
| 换 AX201/AX210（PCIe 非 CNVi） | ❌ 同样无注入 | 换过去仍是同一固件限制 |
| **买 USB 网卡** | ✅ **¥25–110 解决** | 见 §5 |

---

## 5. 推荐的硬件采购（性价比优先）

| 频段 | 型号 | 芯片 | 项目评级 | 参考价 |
|---|---|---|---|---|
| 2.4G | **TP-Link TL-WN722N v2/v3** | RTL8188EUS `0bda:817f` | **A** | ¥25–40 |
| 双频 | **ALFA AWUS036ACM** | MT7612U `0cf3:7612` | **A (93%)** | ¥80–110 |
| 双频备选 | ALFA AWUS036AXML | MT7921AU | A | ¥110–140 |
| 双频备选 | TP-Link Archer T3U Plus | RTL8822BU | A | ¥60–100 |

⚠️ **TL-WN722N 务必买 v2/v3**，v1 是 AR9271，且假货多（v1/v2/v3 芯片混乱是普遍现象）。到手用 §6.2 的探测脚本核验 VID:PID。

---

## 6. 待办工作项（可并行分工）

### 6.1 【最高价值】Path B：虚拟 USB WiFi 适配器

**目标**：让 wifit3 在**没有实体网卡**时也能完整跑通扫描 / PMKID / 破解流程——这既是 CI 基础设施，也是 9462 案的降级兜底。

**落点**：`src/wifit3/chips/` 下新增包，或走 `device/backend.py` 的 `set_usb_backend_factory()` 钩子提供**虚拟 backend**（让 PyUSB 看到一个合成设备）。

**已有可复用件**：`dot11/ap.py` 的 `auth_resp`/`assoc_resp`/`eapol_m1`/`beacon_clone`，`campaigns/eviltwin/fake_ap.py` 的 `FakeAP`（**最完整的 AP 侧实现范式**，含 probe/auth/assoc/M1 状态机与 per-client ANonce）。

**验收**：合成 AP 信标能被 `WlanFrameParser` 解析 → `WlanSink` 正确建 AP → PMKID 战役跑完 → 产出 `.hc22000` → 可被 hashcat 破解。

**注**：此路径**不动 `Driver` ABC**，不触碰 USB 通路，符合上游 port 规则。

### 6.2 Path A：9462 独立探测通路

**目标**：新增一条**独立于 USB 总线**的 9462 探测通路，把板载卡纳入 wifit3 的视野——**作为"检测到但能力受限"的条目**呈现，而不是冒充可用网卡。

**落点**：新增 `src/wifit3/device/pcie.py`（枚举 `PCI\VEN_8086&DEV_A0F0`），产出 `DeviceID` 并接入 `supported_ids()` 体系。

**必须同时解决的架构问题**：`DeviceID` 的 `vid`/`pid` 是 **USB 语义**；9462 的身份是 `VEN/DEV/SUBSYS`。需要决定复用 `DeviceID`（填 PCI 身份）还是引入独立的设备标识模型。

**能力边界的诚实呈现**：条目上必须明确标注 **"被动嗅探 / 无注入"**，避免用户以为 deauth 能用——否则是危险的误导。

### 6.3 固件能力探测工具

把 §2.1 的 `netsh` 探测固化为脚本/模块：**读 `netsh wlan show wirelesscapabilities` → 判断网络监视模式支持 → 给出明确结论**。这是 Path A 任何实现的前置门禁，也能做成通用的"本机无线能力体检"。

### 6.4 上游协作（**推荐先做**）

上游 `derv82/wifit3` 当前 **58 个 issue 中无任何 Intel/9462/CNVi 相关条目**——这是空白市场。

- 本仓库 `origin` 指向**上游**（无自己的 fork），本地 `master` 与上游 `6f3f8ae8` 一致，无未推送提交。
- 建议：向 derv82 提 issue 陈述 CNVi 架构事实 + 固件层"网络监视模式：不支持"的实测证据 + 虚拟适配器方案，请其确认 `Driver` ABC 是否允许扩展非 USB 通路。
- 已有贡献者活跃（如 `xxcosita3czxx`），是既有的协作网络。

---

## 7. 复现命令（本机可直接跑）

```bash
cd F:/haha-work/WIFIT3解密

# 环境（若 venv 失效）
uv python install 3.12 --reinstall && uv sync --group dev

# USB 枚举 + 支持清单比对
.venv/Scripts/python.exe .workbuddy/tmp/usb_inventory_probe.py

# 固件层能力体检（决定性证据）
netsh wlan show wirelesscapabilities      # 看"网络监视模式"一行
netsh wlan show interfaces

# 探测脚本清单
.workbuddy/tmp/usb_inventory_probe.py     # USB 枚举 + 清单比对
.workbuddy/tmp/pcap_80211_probe.py        # pcap 设备 + DLT
.workbuddy/tmp/pcap_open_probe.py         # 逐设备 open（注意：会段错误，须子进程隔离）
```

**踩坑记录**：
1. `usb.core.find()` 裸调抛 `NoBackendError` → 必须 `import libusb_package` 并传 `backend=libusb_package.get_libusb1_backend()`。
2. `supported_ids()` 返回的是 **dict**（`{(vid,pid): Claim}`），不是 list；迭代要取 `.items()`，否则匹配表静默为 0。
3. 字符串描述符常抛 `ValueError: The device has no langid` → 必须逐字段 try/except。
4. `netsh`/`Get-PnpDevice` 输出是**中文本地化**的，解析需按中文关键词匹配。
5. `pcap_open_live` 打开 WLAN 适配器会**段错误**（WinPcap 老版本），必须子进程隔离。
6. `gh issue list --search` 的输出会与 JSON 混排，**编号极易误读**（我误把 #14/#286 当成 9462 相关，实为无关 bug）→ 一律用 `gh api` 精确取。

---

## 8. 环境与基线

- Python 3.12.13（uv 托管），`uv sync --group dev`，`uv run wifit3` 为入口。
- 依赖：pyusb 1.3.1 + libusb_package + textual。
- `uv run pytest -q` → **5042 passed / 42 skipped / 10 xfailed**（75s）。
- 上游已到 `6f3f8ae8`，较上一轮巡检基线 `35c69339` 前进 **499 提交**，标签 v0.5.0→v0.7.1。
- 支持清单：**294 → 381** 个 VID:PID（+87，移除 0）。新增 `rtl8188ftv_dkms`（RTL8188FTV `0bda:f179`）。**0 个 Intel**（`0x8086`/`0x8087` 均为 0 项）。

---

## 9. 交接检查单

- [x] 硬件事实与固件能力已实测（§2），含可复现命令
- [x] 仓库扩展点已逐个读源码定位（§3）
- [x] 不可行方案已排除并留证（§4）
- [x] 硬件采购建议（§5）与上游准入规则（§3.6）成文
- [x] 待办拆分为可并行的 4 个工作项（§6）
- [x] 踩坑记录（§7）与环境基线（§8）固化
- [x] 已有探测脚本落在 `.workbuddy/tmp/`（可直接复用）
- [ ] **代码实现：虚拟 WiFi 适配器（§6.1）—— 已暂停，待团队接手**
- [ ] **代码实现：9462 探测通路（§6.2）—— 已暂停，待团队接手**
