"""Tests for the host wireless capability probe: parsers over recorded netsh / iw output.

The snapshots are verbatim excerpts from a live Chinese Windows 11 host (Intel
Wireless-AC 9462) and from an English netsh build, so the localised parsing is
exercised without needing that hardware in CI.
"""
from __future__ import annotations

import json

from wifit3 import wireless_capabilities as wc

NETSH_CAPS_ZH = """
无线设备功能
----------------------------

接口名称: WLAN

    WDI 版本(Windows)                       : 0.1.1.10

    固件版本                            : D4.DF

    站                                     : 支持

    软 AP                                     : 不支持

    网络监视模式                        : 不支持

    动作帧                                : 支持

    IBSS                                        : 不支持

    混杂模式                             : 不支持

    受保护管理帧                 : 支持
"""

NETSH_CAPS_EN = """
Wireless Device Capabilities
----------------------------

Interface name: WLAN

    WDI Version (Windows)                    : 0.1.1.10
    Station                                  : Supported
    Soft AP                                  : Not supported
    Network monitor mode                     : Not supported
    Action frames                            : Supported
    IBSS                                     : Not supported
    Promiscuous mode                         : Not supported
    Protected Management Frames              : Supported
"""

NETSH_IFACES_ZH = """
系统上有 1 个接口:

    名称                   : WLAN
    描述                   : Intel(R) Wireless-AC 9462
    GUID                   : 00000000-0000-0000-0000-000000000000
    物理地址               : 02:00:00:00:00:01
    状态                   : 已连接
    SSID                   : lab-network
    BSSID                  : aa:bb:cc:dd:ee:ff
    网络类型               : 结构
    无线电类型             : 802.11ac
    信道                   : 149
"""

NETSH_DRIVERS_ZH = """
接口名称: WLAN

    驱动程序                  : Intel(R) Wireless-AC 9462
    供应商                    : Intel Corporation
    提供程序                  : Intel
    版本                      : 23.60.1.2
    INF 文件                  : oem243.inf
    类型                      : 本机 WLAN 驱动程序
    支持的无线电类型          : 802.11b 802.11g 802.11n 802.11a 802.11ac
"""

IW_LIST = """
Wiphy phy0
	max # scan SSIDs: 20
	supported interface modes:
		 * IBSS
		 * managed
		 * AP
		 * P2P-client
		 * P2P-GO
		 * monitor
		 * P2P-device
	Band 1:
"""

IW_LIST_NO_MONITOR = """
Wiphy phy0
	supported interface modes:
		 * managed
		 * AP
"""

IW_DEV = """
phy#0
	Unnamed/non-netdev interface
		wdev 0x2
		Interface wlan0
		ifindex 2
		type managed
"""


def _adapter(**kwargs) -> wc.AdapterReport:
    base = dict(name="WLAN", radio_type="802.11ac")
    base.update(kwargs)
    return wc.AdapterReport(**base)


def _with_caps(adapter: wc.AdapterReport, caps: dict) -> wc.AdapterReport:
    adapter.capabilities = wc.parse_capabilities(NETSH_CAPS_ZH)[caps["iface"]]
    return adapter


# ---- netsh parsing --------------------------------------------------------

def test_parse_capabilities_chinese_maps_the_decisive_fields():
    caps = wc.parse_capabilities(NETSH_CAPS_ZH)
    assert set(caps) == {"WLAN"}
    wlan = caps["WLAN"]
    assert wlan["monitor_mode"].value is False
    assert wlan["promiscuous"].value is False
    assert wlan["soft_ap"].value is False
    assert wlan["ibss"].value is False
    assert wlan["action_frames"].value is True
    assert wlan["protected_mgmt"].value is True
    assert wlan["monitor_mode"].raw == "网络监视模式                        : 不支持"


def test_parse_capabilities_english_wording():
    wlan = wc.parse_capabilities(NETSH_CAPS_EN)["WLAN"]
    assert wlan["monitor_mode"].value is False
    assert wlan["action_frames"].value is True
    assert wlan["protected_mgmt"].value is True


def test_parse_capabilities_ignores_the_system_section():
    """``无线系统功能`` precedes the device block and repeats labels; its values must not leak.

    Note the operative guard is ``current is None`` (nothing is attributed before the first
    ``接口名称``), not the ``started`` flag: the flag is redundant defence, and no realistic
    netsh output can tell the two apart, so this asserts the contract rather than either guard.
    """
    text = ("无线系统功能\n----------------------------\n    动作帧 : 支持\n    共存支持 : 未知\n"
            "无线设备功能\n----------------------------\n接口名称: WLAN\n"
            "    网络监视模式 : 不支持\n")
    caps = wc.parse_capabilities(text)
    assert caps["WLAN"]["monitor_mode"].value is False
    assert "action_frames" not in caps["WLAN"]      # only the device block may contribute


def test_parse_interfaces_reads_the_adapter_identity():
    adapters = wc.parse_interfaces(NETSH_IFACES_ZH)
    assert len(adapters) == 1
    adapter = adapters[0]
    assert adapter.name == "WLAN"
    assert adapter.description == "Intel(R) Wireless-AC 9462"
    assert adapter.radio_type == "802.11ac"
    assert adapter.channel == "149"
    assert adapter.mac == "02:00:00:00:00:01"


def test_parse_interfaces_english_wording():
    text = """There is 1 interface on the system:

    Name                   : WLAN
    Description            : Intel(R) Wireless-AC 9462
    Radio type             : 802.11ac
    Channel                : 149
"""
    adapter = wc.parse_interfaces(text)[0]
    assert adapter.description == "Intel(R) Wireless-AC 9462"
    assert adapter.channel == "149"


def test_parse_drivers_keeps_version_and_inf():
    info = wc.parse_drivers(NETSH_DRIVERS_ZH)["WLAN"]
    assert info["driver"] == "Intel(R) Wireless-AC 9462"
    assert info["driver_inf"] == "oem243.inf"
    assert info["driver_version"] == "23.60.1.2"
    assert info["driver_vendor"] == "Intel Corporation"


# ---- verdicts -------------------------------------------------------------

def test_classify_bound_working_driver_is_firmware_refused():
    adapter = _with_caps(_adapter(), {"iface": "WLAN"})
    verdict, detail = wc.classify(adapter)
    assert verdict is wc.Verdict.FIRMWARE_REFUSED
    assert "no monitor mode" in detail


def test_classify_no_radio_and_no_caps_is_hardware_lacking():
    adapter = wc.AdapterReport(name="WLAN")
    verdict, _detail = wc.classify(adapter)
    assert verdict is wc.Verdict.HARDWARE_LACKING


def test_classify_no_adapter_at_all_is_driver_unsupported():
    verdict, _detail = wc.classify(wc.AdapterReport(name=""))
    assert verdict is wc.Verdict.DRIVER_UNSUPPORTED


def test_classify_radio_without_a_monitor_report_is_unknown():
    adapter = _adapter(radio_type="802.11ac")
    adapter.capabilities = {}
    verdict, _detail = wc.classify(adapter)
    assert verdict is wc.Verdict.UNKNOWN


def test_classify_monitor_reported_is_passive_only_on_windows():
    adapter = _adapter()
    adapter.capabilities = {
        "monitor_mode": wc.Capability("monitor_mode", "Network monitor mode", True, "x")}
    verdict, _detail = wc.classify(adapter)
    assert verdict is wc.Verdict.PASSIVE_ONLY


def test_linux_iwlwifi_monitor_is_passive_only():
    verdict, detail = wc.classify_linux(True, "iwlwifi")
    assert verdict is wc.Verdict.PASSIVE_ONLY
    assert "iwlwifi" in detail


def test_linux_ath9k_monitor_is_injection_capable():
    verdict, _detail = wc.classify_linux(True, "ath9k")
    assert verdict is wc.Verdict.INJECTION_CAPABLE


def test_linux_without_monitor_is_firmware_refused():
    verdict, _detail = wc.classify_linux(False, "iwlwifi")
    assert verdict is wc.Verdict.FIRMWARE_REFUSED


def test_parse_iw_list_and_dev():
    phys = wc.parse_iw_list(IW_LIST)
    assert phys[0]["phy"] == "phy0"
    assert "monitor" in phys[0]["modes"]
    assert "monitor" not in wc.parse_iw_list(IW_LIST_NO_MONITOR)[0]["modes"]
    assert wc.parse_iw_dev(IW_DEV) == [{"iface": "wlan0", "phy": "phy0"}]


# ---- rendering ------------------------------------------------------------

def test_render_quotes_the_os_evidence():
    adapter = _with_caps(_adapter(), {"iface": "WLAN"})
    adapter.verdict, adapter.verdict_detail = wc.classify(adapter)
    adapter.evidence = [cap.raw for cap in adapter.capabilities.values()]
    text = wc.render(wc.ProbeReport(platform="win32", adapters=[adapter]))
    assert "verdict: firmware_refused" in text
    assert "网络监视模式 : 不支持" in text      # squeezed, still verbatim
    assert "monitor_mode" in text


def test_render_reports_a_probe_error():
    text = wc.render(wc.ProbeReport(platform="linux", error="iw is not installed"))
    assert "ERROR: iw is not installed" in text


def test_main_json_emits_the_verdict(monkeypatch, capsys):
    adapter = _with_caps(_adapter(), {"iface": "WLAN"})
    adapter.verdict, adapter.verdict_detail = wc.classify(adapter)
    monkeypatch.setattr(wc, "probe", lambda: wc.ProbeReport(platform="win32",
                                                           adapters=[adapter]))
    assert wc.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapters"][0]["verdict"] == "firmware_refused"
    assert payload["adapters"][0]["capabilities"]["monitor_mode"] is False


def test_main_without_adapters_exits_nonzero(monkeypatch, capsys):
    monkeypatch.setattr(wc, "probe", lambda: wc.ProbeReport(platform="win32",
                                                           error="no wireless service"))
    assert wc.main([]) == 1


def test_display_width_counts_cjk_as_two_cells():
    assert wc.display_width("abc") == 3
    assert wc.display_width("网络") == 4
    assert wc.pad("网络", 6) == "网络  "


# ---- the probe orchestration ------------------------------------------------
# The parsers above are pure and well covered; these cover the layer that actually runs the
# console tools, because that is the only path a user invokes and it can fail in ways the
# parsers never see (service stopped, tool missing, no interface, wrong encoding).

def _fake_run(monkeypatch, mapping):
    """Make ``_run`` answer per-argument-prefix from ``mapping`` and record the calls."""
    calls = []

    def fake(args):
        calls.append(list(args))
        return mapping.get(tuple(args), "")

    monkeypatch.setattr(wc, "_run", fake)
    return calls


def test_probe_windows_reports_a_stopped_wireless_service(monkeypatch):
    _fake_run(monkeypatch, {})
    report = wc.probe_windows()
    assert "WLAN AutoConfig" in report.error
    assert report.adapters == []


def test_probe_windows_falls_back_to_capabilities_when_no_interface_is_up(monkeypatch):
    """A radio in a disconnected state still reports capabilities under its own name."""
    _fake_run(monkeypatch, {("netsh", "wlan", "show", "wirelesscapabilities"): NETSH_CAPS_ZH})
    report = wc.probe_windows()
    assert report.error == ""
    assert [a.name for a in report.adapters] == ["WLAN"]
    assert report.adapters[0].verdict is wc.Verdict.FIRMWARE_REFUSED


def test_probe_windows_merges_the_driver_block_and_quotes_evidence(monkeypatch):
    _fake_run(monkeypatch, {
        ("netsh", "wlan", "show", "wirelesscapabilities"): NETSH_CAPS_ZH,
        ("netsh", "wlan", "show", "interfaces"): NETSH_IFACES_ZH,
        ("netsh", "wlan", "show", "drivers"): NETSH_DRIVERS_ZH,
    })
    adapter = wc.probe_windows().adapters[0]
    assert adapter.driver == "Intel(R) Wireless-AC 9462"
    assert adapter.driver_version == "23.60.1.2"
    assert adapter.driver_inf == "oem243.inf"
    assert adapter.driver_provider == "Intel"
    assert any(e.startswith("driver: ") and "oem243.inf" in e for e in adapter.evidence)
    assert adapter.verdict is wc.Verdict.FIRMWARE_REFUSED


def test_probe_windows_notes_npcap_absence(monkeypatch):
    _fake_run(monkeypatch, {("netsh", "wlan", "show", "wirelesscapabilities"): NETSH_CAPS_ZH})
    monkeypatch.setattr(wc, "find_npcap", lambda: "")
    assert any("No Npcap" in n for n in wc.probe_windows().notes)


def test_probe_windows_notes_npcap_presence(monkeypatch):
    _fake_run(monkeypatch, {("netsh", "wlan", "show", "wirelesscapabilities"): NETSH_CAPS_ZH})
    monkeypatch.setattr(wc, "find_npcap", lambda: r"C:/Windows/System32/Npcap/wpcap.dll")
    assert any("Support raw 802.11" in n for n in wc.probe_windows().notes)


def test_probe_linux_reports_a_missing_iw(monkeypatch):
    monkeypatch.setattr(wc.shutil, "which", lambda _name: None)
    report = wc.probe_linux()
    assert "iw is not installed" in report.error
    assert report.adapters == []


def test_probe_linux_reports_no_interface(monkeypatch):
    monkeypatch.setattr(wc.shutil, "which", lambda _name: "/usr/bin/iw")
    _fake_run(monkeypatch, {("iw", "list"): IW_LIST})
    report = wc.probe_linux()
    assert "no wireless interface" in report.error


def test_probe_linux_reads_modes_and_classifies_the_driver(monkeypatch):
    monkeypatch.setattr(wc.shutil, "which", lambda _name: "/usr/bin/iw")
    monkeypatch.setattr(wc, "_linux_driver", lambda _iface: "ath9k")
    _fake_run(monkeypatch, {("iw", "list"): IW_LIST, ("iw", "dev"): IW_DEV})
    report = wc.probe_linux()
    assert report.error == ""
    adapter = report.adapters[0]
    assert adapter.name == "wlan0"
    assert adapter.driver == "ath9k"
    assert adapter.capabilities["monitor_mode"].value is True
    assert adapter.verdict is wc.Verdict.INJECTION_CAPABLE
    assert any("ath9k" in e for e in adapter.evidence)


def test_probe_linux_without_monitor_mode_is_firmware_refused(monkeypatch):
    monkeypatch.setattr(wc.shutil, "which", lambda _name: "/usr/bin/iw")
    monkeypatch.setattr(wc, "_linux_driver", lambda _iface: "iwlwifi")
    _fake_run(monkeypatch, {("iw", "list"): IW_LIST_NO_MONITOR, ("iw", "dev"): IW_DEV})
    assert wc.probe_linux().adapters[0].verdict is wc.Verdict.FIRMWARE_REFUSED


def test_probe_dispatches_on_the_platform(monkeypatch):
    monkeypatch.setattr(wc.sys, "platform", "darwin")
    assert "unsupported platform" in wc.probe().error


def test_linux_unknown_driver_is_passive_only():
    """The honest tier: a monitor VIF exists, but TX is unproven for this driver."""
    verdict, detail = wc.classify_linux(True, "rndis_wlan")
    assert verdict is wc.Verdict.PASSIVE_ONLY
    assert "not a known injection-capable driver" in detail


def test_bool_of_maps_the_unknown_markers_to_none():
    """netsh reports "unknown"/"unavailable" on some builds; that is not a "supported"."""
    for marker in ("未知", "值不可用", "n/a", "unknown"):
        assert wc._bool_of(marker) is None


def test_kv_splits_on_a_full_width_colon():
    """A Chinese netsh build pads and delimiters with the full-width colon."""
    assert wc._kv("混杂模式：不支持") == ("混杂模式", "不支持")
