"""Host wireless capability probe: what can this machine's radios actually do?

Every monitor-mode / injection workflow has to ask one question before it starts:
does this OS + driver + firmware combination expose 802.11 monitor mode and raw
frame injection? Windows answers through WDI (``netsh wlan show
wirelesscapabilities``); Linux answers through ``iw list``.

The probe separates three refusal tiers, because they imply different remedies:

``DRIVER_UNSUPPORTED``
    No wireless interface at all, or the radio never bound a driver.
``HARDWARE_LACKING``
    A radio with no usable PHY: nothing reports a radio type or capability set.
``FIRMWARE_REFUSED``
    Driver and firmware are up and the card works, yet the capability is
    reported absent. User space cannot override this; only different silicon can.

The evidence behind each verdict is the OS's own line, quoted verbatim, so a
verdict can always be traced back to what the machine said.
"""
from __future__ import annotations

import argparse
import enum
import os
import re
import shutil
import subprocess
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


class Verdict(str, enum.Enum):
    """What the stack will actually let this radio do."""

    INJECTION_CAPABLE = "injection_capable"
    """Monitor mode plus raw TX: the full wifit3 campaign set can run."""
    PASSIVE_ONLY = "passive_only"
    """Monitor mode without TX: capture and AP discovery only."""
    FIRMWARE_REFUSED = "firmware_refused"
    """Driver and firmware live, capability reported absent. Not fixable in user space."""
    DRIVER_UNSUPPORTED = "driver_unsupported"
    """No wireless interface, or no driver bound to the radio."""
    HARDWARE_LACKING = "hardware_lacking"
    """The radio reports no usable PHY or capability set."""
    UNKNOWN = "unknown"
    """The OS reported nothing usable about this adapter."""


# Capability keys the probe tracks, in the order they are rendered.
CAPABILITY_ORDER: Tuple[str, ...] = (
    "monitor_mode", "promiscuous", "soft_ap", "ibss", "action_frames", "protected_mgmt",
)

# OS label (lower-cased, localised) to our key. netsh prints these labels localised, so both the
# Chinese and the English wording are matched.
_LABELS: Dict[str, str] = {
    "网络监视模式": "monitor_mode",
    "network monitor mode": "monitor_mode",
    "wireless monitor mode": "monitor_mode",
    "混杂模式": "promiscuous",
    "promiscuous mode": "promiscuous",
    "软 ap": "soft_ap",
    "soft ap": "soft_ap",
    "hosted network": "soft_ap",
    "ibss": "ibss",
    "动作帧": "action_frames",
    "action frames": "action_frames",
    "受保护管理帧": "protected_mgmt",
    "protected management frames": "protected_mgmt",
}

_TRUE = {"支持", "supported", "yes", "是", "true"}
_FALSE = {"不支持", "not supported", "no", "否", "false"}
_UNKNOWN = {"未知", "unknown", "值不可用", "不可用", "n/a"}

_CAPS_HEADINGS = ("无线设备功能", "wireless device capabilities")
_IFACE_HEADINGS = ("接口名称", "interface name")
_IW_MONITOR_DRIVERS = ("ath9k", "ath10k", "ath11k", "ath12k", "rtw88", "rtw89", "rt2x00",
                       "mt76", "mt7601u", "rtl8xxxu", "carl9170", "p54", "ar5523")


@dataclass(frozen=True)
class Capability:
    """One line of the OS's capability report, verbatim plus its interpretation."""

    key: str
    label: str
    value: Optional[bool]
    raw: str
    value_text: str = ""

    def rendered(self) -> str:
        return {True: "yes", False: "no", None: "unknown"}[self.value]


@dataclass
class AdapterReport:
    """One radio, as the OS describes it, with a verdict and the evidence behind it."""

    name: str
    description: str = ""
    guid: str = ""
    mac: str = ""
    state: str = ""
    radio_type: str = ""
    channel: str = ""
    ssid: str = ""
    bssid: str = ""
    driver: str = ""
    driver_vendor: str = ""
    driver_provider: str = ""
    driver_version: str = ""
    driver_inf: str = ""
    capabilities: Dict[str, Capability] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    verdict: Verdict = Verdict.UNKNOWN
    verdict_detail: str = ""

    def capability(self, key: str) -> Optional[Capability]:
        return self.capabilities.get(key)

    @property
    def monitor(self) -> bool:
        cap = self.capabilities.get("monitor_mode")
        return bool(cap and cap.value)

    @property
    def injection(self) -> bool:
        """Raw TX needs monitor mode; Windows never reaches this, Linux per driver."""
        return self.verdict is Verdict.INJECTION_CAPABLE


@dataclass
class ProbeReport:
    """Every radio on this host, plus the platform notes that frame the verdicts."""

    platform: str
    adapters: List[AdapterReport] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    error: str = ""


# ---- small text helpers ----------------------------------------------------

def _kv(line: str) -> Optional[Tuple[str, str]]:
    """``"label : value"`` split on the first ASCII or full-width colon, or None."""
    parts = re.split(r"[:：]", line, maxsplit=1)
    if len(parts) != 2:
        return None
    label, value = parts[0].strip(), parts[1].strip()
    if not label:
        return None
    return label, value


def _bool_of(value: str) -> Optional[bool]:
    v = value.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    if v in _UNKNOWN:
        return None
    return None


def _cap_key(label: str) -> Optional[str]:
    return _LABELS.get(label.strip().lower())


def display_width(text: str) -> int:
    """Rendered width in terminal cells (CJK and full-width punctuation take two)."""
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)


def pad(text: str, width: int) -> str:
    return text + " " * max(0, width - display_width(text))


def _squeeze(text: str) -> str:
    """Collapse the OS's column padding so a quoted evidence line stays readable."""
    return re.sub(r"\s{2,}", " ", text).strip()


# ---- Windows: netsh parsers (pure, so the snapshots are testable) ----------

def parse_capabilities(text: str) -> Dict[str, Dict[str, Capability]]:
    """``{interface name: {key: Capability}}`` from ``netsh wlan show wirelesscapabilities``."""
    out: Dict[str, Dict[str, Capability]] = {}
    current: Optional[str] = None
    started = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or set(line) <= {"-"}:
            continue
        lowered = line.lower()
        if any(lowered.startswith(h) for h in _CAPS_HEADINGS):
            started = True
            continue
        if not started:
            continue
        kv = _kv(line)
        if kv is None:
            continue
        label, value = kv
        if label.strip().lower() in _IFACE_HEADINGS:
            current = value
            out.setdefault(current, {})
            continue
        key = _cap_key(label)
        if key is None or current is None:
            continue
        out[current][key] = Capability(key=key, label=label, value=_bool_of(value),
                                       raw=line, value_text=value)
    return out


_IFACE_FIELDS = {
    "名称": "name",
    "name": "name",
    "描述": "description",
    "description": "description",
    "guid": "guid",
    "物理地址": "mac",
    "physical address": "mac",
    "状态": "state",
    "state": "state",
    "ssid": "ssid",
    "bssid": "bssid",
    "无线电类型": "radio_type",
    "radio type": "radio_type",
    "信道": "channel",
    "channel": "channel",
}


def parse_interfaces(text: str) -> List[AdapterReport]:
    """One ``AdapterReport`` per interface from ``netsh wlan show interfaces``."""
    out: List[AdapterReport] = []
    current: Optional[AdapterReport] = None
    for raw_line in text.splitlines():
        kv = _kv(raw_line.strip())
        if kv is None:
            continue
        label, value = kv
        slot = _IFACE_FIELDS.get(label.strip().lower())
        if slot is None:
            continue
        if slot == "name":
            current = AdapterReport(name=value)
            out.append(current)
        elif current is not None:
            setattr(current, slot, value)
    return out


# netsh reports the driver's display name here ("Intel(R) Wireless-AC 9462"), not the .sys file
# name; the INF and version are what make the driver identifiable.
_DRIVER_FIELDS = {
    "供应商": "driver_vendor",
    "provider": "driver_vendor",
    "提供程序": "driver_provider",
    "inf 文件": "driver_inf",
    "inf file": "driver_inf",
    "驱动程序": "driver",
    "driver": "driver",
    "版本": "driver_version",
    "version": "driver_version",
}


def parse_drivers(text: str) -> Dict[str, Dict[str, str]]:
    """``{interface name: {field: value}}`` from ``netsh wlan show drivers``.

    The block heading is localised (``接口 WLAN 驱动程序`` / ``Interface name: WLAN``), so the
    interface is taken from whichever heading line carries it.
    """
    out: Dict[str, Dict[str, str]] = {}
    current: Optional[str] = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        kv = _kv(line)
        if kv is not None:
            label, value = kv
            key = label.strip().lower()
            if key in _IFACE_HEADINGS:
                current = value
                out.setdefault(current, {})
                continue
            slot = _DRIVER_FIELDS.get(key)
            if slot and current is not None:
                out[current][slot] = value
            continue
        heading = re.match(r"^(?:接口|interface)\s+(\S+)\s+(?:驱动程序|driver)$", line, re.IGNORECASE)
        if heading:
            current = heading.group(1)
            out.setdefault(current, {})
    return out


# ---- Windows: probe -------------------------------------------------------

def _run(args: Sequence[str]) -> str:
    """Run a console tool and decode its output (netsh prints the OEM code page)."""
    try:
        proc = subprocess.run(args, capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return ""
    encodings = ("gbk", "utf-8", "mbcs") if sys.platform == "win32" else ("utf-8",)
    for encoding in encodings:
        try:
            return proc.stdout.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return proc.stdout.decode("utf-8", "replace")


def _linux_driver(iface: str) -> str:
    """The kernel module bound to ``iface``: the ``device/driver`` symlink, else ethtool."""
    link = Path(f"/sys/class/net/{iface}/device/driver")
    try:
        # readlink, not resolve(): resolve(strict=False) returns the literal "driver" when the
        # symlink is absent (any virtual interface), which then skips the ethtool fallback.
        return os.path.basename(os.readlink(link))
    except OSError:
        pass
    if shutil.which("ethtool"):
        for line in _run(["ethtool", "-i", iface]).splitlines():
            if line.strip().lower().startswith("driver:"):
                return line.split(":", 1)[1].strip()
    return ""


def find_npcap() -> str:
    """Path of wpcap.dll when Npcap or WinPcap is installed, else empty."""
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    for candidate in (system32 / "Npcap" / "wpcap.dll", system32 / "wpcap.dll"):
        if candidate.is_file():
            return str(candidate)
    return ""


def classify(adapter: AdapterReport) -> Tuple[Verdict, str]:
    """Verdict plus a one-line reason, from an adapter's reported capabilities."""
    monitor = adapter.capabilities.get("monitor_mode")
    reported = [c for c in adapter.capabilities.values() if c.value is not None]

    if not adapter.radio_type and not reported:
        if adapter.name:
            return (Verdict.HARDWARE_LACKING,
                    "the adapter reports neither a radio type nor any capability")
        return (Verdict.DRIVER_UNSUPPORTED,
                "no wireless interface is present; no driver is bound to a radio")

    if monitor is None:
        return (Verdict.UNKNOWN,
                "the OS did not report monitor mode for this adapter")

    if monitor.value:
        return (Verdict.PASSIVE_ONLY,
                "monitor mode is reported, but the OS gives user space no raw TX path")

    detail = ("driver and firmware are up, yet the radio reports no monitor mode; "
              "injection needs monitor mode plus raw TX, so the active campaigns "
              "(deauth / WPS / WEP / PMKID) cannot run on this card")
    return Verdict.FIRMWARE_REFUSED, detail


def probe_windows() -> ProbeReport:
    report = ProbeReport(platform="win32")
    caps_text = _run(["netsh", "wlan", "show", "wirelesscapabilities"])
    ifaces_text = _run(["netsh", "wlan", "show", "interfaces"])
    drivers_text = _run(["netsh", "wlan", "show", "drivers"])

    if not caps_text.strip() and not ifaces_text.strip():
        report.error = ("netsh reported no wireless service; the WLAN AutoConfig service "
                        "may be stopped, or this host has no wireless adapter")
        return report

    caps = parse_capabilities(caps_text)
    drivers = parse_drivers(drivers_text)
    adapters = parse_interfaces(ifaces_text)

    if not adapters:
        # A radio can be present but not in a connectable state; still report its capabilities.
        adapters = [AdapterReport(name=name) for name in caps]

    for adapter in adapters:
        adapter.capabilities = caps.get(adapter.name, {})
        info = drivers.get(adapter.name, {})
        adapter.driver = info.get("driver", "")
        adapter.driver_vendor = info.get("driver_vendor", "")
        adapter.driver_provider = info.get("driver_provider", "")
        adapter.driver_version = info.get("driver_version", "")
        adapter.driver_inf = info.get("driver_inf", "")
        adapter.verdict, adapter.verdict_detail = classify(adapter)
        adapter.evidence = [cap.raw for key in CAPABILITY_ORDER
                            if (cap := adapter.capabilities.get(key)) is not None]
        if adapter.driver:
            parts = [adapter.driver]
            if adapter.driver_version:
                parts.append(f"version {adapter.driver_version}")
            if adapter.driver_inf:
                parts.append(f"INF {adapter.driver_inf}")
            if adapter.driver_vendor:
                parts.append(f"vendor {adapter.driver_vendor}")
            adapter.evidence.append("driver: " + ", ".join(parts))

    report.adapters = adapters
    report.notes.append(
        "Windows WDI exposes no 802.11 monitor mode to user space, so \"network monitor "
        "mode: not supported\" is what the WDI stack reports for every adapter. The verdict "
        "still separates this host's tiers: a bound, working driver that reports the "
        "capability absent is firmware_refused, not a missing driver.")
    wpcap = find_npcap()
    if wpcap:
        report.notes.append(
            f"Npcap/WinPcap present ({wpcap}). Installing it with \"Support raw 802.11 "
            "traffic\" enables passive 802.11 captures; it still cannot inject frames.")
    else:
        report.notes.append(
            "No Npcap/WinPcap found. Without it no user-space tool can read 802.11 frames, "
            "passively or otherwise.")
    return report


# ---- Linux: iw parsers ----------------------------------------------------

def parse_iw_list(text: str) -> List[Dict[str, object]]:
    """``[{"phy": "phy0", "modes": [...], "driver": "iwlwifi"}]`` from ``iw list``."""
    phys: List[Dict[str, object]] = []
    current: Optional[Dict[str, object]] = None
    in_modes = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        phy = re.match(r"^Wiphy\s+(\S+)", line)
        if phy:
            current = {"phy": phy.group(1), "modes": [], "driver": ""}
            phys.append(current)
            in_modes = False
            continue
        if current is None:
            continue
        if "supported interface modes" in line.lower():
            in_modes = True
            continue
        if in_modes:
            item = re.match(r"^\s+\*\s+(\S+)$", line)
            if item:
                current["modes"].append(item.group(1))  # type: ignore[union-attr]
                continue
            if line.strip() and not line.startswith("\t\t"):
                in_modes = False
        drv = re.match(r"^\s*driver:\s*(\S+)", line)
        if drv:
            current["driver"] = drv.group(1)
    return phys


def parse_iw_dev(text: str) -> List[Dict[str, str]]:
    """``[{"iface": "wlan0", "phy": "phy0"}]`` from ``iw dev`` (the ``phy#N`` line precedes it)."""
    out: List[Dict[str, str]] = []
    pending_phy = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("phy#"):
            pending_phy = "phy" + line[4:]
            continue
        if line.startswith("Interface "):
            out.append({"iface": line.split(None, 1)[1], "phy": pending_phy})
    return out


def classify_linux(monitor: bool, driver: str) -> Tuple[Verdict, str]:
    if not monitor:
        return (Verdict.FIRMWARE_REFUSED,
                "the radio's supported interface modes do not include monitor")
    if driver == "iwlwifi":
        return (Verdict.PASSIVE_ONLY,
                "iwlwifi exposes a passive-only monitor VIF: capture works, no frame TX")
    if driver in _IW_MONITOR_DRIVERS:
        return (Verdict.INJECTION_CAPABLE,
                f"{driver} exposes an active monitor VIF: capture and raw injection")
    return (Verdict.PASSIVE_ONLY,
            f"monitor mode is listed, but {driver or 'this driver'} is not a known "
            "injection-capable driver; treat TX as unverified")


def probe_linux() -> ProbeReport:
    report = ProbeReport(platform="linux")
    if shutil.which("iw") is None:
        report.error = "iw is not installed; install it (wireless-tools / iw package) to probe"
        return report
    phys = parse_iw_list(_run(["iw", "list"]))
    ifaces = parse_iw_dev(_run(["iw", "dev"]))
    by_phy = {str(p["phy"]): p for p in phys}
    if not ifaces:
        report.error = "no wireless interface found (iw dev reported none)"
        return report
    for entry in ifaces:
        info = by_phy.get(entry.get("phy", ""), {})
        modes = [str(m) for m in info.get("modes", [])]  # type: ignore[union-attr]
        driver = _linux_driver(entry["iface"])
        adapter = AdapterReport(name=entry["iface"], driver=driver)
        monitor = "monitor" in modes
        adapter.capabilities["monitor_mode"] = Capability(
            key="monitor_mode", label="monitor (iw interface mode)", value=monitor,
            raw=f"supported interface modes: {' '.join(modes) or '(none reported)'}")
        adapter.verdict, adapter.verdict_detail = classify_linux(monitor, driver)
        adapter.evidence = [adapter.capabilities["monitor_mode"].raw]
        if driver:
            adapter.evidence.append(f"driver: {driver}")
        report.adapters.append(adapter)
    report.notes.append(
        "Linux: a monitor VIF is not the same as injection. iwlwifi's monitor interface is "
        "passive by design (kernel documentation: no packets are transmitted).")
    return report


def probe() -> ProbeReport:
    """Probe this host, dispatching on the platform."""
    if sys.platform == "win32":
        return probe_windows()
    if sys.platform.startswith("linux"):
        return probe_linux()
    return ProbeReport(platform=sys.platform,
                       error=f"unsupported platform: {sys.platform}")


# ---- rendering ------------------------------------------------------------

def render(report: ProbeReport) -> str:
    """A plain-text report: one block per adapter, the verdict, and its quoted evidence."""
    lines: List[str] = [f"Wireless capability probe (platform: {report.platform})", ""]
    if report.error:
        lines.append(f"ERROR: {report.error}")
        return "\n".join(lines)
    for index, adapter in enumerate(report.adapters, 1):
        lines.append(f"Adapter {index}/{len(report.adapters)}: {adapter.name}")
        for label, value in (("description", adapter.description), ("driver", adapter.driver),
                             ("version", adapter.driver_version),
                             ("provider", adapter.driver_provider),
                             ("vendor", adapter.driver_vendor), ("INF", adapter.driver_inf),
                             ("radio", adapter.radio_type), ("channel", adapter.channel),
                             ("state", adapter.state), ("SSID", adapter.ssid),
                             ("BSSID", adapter.bssid), ("MAC", adapter.mac)):
            if value:
                lines.append(f"  {pad(label, 12)}: {value}")
        if adapter.capabilities:
            lines.append("  capabilities:")
            for key in CAPABILITY_ORDER:
                cap = adapter.capabilities.get(key)
                if cap is None:
                    continue
                lines.append(f"    {pad(key, 16)} {pad(cap.rendered(), 8)} "
                             f"{cap.label} : {cap.value_text}")
        lines.append(f"  verdict: {adapter.verdict.value}")
        if adapter.verdict_detail:
            lines.append(f"    {adapter.verdict_detail}")
        if adapter.evidence:
            lines.append("  evidence:")
            for item in adapter.evidence:
                lines.append(f"    {_squeeze(item)}")
        lines.append("")
    if report.notes:
        lines.append("Platform notes:")
        for note in report.notes:
            lines.append(f"  - {note}")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="wifit3-capabilities",
        description="Report each wireless adapter's monitor-mode and injection capability.")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    report = probe()
    if args.json:
        import json
        payload = {
            "platform": report.platform,
            "error": report.error,
            "notes": report.notes,
            "adapters": [
                {
                    "name": a.name, "description": a.description, "driver": a.driver,
                    "driver_vendor": a.driver_vendor, "driver_provider": a.driver_provider,
                    "driver_version": a.driver_version, "driver_inf": a.driver_inf,
                    "radio_type": a.radio_type, "channel": a.channel, "state": a.state,
                    "ssid": a.ssid, "bssid": a.bssid, "mac": a.mac,
                    "verdict": a.verdict.value, "verdict_detail": a.verdict_detail,
                    "monitor": a.monitor, "injection": a.injection,
                    "capabilities": {k: c.value for k, c in a.capabilities.items()},
                    "evidence": [_squeeze(item) for item in a.evidence],
                }
                for a in report.adapters
            ],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(render(report))
    return 0 if report.adapters else 1


if __name__ == "__main__":
    raise SystemExit(main())
