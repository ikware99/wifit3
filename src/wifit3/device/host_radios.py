"""Host radios wifit3 cannot drive, enumerated so they are visible instead of silently absent.

The device layer is USB-only by construction: ``DeviceID`` carries a USB ``vid:pid`` and every
``chips/*`` driver opens a ``usb.core.Device``. A CNVi radio breaks that assumption completely.
On an Intel CNVi platform the 802.11 MAC, baseband and firmware sit inside the PCH; the M.2 module
is the RF front end only, and the Wi-Fi function has no USB presence at all (the USB device next to
it, ``8087:0aaa``, is the Bluetooth half). Nothing can be handed to libusb, so such a radio can
never enter ``supported_ids()`` no matter how it is probed.

Forcing it into the USB model would need a change to the ``Driver`` ABC, which the porting rules
reserve for the upstream maintainer. So this module reports host radios beside the USB device
list, states the architecture it found, and keeps the honesty requirement: a radio that cannot
inject is never described as if it could.
"""
from __future__ import annotations

import enum
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

INTEL_VENDOR = 0x8086

# PCI device ids confirmed as CNVi integrated MACs. Only ids verified on real hardware are listed;
# an unlisted Intel wireless id is reported without an architecture claim rather than guessed at.
CNVI_DEVICE_IDS: Dict[int, str] = {
    0xA0F0: "Intel Wireless-AC 9462",
}

_USB_BLUETOOTH_SIBLING = "8087:0aaa"


class Architecture(str, enum.Enum):
    """Where the 802.11 MAC actually lives, as far as this probe can establish."""

    CNVI = "cnvi"
    """Integrated MAC inside the PCH; the module is RF only, no USB Wi-Fi function."""
    PCIE = "pcie"
    """A discrete PCIe wireless controller."""
    UNKNOWN = "unknown"


class Reach(str, enum.Enum):
    """What wifit3 can do with this radio."""

    NONE = "none"
    """No driver path: the device layer cannot open it at all."""
    PASSIVE = "passive"
    """Frames can be observed through a third-party capture stack, never transmitted."""
    ACTIVE = "active"
    """Monitor mode plus raw TX, i.e. a normal supported USB adapter."""


@dataclass
class HostRadio:
    """One non-USB wireless controller on this host."""

    vendor: int
    device: int
    subsystem_vendor: Optional[int] = None
    subsystem_device: Optional[int] = None
    driver: str = ""
    location: str = ""
    model: str = ""
    architecture: Architecture = Architecture.UNKNOWN
    reach: Reach = Reach.NONE
    notes: List[str] = field(default_factory=list)

    @property
    def pci_id(self) -> str:
        return f"{self.vendor:04x}:{self.device:04x}"

    @property
    def subsystem_id(self) -> str:
        if self.subsystem_vendor is None or self.subsystem_device is None:
            return ""
        return f"{self.subsystem_vendor:04x}:{self.subsystem_device:04x}"

    def describe(self) -> str:
        return self.model or f"PCI wireless controller {self.pci_id}"


def _classify(radio: HostRadio) -> HostRadio:
    """Fill in the architecture and what it means for wifit3."""
    if radio.vendor == INTEL_VENDOR and radio.device in CNVI_DEVICE_IDS:
        radio.architecture = Architecture.CNVI
        radio.model = radio.model or CNVI_DEVICE_IDS[radio.device]
        radio.reach = Reach.PASSIVE
        radio.notes.append(
            "CNVi: the 802.11 MAC, baseband and firmware are inside the PCH, and the M.2 module "
            "is the RF front end only. Nothing on the USB bus carries this radio's Wi-Fi "
            "function, so wifit3 cannot open it as a card.")
        radio.notes.append(
            f"The USB device beside it ({_USB_BLUETOOTH_SIBLING}) is the Bluetooth half of the "
            "same module, not a Wi-Fi adapter.")
        radio.notes.append(
            "Firmware refuses monitor mode and injection on this family, so even a passive "
            "capture needs Npcap with raw 802.11 support; the active campaigns cannot run.")
    elif radio.driver.lower().startswith("netwtw"):
        radio.architecture = Architecture.UNKNOWN
        radio.reach = Reach.NONE
        radio.notes.append(
            "an Intel Windows driver is bound, but this PCI id is not in the verified CNVi table; "
            "no architecture claim is made and no driver path exists either way")
    else:
        radio.architecture = Architecture.PCIE
        radio.reach = Reach.NONE
        radio.notes.append(
            "a discrete PCIe controller: it has no USB function, so wifit3's device layer cannot "
            "open it")
    return radio


# ---- Windows --------------------------------------------------------------

_PCI_ID = re.compile(r"PCI\\VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})"
                     r"(?:&SUBSYS_([0-9A-F]{8}))?", re.IGNORECASE)
_CR_SUCCESS = 0
_CM_FILTER = 0x1 | 0x100        # CM_GETIDLIST_FILTER_ENUMERATOR | CM_GETIDLIST_FILTER_PRESENT


def _windows_pci_ids() -> List[str]:
    """Every present PCI instance id, via cfgmgr32 (the same API ``windows_pnp`` uses for USB)."""
    import ctypes
    from ctypes import wintypes

    cm = ctypes.WinDLL("cfgmgr32")
    size = wintypes.ULONG()
    if cm.CM_Get_Device_ID_List_SizeW(ctypes.byref(size), "PCI", _CM_FILTER) != _CR_SUCCESS:
        return []
    buf = ctypes.create_unicode_buffer(size.value)
    if cm.CM_Get_Device_ID_ListW("PCI", buf, size.value, _CM_FILTER) != _CR_SUCCESS:
        return []
    return [item for item in buf[:].split("\0") if item]


def _windows_driver_names() -> List[str]:
    """Intel Wi-Fi driver binaries present on disk (Netwtw*.sys)."""
    root = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers"
    try:
        return sorted(p.name for p in root.glob("Netwtw*.sys"))
    except OSError:
        return []


def probe_windows() -> List[HostRadio]:
    """CNVi radios only.

    cfgmgr32 lists PCI instance ids but not the driver bound to each one, so an id outside the
    verified table cannot be attributed safely; reporting every Intel PCI function as a radio
    would bury the one that matters. Linux, where sysfs exposes the bound driver, is less limited.
    """
    radios: List[HostRadio] = []
    drivers = _windows_driver_names()
    driver = drivers[0] if len(drivers) == 1 else ""
    for instance in _windows_pci_ids():
        match = _PCI_ID.search(instance)
        if match is None:
            continue
        vendor, device = int(match.group(1), 16), int(match.group(2), 16)
        if vendor != INTEL_VENDOR or device not in CNVI_DEVICE_IDS:
            continue
        subsys = match.group(3)
        sub_vendor = sub_device = None
        if subsys:
            # Windows packs SUBSYS as <device><vendor>, each 16 bits.
            sub_device, sub_vendor = int(subsys[:4], 16), int(subsys[4:], 16)
        radio = HostRadio(vendor=vendor, device=device, subsystem_vendor=sub_vendor,
                          subsystem_device=sub_device, driver=driver, location=instance)
        if not driver and drivers:
            radio.notes.append(
                f"several Intel Wi-Fi drivers are installed ({', '.join(drivers)}); the bound "
                "one is not attributed here")
        radios.append(_classify(radio))
    return radios


# ---- Linux ----------------------------------------------------------------

def probe_linux(root: Optional[Path] = None) -> List[HostRadio]:
    """Intel PCI functions under ``root`` (default ``/sys/bus/pci/devices``).

    ``root`` is a parameter so a fabricated sysfs tree can exercise the parsing offline.
    """
    radios: List[HostRadio] = []
    root = Path("/sys/bus/pci/devices") if root is None else root
    if not root.is_dir():
        return radios
    for entry in sorted(root.iterdir()):
        try:
            vendor = int((entry / "vendor").read_text().strip(), 16)
            device = int((entry / "device").read_text().strip(), 16)
        except (OSError, ValueError):
            continue
        if vendor != INTEL_VENDOR:
            continue
        try:
            sub_vendor = int((entry / "subsystem_vendor").read_text().strip(), 16)
            sub_device = int((entry / "subsystem_device").read_text().strip(), 16)
        except (OSError, ValueError):
            sub_vendor = sub_device = None
        driver = ""
        link = entry / "driver"
        try:
            # readlink, not resolve(): resolve(strict=False) hands back the literal "driver" when
            # the symlink is absent, which would be reported as a bound driver named "driver".
            driver = os.path.basename(os.readlink(link))
        except OSError:
            pass
        radio = HostRadio(vendor=vendor, device=device, subsystem_vendor=sub_vendor,
                          subsystem_device=sub_device, driver=driver, location=entry.name)
        if device in CNVI_DEVICE_IDS or driver.startswith("iwlwifi"):
            radios.append(_classify(radio))
    return radios


def host_radios() -> List[HostRadio]:
    """Every non-USB wireless controller this host reports."""
    if sys.platform == "win32":
        return probe_windows()
    if sys.platform.startswith("linux"):
        return probe_linux()
    return []


# ---- rendering ------------------------------------------------------------

def render(radios: List[HostRadio]) -> str:
    if not radios:
        return "Host radios: none reported (no non-USB wireless controller found)."
    lines = [f"Host radios not drivable by wifit3 ({len(radios)}):"]
    for radio in radios:
        lines.append("")
        lines.append(f"  {radio.describe()}")
        lines.append(f"    pci       : {radio.pci_id}"
                     + (f"  subsys {radio.subsystem_id}" if radio.subsystem_id else ""))
        if radio.location:
            lines.append(f"    location  : {radio.location}")
        lines.append(f"    driver    : {radio.driver or 'none bound'}")
        lines.append(f"    kind      : {radio.architecture.value}  "
                     f"(wifit3 reach: {radio.reach.value})")
        for note in radio.notes:
            lines.append(f"    note      : {note}")
    return "\n".join(lines)


def main() -> int:
    radios = host_radios()
    print(render(radios))
    return 0 if radios else 1


if __name__ == "__main__":
    raise SystemExit(main())
