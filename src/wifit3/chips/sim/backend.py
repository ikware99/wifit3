"""A ``UsbBackend`` that exposes the synthetic adapter, so the stock discovery path finds it.

``device/backend.py`` documents ``set_usb_backend_factory`` as the extension point for an
alternative transport; this is that transport, with a device list of one. Nothing here reaches
libusb, and enabling it is explicit, so a real USB card is never shadowed by accident.
"""
from __future__ import annotations

from typing import List, Optional

from wifit3.chips.sim import SIM_PID, SIM_VID
from wifit3.device.backend import UsbBackend, set_usb_backend_factory

SIM_BUS = 250             # far outside real bus numbering
SIM_ADDRESS = 1


class SimulatedUsbDevice:
    """The attributes ``device/manager.py`` and ``WlanInterface`` read off a pyusb device."""

    def __init__(self, vid: int = SIM_VID, pid: int = SIM_PID,
                 bus: int = SIM_BUS, address: int = SIM_ADDRESS) -> None:
        self.idVendor = vid
        self.idProduct = pid
        self.bus = bus
        self.address = address

    def __repr__(self) -> str:
        return f"<SimulatedUsbDevice {self.idVendor:04x}:{self.idProduct:04x}>"


class SimulatedUsbBackend(UsbBackend):
    """One synthetic device on a synthetic bus."""

    def __init__(self, device: Optional[SimulatedUsbDevice] = None) -> None:
        self.device = device or SimulatedUsbDevice()

    def enumerate(self) -> List[SimulatedUsbDevice]:
        return [self.device]

    def find(self, vid: int, pid: int, bus: Optional[int] = None,
             address: Optional[int] = None) -> Optional[SimulatedUsbDevice]:
        dev = self.device
        if (dev.idVendor, dev.idProduct) != (vid, pid):
            return None
        if bus is not None and address is not None and (dev.bus, dev.address) != (bus, address):
            return None
        return dev

    def find_all(self, vid: int, pid: int) -> List[SimulatedUsbDevice]:
        return [d for d in self.enumerate() if (d.idVendor, d.idProduct) == (vid, pid)]


def use_sim_backend() -> SimulatedUsbBackend:
    """Route discovery through the synthetic adapter until ``reset_usb_backend()``."""
    backend = SimulatedUsbBackend()
    set_usb_backend_factory(lambda: backend)
    return backend


def reset_usb_backend() -> None:
    """Restore the platform libusb backend."""
    set_usb_backend_factory(None)
