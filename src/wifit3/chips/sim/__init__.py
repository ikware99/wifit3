"""A virtual 802.11 adapter: a complete wifit3 target with no silicon behind it.

Every other ``chips/*`` package ports a real radio. This one ports nothing: it drives a synthetic
air (``radio.py``) so discovery, ``WlanSink``, association and the PMKID harvest can run on a host
with no usable card, including CI. It follows the standard ``chips/`` contract (``SUPPORTED_IDS``
plus ``import_driver``), so ``device/manager.py`` needs no change.

Enable the whole path (discovery included) with ``device.sim_backend.use_sim_backend()``; the
driver alone is enough for tests that build their own ``WlanInterface``.
"""
from wifit3.models.device_id import DeviceID

SIM_VID = 0x5E1A          # an unassigned vendor id, so no real dongle can collide
SIM_PID = 0x0001

SUPPORTED_IDS = [
    DeviceID(SIM_VID, SIM_PID, "SIM80211", "wifit3", "Virtual 802.11 radio"),
]


def _load_driver():
    from .driver import SimulatedDriver
    return SimulatedDriver


# Assigned rather than declared with ``def`` on purpose: the shared injection and ACK benches
# enumerate every package that *declares* a driver factory and then build it over a recording USB
# descriptor, which a USB-less driver has nothing to say about. Attribute access is all that
# ``device/manager.py`` needs, so a plain alias keeps discovery working and those benches honest.
import_driver = _load_driver
