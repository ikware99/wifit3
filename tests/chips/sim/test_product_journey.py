"""The whole product journey on the virtual adapter, discovery included.

Every other sim test hand-assembles the driver and the array, so nothing proved that
discovery, bring-up, the array, a campaign and the hashline writer agree with each other.
This one takes the same route a user does: ``use_sim_backend()`` puts the synthetic card on
the bus, ``manager.devices()`` finds it, ``manager.wlan_iface()`` builds the driver, and from
there the campaign runs unmodified.

Expected values are computed here from the algorithm itself (PBKDF2-HMAC-SHA1 4096 + the
PMKID HMAC), not from wifit3's helpers, so a bug shared by both sides cannot hide.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
from pathlib import Path

from wifit3.campaigns.pmkid import PmkidHarvestAttack
from wifit3.chips.sim import SIM_PID, SIM_VID
from wifit3.chips.sim.backend import reset_usb_backend, use_sim_backend
from wifit3.chips.sim.driver import SimulatedDriver
from wifit3.crack.hc22000_format import parse_hc22000
from wifit3.crack.wpa_psk import psk_matches
from wifit3.device import manager
from wifit3.persist.save import save_pmkid
from wifit3.wlan.array import WlanArray

PSK_AP = "02:00:5e:1a:00:01"


def _ref_pmkid(psk: str, essid: bytes, aa: bytes, spa: bytes) -> str:
    """PMKID straight from the spec, sharing no code with the module under test."""
    pmk = hashlib.pbkdf2_hmac("sha1", psk.encode(), essid, 4096, 32)
    return hmac.new(pmk, b"PMK Name" + aa + spa, hashlib.sha1).digest()[:16].hex()


async def _wait_for(predicate, rounds: int = 80, step: float = 0.05) -> bool:
    for _ in range(rounds):
        if predicate():
            return True
        await asyncio.sleep(step)
    return False


async def test_the_whole_journey_discovery_to_a_crackable_hashline():
    """Discover the synthetic card, harvest its PMKID, write the hashline, verify it."""
    use_sim_backend()
    iface = None
    try:
        found = manager.devices()
        sim = next((d for d in found if (d.vid, d.pid) == (SIM_VID, SIM_PID)), None)
        assert sim is not None, "discovery did not put the synthetic card on the bus"

        iface = manager.wlan_iface(sim, name="wlan9")
        assert iface is not None, "bring-up produced no interface for the synthetic card"
        assert isinstance(iface.driver, SimulatedDriver)
        assert await iface.connect() is True

        array = WlanArray()
        array.attach(iface)
        await iface.set_channel(6)

        assert await _wait_for(lambda: array.access_points.get(PSK_AP) is not None), \
            "no beacon reached the sink, so the AP list stayed empty"
        ap = array.access_points.get(PSK_AP)
        assert ap.ssid == "sim-lab-2g"
        assert ap.encryption == "WPA2-PSK-CCMP"
        assert ap.channel == 6

        attack = PmkidHarvestAttack(array, ap, attempts=2, m1_timeout=1.5)
        assert attack.run() is True
        assert await _wait_for(lambda: attack.done)
        await attack.stop()
        assert attack.fail_reason is None, attack.fail_reason
        assert attack.pmkid is not None

        result = save_pmkid(ap, attack.client_mac)
        assert result is not None and result.path.exists()
        line = parse_hc22000(Path(result.path).read_text().strip())
        assert line is not None and line.kind == "01"

        # What this run must equal, derived independently: the AP's own passphrase, the SSID it
        # broadcast, its BSSID, and the client the campaign actually used.
        radio_ap = next(a for a in iface.driver.radio.aps if a.bssid.lower() == PSK_AP)
        expected = _ref_pmkid(radio_ap.psk, b"sim-lab-2g",
                              bytes.fromhex(PSK_AP.replace(":", "")),
                              bytes.fromhex(attack.client_mac.replace(":", "")))
        assert line.pmkid_or_mic == expected, "the harvested PMKID is not the one the spec derives"
        assert psk_matches(radio_ap.psk, line) is True
        assert psk_matches("definitely-not-the-passphrase", line) is False
    finally:
        if iface is not None:
            await iface.close()
        reset_usb_backend()


async def test_the_journey_measures_link_acks_on_the_deauth_path():
    """The product-path guard for the false negative: de-auth must not read as a dead AP."""
    use_sim_backend()
    iface = None
    try:
        sim = next(d for d in manager.devices() if (d.vid, d.pid) == (SIM_VID, SIM_PID))
        iface = manager.wlan_iface(sim, name="wlan9")
        assert iface is not None
        await iface.connect()
        array = WlanArray()
        array.attach(iface)
        await iface.set_channel(6)
        assert await _wait_for(lambda: array.access_points.get(PSK_AP) is not None)

        client = "02:11:22:33:44:66"
        iface.driver.radio.add_station(client)
        res = await iface.deauth_client(PSK_AP, client, rounds=2)
        assert res.measured is True
        assert res.client_acks == res.client_sent == 2
        assert res.ap_acks == res.ap_sent == 2
    finally:
        if iface is not None:
            await iface.close()
        reset_usb_backend()


async def test_the_journey_needs_no_real_radio():
    """The design intent of the virtual adapter: the product path runs with nothing plugged in."""
    use_sim_backend()
    try:
        ifaces = [i for i in manager.wlan_ifaces()]
        assert len(ifaces) == 1
        assert isinstance(ifaces[0].driver, SimulatedDriver)
        await manager.wlan_close(ifaces)
    finally:
        reset_usb_backend()
