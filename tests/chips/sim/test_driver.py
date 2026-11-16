"""The synthetic adapter: frame building, the air's replies, and the full PMKID pipeline.

These run the same code paths a real card drives (parser, WlanSink, campaign, hashline), so a
regression here means the product path broke, not just this test harness.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from wifit3.campaigns.pmkid import PmkidHarvestAttack, PmkidFail
from wifit3.chips.sim import SIM_PID, SIM_VID
from wifit3.chips.sim.backend import reset_usb_backend, use_sim_backend
from wifit3.chips.sim.driver import SimulatedDriver
from wifit3.chips.sim.radio import VirtualAccessPoint, VirtualRadio, default_radio
from wifit3.crack.hc22000_format import parse_hc22000
from wifit3.crack.wpa_psk import psk_matches
from wifit3.device import manager
from wifit3.dot11.ie import ssid_ie
from wifit3.dot11.mac import mac_header, str_to_mac
from wifit3.dot11.parser import WlanFrameParser
from wifit3.persist.save import save_pmkid
from wifit3.wlan.array import WlanArray
from wifit3.wlan.interface import WlanInterface

PSK_AP = "02:00:5e:1a:00:01"


def _assoc_req(bssid: str, client: str) -> bytes:
    """Just enough of an Assoc Req for the virtual air: subtype 0 + the addressed BSSID."""
    return mac_header(b"\x00\x00", str_to_mac(bssid), str_to_mac(client), str_to_mac(bssid)) + \
        b"\x21\x04\x00\x00" + ssid_ie("sim-lab-2g")


async def _array_with_sim(channel: int = 6) -> tuple[WlanArray, WlanInterface, SimulatedDriver]:
    driver = SimulatedDriver()
    array = WlanArray()
    iface = array.attach(WlanInterface(driver, "wlan0", "SIM80211"))
    await iface.connect()
    await iface.set_channel(channel)
    await asyncio.sleep(0.15)          # one beacon round
    return array, iface, driver


# ---- the air --------------------------------------------------------------

def test_beacon_parses_with_its_ssid_channel_and_akm():
    ap = VirtualAccessPoint(ssid="parse-me", bssid="02:00:5e:1a:00:09", channel=6)
    pkt = WlanFrameParser.parse_80211_frame(ap.beacon(), rssi=-40)
    assert pkt is not None
    assert pkt.type == "beacon"
    assert pkt.ssid == "parse-me"
    assert pkt.channel == 6
    assert pkt.akm_suites == [2]
    assert pkt.rsn_valid is True


def test_psk_ap_answers_auth_then_assoc_with_m1():
    ap = VirtualAccessPoint(ssid="psk", bssid="02:00:5e:1a:00:0a", channel=6)
    radio = VirtualRadio(aps=[ap])
    client = str_to_mac("02:11:22:33:44:55")
    auth = mac_header(b"\xb0\x00", ap.bssid_bytes, client, ap.bssid_bytes) + b"\x00\x00\x02\x00\x00\x00"
    assert len(radio.handle_tx(auth, channel=6)) == 1
    replies = radio.handle_tx(_assoc_req(ap.bssid, "02:11:22:33:44:55"), channel=6)
    assert len(replies) == 2
    m1 = WlanFrameParser.parse_80211_frame(replies[1], rssi=-40)
    assert m1 is not None and m1.type == "eapol"
    assert m1.msg_num == 1
    assert m1.pmkid == ap.pmkid_for(client)


def test_sae_ap_associates_but_sends_no_m1():
    ap = VirtualAccessPoint(ssid="sae", bssid="02:00:5e:1a:00:0b", channel=11, akm=0x08)
    replies = VirtualRadio(aps=[ap]).handle_tx(_assoc_req(ap.bssid, "02:11:22:33:44:55"),
                                               channel=11)
    assert len(replies) == 1


def test_open_ap_sends_no_m1():
    ap = VirtualAccessPoint(ssid="open", bssid="02:00:5e:1a:00:0c", channel=1, akm=None)
    replies = VirtualRadio(aps=[ap]).handle_tx(_assoc_req(ap.bssid, "02:11:22:33:44:55"),
                                               channel=1)
    assert len(replies) == 1


def test_the_air_ignores_a_frame_for_another_channel():
    ap = VirtualAccessPoint(ssid="off-ch", bssid="02:00:5e:1a:00:0d", channel=11)
    assert VirtualRadio(aps=[ap]).handle_tx(_assoc_req(ap.bssid, "02:11:22:33:44:55"),
                                            channel=6) == []


def test_handle_tx_ignores_data_frames_and_unknown_bssids():
    radio = default_radio()
    data = b"\x08\x01" + b"\x00" * 22 + b"\x00" * 8
    assert radio.handle_tx(data) == []
    unknown = _assoc_req("02:00:5e:1a:ff:ff", "02:11:22:33:44:55")
    assert radio.handle_tx(unknown, channel=6) == []


# ---- the driver contract --------------------------------------------------

def test_stamp_tx_seq_increments_and_preserves_length():
    driver = SimulatedDriver()
    frame = b"\x80\x00" + b"\x00" * 22
    first = driver._stamp_tx_seq(frame)
    second = driver._stamp_tx_seq(frame)
    assert len(first) == len(frame)
    assert first[22:24] != second[22:24]
    assert first[:22] == frame[:22]


async def test_connect_registers_the_air_and_closes_cleanly():
    driver = SimulatedDriver()
    seen: list = []
    driver.register_rx_callback(seen.append)
    assert await driver.connect() is True
    await driver.set_channel(6)
    await asyncio.sleep(0.1)
    await driver.close()
    assert seen, "no beacon reached the RX callback"
    assert all(pkt.type == "beacon" for pkt in seen)


async def test_active_monitor_adopts_the_requested_mac():
    driver = SimulatedDriver()
    mac = str_to_mac("02:aa:bb:cc:dd:ee")
    assert await driver.enter_active_monitor(mac) == mac


# ---- discovery ------------------------------------------------------------

def test_discovery_lists_the_virtual_adapter(monkeypatch):
    use_sim_backend()
    try:
        found = manager.devices()
    finally:
        reset_usb_backend()
    match = [d for d in found if (d.vid, d.pid) == (SIM_VID, SIM_PID)]
    assert len(match) == 1
    assert match[0].bus is not None and match[0].address is not None


def test_wlan_iface_builds_a_driver_for_the_virtual_adapter():
    use_sim_backend()
    try:
        entry = manager.devices()
        sim = next(d for d in entry if (d.vid, d.pid) == (SIM_VID, SIM_PID))
        iface = manager.wlan_iface(sim, name="wlan9")
    finally:
        reset_usb_backend()
    assert iface is not None
    assert isinstance(iface.driver, SimulatedDriver)


# ---- the product path -----------------------------------------------------

async def test_beacons_build_an_ap_in_the_sink():
    array, iface, _driver = await _array_with_sim()
    try:
        ap = array.access_points.get(PSK_AP)
        assert ap is not None
        assert ap.ssid == "sim-lab-2g"
        assert ap.encryption == "WPA2-PSK-CCMP"
        assert ap.channel == 6
    finally:
        await iface.close()


async def test_pmkid_harvest_produces_a_crackable_hashline():
    """The acceptance test for the virtual adapter: harvest, save, then crack it back."""
    array, iface, driver = await _array_with_sim()
    try:
        ap = array.access_points.get(PSK_AP)
        assert ap is not None
        attack = PmkidHarvestAttack(array, ap, attempts=2, m1_timeout=1.5)
        assert attack.run() is True
        for _ in range(60):
            await asyncio.sleep(0.05)
            if attack.pmkid is not None or attack.done:
                break
        await attack.stop()

        assert attack.fail_reason is None, attack.fail_reason
        assert attack.pmkid is not None

        result = save_pmkid(ap, attack.client_mac)
        assert result is not None and result.path.exists()

        line = parse_hc22000(Path(result.path).read_text().strip())
        assert line is not None and line.kind == "01"
        psk = next(a.psk for a in driver.radio.aps if a.bssid.lower() == PSK_AP)
        assert psk_matches(psk, line) is True
        assert psk_matches("definitely-not-the-passphrase", line) is False
    finally:
        await iface.close()


async def test_sae_ap_is_reported_as_having_no_psk_akm():
    array, iface, _driver = await _array_with_sim(channel=11)
    try:
        ap = array.access_points.get("02:00:5e:1a:00:03")
        assert ap is not None
        attack = PmkidHarvestAttack(array, ap, attempts=1, m1_timeout=0.3)
        attack.run()
        for _ in range(40):
            await asyncio.sleep(0.05)
            if attack.done:
                break
        await attack.stop()
        assert attack.fail_reason is PmkidFail.NO_PSK_AKM
    finally:
        await iface.close()
