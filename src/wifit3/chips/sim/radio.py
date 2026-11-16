"""The synthetic RF environment: a few virtual APs, their frames, and the state machines that
answer an injected Auth / Assoc.

Nothing here touches a socket or a device. ``handle_tx`` takes the raw MPDU this driver was asked
to transmit and returns the raw frames the virtual air would put on the wire, which the driver
then feeds back through its RX callback. Every response is built by the shipped ``dot11``
builders, so what the rest of wifit3 parses is a frame it would also see from real silicon.
"""
from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from wifit3.crack.wpa_psk import pmkid as pmkid_of
from wifit3.dot11.ap import assoc_resp, auth_resp
from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header, eapol_key
from wifit3.dot11.ie import ds_param_ie, rates_ie, ssid_ie
from wifit3.dot11.mac import mac_header, str_to_mac
from wifit3.dot11.wpa import derive_pmk

logger = logging.getLogger(__name__)

BROADCAST = b"\xff\xff\xff\xff\xff\xff"
BEACON_INTERVAL = 100            # TU, the 802.11 default
_CAP_ESS = 0x0001
_CAP_PRIVACY = 0x0010
_ANONCE = bytes.fromhex("a1" * 32)
_M1_KEY_INFO = 0x008A            # pairwise + ACK + key descriptor version 2 (HMAC-SHA1, PSK)
_CCMP_KEY_LEN = 16
_RSSI = -42                      # a strong virtual signal, so the sink keeps the AP listed


def rsn_ie_psk(akm: int = 0x02) -> bytes:
    """An RSN IE: CCMP group + pairwise, one AKM. 0x02 = PSK, 0x08 = SAE."""
    return (b"\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04"
            b"\x01\x00\x00\x0f\xac" + bytes([akm]) + b"\x00\x00")


def pmkid_kde(value: bytes) -> bytes:
    """A PMKID KDE: the vendor IE an AP puts in M1's key data (OUI 00:0f:ac, type 04)."""
    return b"\xdd\x14\x00\x0f\xac\x04" + value


def build_beacon(bssid: bytes, ssid: str, channel: int,
                 rsn_ie: Optional[bytes] = None) -> bytes:
    """A Beacon MPDU: fixed fields, then SSID / rates / DS param / optional RSN."""
    head = mac_header(b"\x80\x00", BROADCAST, bssid, bssid)
    capability = _CAP_ESS | (_CAP_PRIVACY if rsn_ie else 0)
    body = struct.pack("<QHH", 0, BEACON_INTERVAL, capability)
    ies = ssid_ie(ssid) + rates_ie(channel) + ds_param_ie(channel)
    if rsn_ie:
        ies += rsn_ie
    return head + body + ies


@dataclass
class VirtualAccessPoint:
    """One virtual AP: its identity, band position, and the PSK its PMKIDs are derived from.

    ``psk`` is what makes a harvest verifiable: the M1 carries
    ``HMAC-SHA1-128(PBKDF2(psk, ssid), "PMK Name" || AP || STA)``, exactly the value hashcat
    recomputes from the same passphrase, so a captured PMKID can be cracked back to it.
    """

    ssid: str
    bssid: str
    channel: int = 1
    psk: str = "simulated-passphrase"
    akm: Optional[int] = 0x02        # None = open network (no RSN IE)
    m1_delay: float = 0.0

    def __post_init__(self) -> None:
        self.bssid_bytes = str_to_mac(self.bssid)
        self._beacon = build_beacon(self.bssid_bytes, self.ssid, self.channel,
                                    rsn_ie_psk(self.akm) if self.akm else None)

    @property
    def secured(self) -> bool:
        return self.akm is not None

    @property
    def sends_m1(self) -> bool:
        """Only a PSK AKM yields the harvestable M1; SAE would need a full SAE exchange."""
        return self.akm == 0x02

    def beacon(self) -> bytes:
        return self._beacon

    def pmkid_for(self, client: bytes) -> bytes:
        """The PMKID this AP would report for ``client``: the crackable HMAC-SHA1-128 form."""
        pmk = derive_pmk(self.psk, self.ssid.encode())
        return pmkid_of(pmk, self.bssid_bytes, client)

    def m1(self, client: bytes) -> bytes:
        """4-way message 1 carrying this AP's PMKID KDE for ``client``."""
        payload = eapol_key(key_info=_M1_KEY_INFO, key_len=_CCMP_KEY_LEN, replay=1,
                            nonce=_ANONCE, key_data=pmkid_kde(self.pmkid_for(client)))
        return data_header(to_ds=False, bssid=self.bssid_bytes, client=client) + \
            LLC_SNAP_EAPOL + payload


@dataclass
class VirtualRadio:
    """The virtual air: APs by BSSID, and the response frames for whatever was transmitted."""

    aps: List[VirtualAccessPoint] = field(default_factory=list)
    _sink: Optional[Callable[[bytes], None]] = None

    def __post_init__(self) -> None:
        self._by_bssid: Dict[str, VirtualAccessPoint] = {
            ap.bssid.lower(): ap for ap in self.aps}

    def add_ap(self, ap: VirtualAccessPoint) -> VirtualAccessPoint:
        self.aps.append(ap)
        self._by_bssid[ap.bssid.lower()] = ap
        return ap

    def attach(self, sink: Callable[[bytes], None]) -> None:
        """Send every frame this radio emits to ``sink`` (the driver's RX tap)."""
        self._sink = sink

    def beacons(self, channel: Optional[int] = None) -> List[bytes]:
        """Beacon frames for the APs on ``channel`` (all APs when None)."""
        return [ap.beacon() for ap in self.aps if channel is None or ap.channel == channel]

    def handle_tx(self, frame: bytes, channel: Optional[int] = None) -> List[bytes]:
        """The frames the air answers a transmitted MPDU with (management frames only)."""
        if len(frame) < 24:
            return []
        fc0 = frame[0]
        if (fc0 & 0x0C) >> 2 != 0:          # type 0 = management; data/control get no answer
            return []
        subtype = (fc0 & 0xF0) >> 4
        dest, source = frame[4:10], frame[10:16]
        ap = self._by_bssid.get(dest.hex(":"))
        if ap is None or (channel is not None and ap.channel != channel):
            return []
        if subtype == 11:                    # Authentication
            return [auth_resp(ap.bssid_bytes, source)]
        if subtype in (0, 2):                # (Re)Association Request
            replies = [assoc_resp(ap.bssid_bytes, source, channel=ap.channel,
                                  twin_beacon=ap.beacon())]
            if ap.sends_m1:
                replies.append(ap.m1(source))
            return replies
        return []

    def emit(self, frames: List[bytes]) -> int:
        """Push ``frames`` into the RX tap; returns how many were handed over."""
        if self._sink is None:
            return 0
        sent = 0
        for frame in frames:
            self._sink(frame)
            sent += 1
        return sent


def default_radio() -> VirtualRadio:
    """A small mixed environment: WPA2-PSK on both bands, plus an SAE-only and an open AP."""
    return VirtualRadio(aps=[
        VirtualAccessPoint(ssid="sim-lab-2g", bssid="02:00:5e:1a:00:01", channel=6),
        VirtualAccessPoint(ssid="sim-lab-5g", bssid="02:00:5e:1a:00:02", channel=149,
                           psk="simulated-5g-passphrase"),
        VirtualAccessPoint(ssid="sim-wpa3", bssid="02:00:5e:1a:00:03", channel=11, akm=0x08),
        VirtualAccessPoint(ssid="sim-open", bssid="02:00:5e:1a:00:04", channel=1, akm=None),
    ])
