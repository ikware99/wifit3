"""A real WPS PIN exchange against the virtual air, driven by the shipped registrar.

Why end to end: the previous gap was that no campaign could even start against the virtual
radio, so anything short of running the actual registrar would not prove the gap is closed.
These tests therefore build the radio, hand its frames to ``WpsRegistrar`` through a loopback
transport, and assert on the verdict the campaign itself would read.
"""
from __future__ import annotations

from wifit3.campaigns.wps.registrar import PinResult, WpsRegistrar
from wifit3.chips.sim.radio import VirtualAccessPoint, VirtualRadio

AP_BSSID = "02:00:5e:1a:00:01"
SSID = "sim-lab-2g"
PSK = "sim-lab-2g-passphrase"
PIN = "12345670"
CLIENT = "02:11:22:33:44:66"
CHANNEL = 6


def _bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


class Loopback:
    """Carries the registrar's frames into the radio and the radio's answers back.

    ``recv`` returns whatever is queued without waiting: the virtual air answers synchronously,
    so any real waiting would only slow the test down. When nothing is queued it returns None,
    which is how the registrar learns the AP is silent.
    """

    def __init__(self, radio: VirtualRadio, channel: int) -> None:
        self.radio = radio
        self.channel = channel
        self.inbox: list[bytes] = []
        self.sent: list[bytes] = []

    async def send_no_wait(self, frame: bytes) -> None:
        self.sent.append(frame)
        self.inbox.extend(self.radio.handle_tx(frame, self.channel))

    async def send_until_ack(self, frame: bytes, max_retries: int = 0) -> bool:
        self.sent.append(frame)
        self.inbox.extend(self.radio.handle_tx(frame, self.channel))
        return True

    async def recv(self, timeout: float):
        return self.inbox.pop(0) if self.inbox else None


def _radio(ap_pin: str | None) -> VirtualRadio:
    ap = VirtualAccessPoint(ssid=SSID, bssid=AP_BSSID, channel=CHANNEL, psk=PSK,
                            wps_pin=ap_pin) if ap_pin else VirtualAccessPoint(
        ssid=SSID, bssid=AP_BSSID, channel=CHANNEL, psk=PSK)
    radio = VirtualRadio()
    radio.add_ap(ap)
    return radio


def _registrar(radio: VirtualRadio) -> tuple[WpsRegistrar, Loopback]:
    transport = Loopback(radio, CHANNEL)
    reg = WpsRegistrar(transport, _bytes(AP_BSSID), _bytes(CLIENT), CHANNEL, False,
                       msg_timeout=0.1, eapol_start_timeout=0.1, overall_timeout=2.0,
                       max_resends=2)
    return reg, transport


async def _attempt(pin: str, ap_pin: str | None = PIN):
    radio = _radio(ap_pin)
    reg, _ = _registrar(radio)
    return await reg.try_pin(pin), radio


async def test_the_true_pin_completes_m1_to_m7_and_yields_the_network_key():
    outcome, radio = await _attempt(PIN)

    assert outcome.result is PinResult.SUCCESS
    assert outcome.psk == PSK
    session = radio.wps_session(CLIENT)
    assert session is not None
    assert session.phase == "done"
    assert session.first_half_ok is True
    assert session.second_half_ok is True
    assert session.network_key == PSK


async def test_a_wrong_first_half_is_rejected_at_m4():
    """Negative case: without it, an AP that always says yes would pass the test above."""
    outcome, radio = await _attempt("99995670")

    assert outcome.result is PinResult.FIRST_HALF_WRONG
    assert outcome.psk is None
    session = radio.wps_session(CLIENT)
    assert session.first_half_ok is False
    assert session.config_error == 18          # Device Password Auth Failure
    assert session.network_key is None         # no credential on a rejected attempt


async def test_a_wrong_second_half_is_rejected_at_m6():
    """The first half of "12345671" matches, so the AP must accept M4 and fail at M6 instead."""
    outcome, radio = await _attempt("12345671")

    assert outcome.result is PinResult.SECOND_HALF_WRONG
    assert outcome.psk is None
    session = radio.wps_session(CLIENT)
    assert session.first_half_ok is True
    assert session.second_half_ok is False


async def test_an_ap_with_wps_disabled_stays_silent():
    """Most hardened APs ship with WPS off; the campaign must read silence, not a wrong PIN."""
    outcome, radio = await _attempt(PIN, ap_pin=None)

    assert outcome.result is PinResult.TIMEOUT
    assert outcome.reached_m1 is False
    assert radio.wps_session(CLIENT) is None


async def test_a_failed_attempt_does_not_poison_the_next_one():
    """Each try opens a fresh EAPOL session, so the sweeper can keep walking the keyspace."""
    radio = _radio(PIN)
    reg, transport = _registrar(radio)

    first = await reg.try_pin("99995670")
    transport.inbox.clear()                    # drop the tail of the rejected exchange
    second = await reg.try_pin(PIN)

    assert first.result is PinResult.FIRST_HALF_WRONG
    assert second.result is PinResult.SUCCESS
    assert second.psk == PSK


async def test_non_eapol_data_traffic_does_not_disturb_the_session():
    """Ordinary data frames draw the link ACK and nothing else, as on a real air."""
    radio = _radio(PIN)
    ap = radio.aps[0]
    plain = (b"\x08\x01" + b"\x00\x00" + ap.bssid_bytes + _bytes(CLIENT) + ap.bssid_bytes
             + b"\x00\x00" + b"\xaa\xaa\x03\x00\x00\x00\x08\x00")

    replies = radio.handle_tx(plain, CHANNEL)

    assert len(replies) == 1                   # the ACK, and only the ACK
    assert radio.wps_session(CLIENT) is None
