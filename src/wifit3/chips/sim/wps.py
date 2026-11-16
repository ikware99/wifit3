"""The AP half of a WPS PIN exchange, so the campaign can run without a radio.

Why this exists: in the PIN attack wifit3 plays the external registrar and the AP plays the
*enrollee* (the AP sends M1 and proves its device password through E-Hash1/2). A virtual AP that
only answers beacons and authentication never opens that exchange, so ``WpsRegistrar`` waits out
its whole timeout on every attempt and every PIN reads as wrong. This module supplies the missing
half, with the rules a real AP enforces:

* a wrong first half fails at M4 (R-Hash1 mismatch) and the AP answers WSC_NACK,
* a wrong second half fails at M6 (R-Hash2 mismatch),
* only the true PIN reaches M8, which carries the network key.

That asymmetry is the point of the test: it lets the two-half sweeper converge instead of
timing out, and it lets a negative assertion exist (wrong PIN must not produce a credential).

The message builders already existed for the PBC path in ``campaigns/wps/enrollee.py``, where
wifit3 is the enrollee instead. This reuses them with the polarity the PIN path needs.
"""
from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional

from wifit3.dot11.wsc import crypto as wc
from wifit3.dot11.wsc import messages as M

logger = logging.getLogger(__name__)

# 802.1X payload types this module distinguishes. Start carries no EAP header at all, which is
# why it cannot come back through M.parse_rx_frame and needs its own detector.
#
# Two numbering schemes live here and they are easy to confuse: ``M.WSC_MSG`` (0x04) is the
# EAP-WSC op-code in the EAP header, while ``M.WPS_M7`` (0x0B) is the Message Type attribute
# inside the payload. A frame needs one of each.
_CONFIG_ERROR_DEVICE_PASSWORD = 18   # "Device Password Auth Failure", per WSC config errors

PHASE_IDLE = "idle"
PHASE_IDENTITY_SENT = "identity-sent"
PHASE_M1_SENT = "m1-sent"
PHASE_M3_SENT = "m3-sent"
PHASE_M5_SENT = "m5-sent"
PHASE_M7_SENT = "m7-sent"
PHASE_DONE = "done"


def is_eapol_start(frame: bytes) -> bool:
    """True for an 802.1X EAPOL-Start, which has no EAP header to parse."""
    idx = frame.find(M.LLC_SNAP_EAPOL, 22, 40)
    if idx < 0:
        return False
    pos = idx + len(M.LLC_SNAP_EAPOL)
    return len(frame) > pos + 1 and frame[pos + 1] == M.DOT1X_TYPE_EAPOL_START


def eap_request(eap_id: int, body: bytes) -> bytes:
    """An EAP-Request, which is what an authenticator sends (M.eap_wsc_response is the mirror).

    ``_eapol_eap`` is private to the WSC package, but it is the one place that knows the 802.1X
    header layout, and duplicating that here would let the two drift apart.
    """
    return M._eapol_eap(M.EAP_REQUEST, eap_id, body)


def request_identity(eap_id: int = 1) -> bytes:
    return eap_request(eap_id, bytes([M.EAP_TYPE_IDENTITY]))


def request_wsc(eap_id: int, opcode: int, attrs: bytes) -> bytes:
    body = (
        bytes([M.EAP_TYPE_EXPANDED])
        + M.WFA_VENDOR_ID
        + M.WFA_VENDOR_TYPE_SIMPLECONFIG
        + bytes([opcode, 0x00])       # op-code, flags: no fragmentation
        + attrs
    )
    return eap_request(eap_id, body)


def decrypt_encr_settings(keywrapkey: bytes, blob: bytes) -> Dict[int, bytes]:
    """Undo ``messages._encr_settings``: IV(16) || AES-CBC(pad(inner || KWA(8))).

    Returns the inner TLV map, or an empty map when the blob is malformed. A wrong key does not
    raise here (CBC has no integrity of its own); the caller's hash comparison is what rejects
    a bad decrypt, which is exactly how a real AP detects a wrong device password.
    """
    if not blob or len(blob) < wc.NONCE_LEN + 16:
        return {}
    iv, data = blob[:wc.NONCE_LEN], blob[wc.NONCE_LEN:]
    try:
        plain = wc.pkcs5_unpad(wc.aes128_cbc_decrypt(keywrapkey, iv, data))
    except (ValueError, IndexError):
        return {}
    return M.parse_tlvs(plain[:-wc.KWA_LEN])


class VirtualWpsEnrollee:
    """One AP-side WSC session, driven by :meth:`feed`.

    ``feed`` takes a frame the client transmitted and returns the frames the AP would answer
    with. Each call advances at most one stage, which is what makes it usable from a synchronous
    radio that has no event loop of its own.
    """

    def __init__(self, bssid: bytes, ssid: str, psk: str, pin: str, channel: int,
                 wsc_2_0: bool = True) -> None:
        self.bssid = bssid
        self.ssid = ssid
        self.psk = psk
        self.pin = pin
        self.channel = channel
        self.wsc_2_0 = wsc_2_0
        self.phase = PHASE_IDLE
        self.attempts = 0            # EAPOL-Starts seen: one per PIN the sweeper tried
        self.first_half_ok: Optional[bool] = None
        self.second_half_ok: Optional[bool] = None
        self.config_error: Optional[int] = None
        self.network_key: Optional[str] = None
        self.leaked_ssid: Optional[str] = None
        self._eap_id = 1
        self._uuid_e = os.urandom(16)
        self._nonce_e = b""
        self._priv = 0
        self._pke = b""
        self._nonce_r = b""
        self._pkr = b""
        self._authkey = b""
        self._keywrapkey = b""
        self._psk1 = b""
        self._psk2 = b""
        self._e_s1 = b""
        self._e_s2 = b""
        self._r_hash2 = b""

    # -- session -------------------------------------------------------------
    def _reset_session(self) -> None:
        """Drop the per-attempt key state but keep the verdicts, which tests assert on."""
        self._nonce_e = b""
        self._pkr = self._nonce_r = b""
        self._authkey = self._keywrapkey = b""
        self._psk1 = self._psk2 = b""
        self._r_hash2 = b""

    def feed(self, frame: bytes) -> List[bytes]:
        if self.phase == PHASE_DONE:
            return []
        if is_eapol_start(frame):
            # A sweeper opens a fresh EAPOL session per PIN; reset so attempt N+1 is independent
            # of attempt N, exactly like an AP that has no idea the previous one happened.
            self._reset_session()
            self.attempts += 1
            self.phase = PHASE_IDENTITY_SENT
            return [request_identity(self._eap_id)]

        parsed = M.parse_rx_frame(frame)
        if parsed is None or parsed.eap_code != M.EAP_RESPONSE:
            return []
        if parsed.eap_type == M.EAP_TYPE_IDENTITY:
            return [self._send_m1(parsed.eap_id)] if self.phase == PHASE_IDENTITY_SENT else []
        if parsed.wsc_opcode != M.WSC_MSG or not parsed.attrs:
            return []

        stage = {
            M.WPS_M2: self._on_m2,
            M.WPS_M4: self._on_m4,
            M.WPS_M6: self._on_m6,
        }.get(parsed.wsc_msg_type)
        return stage(parsed) if stage is not None else []

    # -- M1 ------------------------------------------------------------------
    def _send_m1(self, eap_id: int) -> bytes:
        self._priv, self._pke = wc.dh_generate_keypair()
        self._nonce_e = os.urandom(wc.NONCE_LEN)
        self._e_s1 = os.urandom(wc.SECRET_NONCE_LEN)
        self._e_s2 = os.urandom(wc.SECRET_NONCE_LEN)
        self.phase = PHASE_M1_SENT
        attrs = M.build_m1(self._uuid_e, self.bssid, self._nonce_e, self._pke,
                           M.rf_band_for_channel(self.channel), self.wsc_2_0,
                           dev_pw_id=M.DEV_PW_DEFAULT)
        return request_wsc(eap_id, M.WSC_MSG, attrs)

    # -- M2 -> M3 ------------------------------------------------------------
    def _on_m2(self, parsed) -> List[bytes]:
        if self.phase not in (PHASE_M1_SENT, PHASE_M3_SENT):
            return []
        pkr = parsed.attrs.get(M.ATTR_PUBLIC_KEY)
        nonce_r = parsed.attrs.get(M.ATTR_REGISTRAR_NONCE)
        nonce_e = parsed.attrs.get(M.ATTR_ENROLLEE_NONCE)
        if not pkr or not nonce_r or nonce_e != self._nonce_e:
            return [self._nack(parsed.eap_id)]

        self._pkr, self._nonce_r = pkr, nonce_r
        shared = wc.dh_shared_secret(pkr, self._priv)
        self._authkey, self._keywrapkey, _ = wc.derive_keys(
            shared, self._nonce_e, self.bssid, nonce_r)
        self._psk1, self._psk2 = wc.derive_psk(self._authkey, self.pin)
        self.phase = PHASE_M3_SENT
        attrs = M.build_m3_enrollee(nonce_r, self._e_s1, self._e_s2, self._psk1, self._psk2,
                                    self._pke, pkr, self._authkey, parsed.raw_wsc_attrs)
        return [request_wsc(parsed.eap_id, M.WSC_MSG, attrs)]

    # -- M4 -> M5 (first half) or NACK ---------------------------------------
    def _on_m4(self, parsed) -> List[bytes]:
        if self.phase != PHASE_M3_SENT:
            return []
        r_hash1 = parsed.attrs.get(M.ATTR_R_HASH1)
        self._r_hash2 = parsed.attrs.get(M.ATTR_R_HASH2, b"")
        inner = decrypt_encr_settings(self._keywrapkey,
                                      parsed.attrs.get(M.ATTR_ENCR_SETTINGS, b""))
        r_s1 = inner.get(M.ATTR_R_SNONCE1)
        if not r_hash1 or not r_s1:
            return [self._nack(parsed.eap_id)]

        # The AP knows its own PIN, so it can state the expected hash directly. Comparing like
        # this, rather than checking PK against a stored copy, is what makes a wrong first half
        # fail here instead of at M6.
        self.first_half_ok = wc.e_or_r_hash(
            self._authkey, r_s1, self._psk1, self._pke, self._pkr) == r_hash1
        if not self.first_half_ok:
            return [self._nack(parsed.eap_id)]

        self.phase = PHASE_M5_SENT
        attrs = M.build_m5_enrollee(self._nonce_r, self._e_s1, self._authkey,
                                    self._keywrapkey, parsed.raw_wsc_attrs)
        return [request_wsc(parsed.eap_id, M.WSC_MSG, attrs)]

    # -- M6 -> M7 (second half) or NACK --------------------------------------
    def _on_m6(self, parsed) -> List[bytes]:
        if self.phase != PHASE_M5_SENT:
            return []
        inner = decrypt_encr_settings(self._keywrapkey,
                                      parsed.attrs.get(M.ATTR_ENCR_SETTINGS, b""))
        r_s2 = inner.get(M.ATTR_R_SNONCE2)
        if not r_s2 or not self._r_hash2:
            return [self._nack(parsed.eap_id)]

        self.second_half_ok = wc.e_or_r_hash(
            self._authkey, r_s2, self._psk2, self._pke, self._pkr) == self._r_hash2
        if not self.second_half_ok:
            return [self._nack(parsed.eap_id)]

        # Both halves proven. In this polarity the credential travels in M7, not M8: wifit3
        # reads it with extract_m7_credentials and stops there, answering with a NACK to close
        # the session. Sending it in M8 instead would leave the registrar waiting forever.
        self.leaked_ssid = self.ssid
        self.network_key = self.psk
        self.phase = PHASE_DONE
        attrs = M.build_m7_credential(self._nonce_r, self.ssid.encode(),
                                      self.psk.encode(), self.bssid,
                                      self._authkey, self._keywrapkey, parsed.raw_wsc_attrs)
        return [request_wsc(parsed.eap_id, M.WSC_MSG, attrs)]

    # -- NACK ----------------------------------------------------------------
    def _nack(self, eap_id: int) -> bytes:
        """Reject, then rearm: a sweeper's next PIN arrives as a fresh EAPOL-Start."""
        self.config_error = _CONFIG_ERROR_DEVICE_PASSWORD
        self.phase = PHASE_IDLE
        attrs = M.build_wsc_nack(self._nonce_e or bytes(wc.NONCE_LEN),
                                 self._nonce_r or bytes(wc.NONCE_LEN),
                                 _CONFIG_ERROR_DEVICE_PASSWORD)
        return request_wsc(eap_id, M.WSC_NACK, attrs)
