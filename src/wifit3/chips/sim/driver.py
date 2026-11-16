"""The synthetic driver: a ``Driver`` whose air is ``radio.VirtualRadio`` instead of silicon.

This is the one driver in ``chips/`` that transmits nothing. It exists so the whole product path
(discovery, ``WlanSink``, associations, PMKID harvest, ``.hc22000`` output) can run with no
hardware: on a CI runner, on a host whose radio refuses monitor mode, or on a desk.

Delivery is deliberately deferred by ``DELIVERY_DELAY``: a real driver's frames arrive through a
reader thread, i.e. never inside the ``inject_frame`` call. Callers such as ``Association`` clear
their reply event right after sending, so a synchronous reply would be cleared away. The delay
reproduces the asynchronous arrival the rest of the code is written against.
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

import usb.core

from wifit3.chips.driver import Driver, FakeMacSupport, ProgressCallback
from wifit3.chips.sim.radio import VirtualRadio, default_radio
from wifit3.dot11.parser import WlanFrameParser
from wifit3.models.device_id import DeviceID

logger = logging.getLogger(__name__)

DELIVERY_DELAY = 0.003      # seconds between transmit and the air's answer reaching RX
BEACON_PERIOD = 0.25        # seconds between beacon rounds on the tuned channel
SIM_MAC = "02:00:5e:1a:ff:01"
SEQUENCE_MODULUS = 4096


class SimulatedDriver(Driver):
    """A driver for a virtual radio: full RX/TX path, no USB traffic."""

    SUPPORTED_CHANNELS: List[int] = (list(Driver.CHANNELS_2G) + list(Driver.CHANNELS_5G)
                                     + list(Driver.CHANNELS_DFS))
    FAKE_MAC = FakeMacSupport.SPOOFABLE
    CONFLICTING_LINUX_MODULES: List[str] = []
    LINUX_REPLUG_AFTER_MODPROBE = False

    def __init__(self, radio: Optional[VirtualRadio] = None) -> None:
        super().__init__()
        self.radio = radio if radio is not None else default_radio()
        self.mac_address: Optional[str] = SIM_MAC
        self.is_warm = False
        self._rx_cb = None
        self._disconnect_cb = None
        self._channel = 1
        self._seq = 0
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._tasks: List[asyncio.Task] = []
        self._closed = False
        self._monitor_mac: Optional[bytes] = None

    @classmethod
    def from_usb_device(cls, dev: Optional[usb.core.Device],
                        id_entry: Optional[DeviceID] = None) -> "SimulatedDriver":
        """No device is opened; the argument exists to satisfy ``Driver``."""
        return cls()

    # ---- wiring ----------------------------------------------------------

    def register_rx_callback(self, cb) -> None:
        self._rx_cb = cb

    def register_disconnect_callback(self, cb) -> None:
        self._disconnect_cb = cb

    async def connect(self, progress_cb: Optional[ProgressCallback] = None) -> bool:
        self._loop = asyncio.get_running_loop()
        self.radio.attach(self._deliver)
        if progress_cb is not None:
            progress_cb(1.0, "simulated radio ready")
        self._tasks.append(asyncio.create_task(self._beacon_loop()))
        logger.info("sim: %d virtual AP(s) on the air", len(self.radio.aps))
        return True

    async def set_channel(self, channel: int, scan: bool = False) -> bool:
        self._channel = channel
        self._publish(self.radio.beacons(channel))
        return True

    async def close(self) -> None:
        self._closed = True
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        self.radio.attach(lambda _frame: None)

    # ---- air -> RX -------------------------------------------------------

    def _deliver(self, frame: bytes) -> None:
        """The RX tap: tally an ACK, then parse and hand one Packet to the sink.

        Control frames stop after the tally: the parser has no Packet for them (and an ACK is
        shortened to 10 bytes by design), so passing one on would only feed garbage upward.
        """
        self.record_ack(frame)
        if len(frame) >= 2 and (frame[0] & 0x0C) >> 2 == 1:
            return
        pkt = WlanFrameParser.parse_80211_frame(frame, rssi=-42)
        if pkt is not None and self._rx_cb is not None:
            self._rx_cb(pkt)

    def _publish(self, frames: List[bytes], delay: float = DELIVERY_DELAY) -> None:
        """Hand ``frames`` to the air, after ``delay``, on the running loop.

        The air delivers through its own sink, so a ``close()`` (which detaches that sink) also
        stops anything already queued from reaching the RX tap.
        """
        if not frames or self._loop is None:
            return
        self._loop.call_later(delay, self.radio.emit, frames)

    async def _beacon_loop(self) -> None:
        while not self._closed:
            self._publish(self.radio.beacons(self._channel))
            await asyncio.sleep(BEACON_PERIOD)

    # ---- TX --------------------------------------------------------------

    async def _inject_frame(self, frame_bytes: bytes) -> bool:
        answers = self.radio.handle_tx(frame_bytes, self._channel)
        if answers:
            self._publish(answers)
        return True

    def _stamp_tx_seq(self, frame_bytes: bytes) -> bytes:
        """Assign an incrementing 802.11 sequence number, as the hardware would."""
        if len(frame_bytes) < 24:
            return frame_bytes
        seq = (self._seq % SEQUENCE_MODULUS) << 4
        self._seq += 1
        return frame_bytes[:22] + seq.to_bytes(2, "little") + frame_bytes[24:]

    # ---- RX-ACK tally ----------------------------------------------------

    async def _enable_rx_acks(self) -> None:
        """The RX tap already admits control frames; nothing to switch on."""

    async def _disable_rx_acks(self) -> None:
        """Mirror of ``_enable_rx_acks``."""

    # ---- active monitor --------------------------------------------------

    @property
    def monitor_mac(self) -> Optional[bytes]:
        """The MAC this air is currently answering as, or None outside active monitor."""
        return self._monitor_mac

    async def enter_active_monitor(self, mac: bytes, bssid: Optional[bytes] = None) -> bytes:
        self._monitor_mac = bytes(mac)
        return self._monitor_mac

    async def exit_active_monitor(self) -> None:
        self._monitor_mac = None
