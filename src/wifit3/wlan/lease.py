"""A campaign's scoped hold on one interface: apply config on enter, restore it on exit."""
from __future__ import annotations

import logging
from typing import Any, List, Optional

logger = logging.getLogger(__name__)

# Sentinel for ``fake_mac``: let the driver pick a random locally-administered MAC
# (SPOOFABLE cards) or fall back to the card's own MAC (FIXED_MAC cards).
SPOOFABLE = object()


class Lease:
    """One interface, configured on enter and restored on exit (channel, active-monitor MAC, ACK tally).
    The active-monitor MAC is registered as own so ingest drops our echo; exit clears everything."""

    def __init__(self, array, iface, *, channel: Optional[int] = None,
                 fake_mac: Any = None, bssid: Any = None, ack_tally: bool = False) -> None:
        self._array = array
        self.iface = iface
        self._channel = channel
        self._fake_mac = fake_mac
        self._bssid = bssid
        self._ack_tally = ack_tally
        self._orig_channel: Optional[int] = None
        self._own_mac: Optional[str] = None
        self._in_active_monitor = False

    async def enter_active_monitor(self, mac, bssid=None) -> Optional[str]:
        """Replace any earlier active-monitor MAC with ``mac``; register the MAC we transmit as
        with the array and return it (None if none)."""
        if bssid is not None:
            self._bssid = bssid
        await self._exit_active_monitor()
        requested = None if mac is SPOOFABLE else mac
        assumed = await self.iface.set_fake_mac(requested, self._bssid)
        self._in_active_monitor = assumed is not None
        # Register whatever we transmit as: the assumed MAC, else the concrete MAC we
        # asked for (we still send from it even when the card can't HW-ACK it).
        own = assumed or requested
        self._own_mac = self._array.register_own_mac(own) if own is not None else None
        self._fake_mac = mac
        return self._own_mac

    async def _exit_active_monitor(self) -> None:
        try:
            if self._in_active_monitor:
                await self.iface.clear_fake_mac()
        finally:
            # The array's own-MAC registration must be released even when the card refused the
            # clear: a stale entry makes ingest drop frames we never sent.
            if self._own_mac is not None:
                self._array.unregister_own_mac(self._own_mac)
            self._in_active_monitor = False
            self._own_mac = None

    async def __aenter__(self):
        self._orig_channel = self.iface.current_channel
        if self._channel is not None:
            await self.iface.set_channel(self._channel)
        if self._fake_mac is not None:
            await self.enter_active_monitor(self._fake_mac)
        if self._ack_tally:
            await self.iface.enable_rx_acks()
        return self.iface

    async def __aexit__(self, exc_type=None, exc=None, tb=None) -> bool:
        """Restore everything the lease changed, even when one restore step fails.

        A card can be unplugged mid-lease, and then the first restore raises (usually a USBError
        from the ACK-tally write). Running the three steps unguarded would skip the other two,
        leaving the own-MAC registered and the card parked on the target channel. Each step is
        isolated instead; the first failure is raised afterwards, but only when the body itself
        did not raise, so cleanup never masks the original error.
        """
        failures: List[Exception] = []
        if self._ack_tally:
            try:
                await self.iface.disable_rx_acks()
            except Exception as error:
                failures.append(error)
        try:
            await self._exit_active_monitor()
        except Exception as error:
            failures.append(error)
        if self._channel is not None and self._orig_channel is not None:
            try:
                await self.iface.set_channel(self._orig_channel)
            except Exception as error:
                failures.append(error)
        if failures:
            logger.warning("lease on %s restored with %d error(s): %s",
                           getattr(self.iface, "name", self.iface), len(failures), failures)
            if exc_type is None:
                raise failures[0]
        return False

    async def acquire(self):
        """Enter the lease imperatively, for a campaign that holds it across method calls."""
        return await self.__aenter__()

    async def release(self) -> None:
        """Exit the lease imperatively; the inverse of ``acquire``."""
        await self.__aexit__(None, None, None)

    @property
    def active_monitor_mac(self) -> Optional[str]:
        """The MAC registered for this lease: the one the device active-monitors as, else the
        requested MAC on a device that can't active-monitor; None when no MAC was requested."""
        return self._own_mac
