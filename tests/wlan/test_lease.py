"""Unit tests for the interface Lease: config on enter, restore on exit."""
import pytest

from wifit3.wlan.lease import Lease, SPOOFABLE


class FakeIface:
    def __init__(self, channel=1, active_monitor_mac="02:aa:bb:cc:dd:ee"):
        self.current_channel = channel
        self._active_monitor_mac = active_monitor_mac
        self.calls = []
        self.raise_on = set()          # names of methods that should fail, as an unplugged card does

    async def set_channel(self, ch, scan=False):
        if "set_channel" in self.raise_on:
            raise OSError("device gone")
        self.current_channel = ch
        self.calls.append(("set_channel", ch))
        return True

    async def set_fake_mac(self, mac=None, bssid=None):
        self.calls.append(("set_fake_mac", mac, bssid))
        return self._active_monitor_mac

    async def clear_fake_mac(self):
        if "clear_fake_mac" in self.raise_on:
            raise OSError("device gone")
        self.calls.append(("clear_fake_mac",))

    async def enable_rx_acks(self):
        self.calls.append(("enable_rx_acks",))

    async def disable_rx_acks(self):
        if "disable_rx_acks" in self.raise_on:
            raise OSError("device gone")
        self.calls.append(("disable_rx_acks",))


class FakeArray:
    def __init__(self):
        self.own = set()

    def register_own_mac(self, mac):
        self.own.add(mac.lower())
        return mac.lower()

    def unregister_own_mac(self, mac):
        self.own.discard(mac.lower())


async def test_lease_enters_active_monitor_and_restores():
    iface, arr = FakeIface(channel=1), FakeArray()
    async with Lease(arr, iface, channel=6, fake_mac=SPOOFABLE,
                     bssid="aa:bb:cc:dd:ee:ff", ack_tally=True) as got:
        assert got is iface
        assert iface.current_channel == 6
        assert "02:aa:bb:cc:dd:ee" in arr.own
        assert ("enable_rx_acks",) in iface.calls
    assert iface.current_channel == 1              # channel restored
    assert arr.own == set()                        # own MAC released
    assert ("clear_fake_mac",) in iface.calls
    assert ("disable_rx_acks",) in iface.calls


async def test_lease_without_fake_mac_never_touches_own():
    iface, arr = FakeIface(channel=6), FakeArray()
    async with Lease(arr, iface, channel=6) as got:
        assert got is iface
    assert arr.own == set()
    assert not any(c[0] == "set_fake_mac" for c in iface.calls)


async def test_lease_channel_only_restores_original():
    iface, arr = FakeIface(channel=3), FakeArray()
    async with Lease(arr, iface, channel=11):
        assert iface.current_channel == 11
    assert iface.current_channel == 3


async def test_lease_registers_concrete_mac_when_active_monitor_fails():
    iface, arr = FakeIface(active_monitor_mac=None), FakeArray()
    async with Lease(arr, iface, fake_mac="02:11:22:33:44:55") as got:
        assert got is iface
        assert "02:11:22:33:44:55" in arr.own          # still transmit from it, un-ACKed
    assert arr.own == set()


async def test_lease_spoofable_active_monitor_failure_registers_nothing():
    iface, arr = FakeIface(active_monitor_mac=None), FakeArray()
    async with Lease(arr, iface, fake_mac=SPOOFABLE):
        assert arr.own == set()


async def test_enter_active_monitor_replaces_the_mac():
    iface, arr = FakeIface(active_monitor_mac=None), FakeArray()          # un-ACKed: own == requested
    lease = Lease(arr, iface, fake_mac="02:aa:aa:aa:aa:01")
    async with lease:
        assert arr.own == {"02:aa:aa:aa:aa:01"}
        await lease.enter_active_monitor("02:bb:bb:bb:bb:02")
        assert arr.own == {"02:bb:bb:bb:bb:02"}              # old released, new registered
        assert lease.active_monitor_mac == "02:bb:bb:bb:bb:02"
    assert arr.own == set()                                  # released on exit


# ----- an unplugged card must not strand the array ---------------------------
# A card can vanish mid-lease; the ACK-tally write is then the first thing to raise. If the
# three restores ran unguarded, that one error would skip the other two and leave the own-MAC
# registered (making ingest drop frames we never sent) and the card parked on the target channel.

async def test_exit_still_releases_the_own_mac_when_acks_cannot_be_disarmed():
    iface, arr = FakeIface(channel=1), FakeArray()
    iface.raise_on = {"disable_rx_acks"}
    with pytest.raises(OSError, match="device gone"):    # surfaced, not swallowed
        async with Lease(arr, iface, channel=6, fake_mac=SPOOFABLE, ack_tally=True):
            assert arr.own
    assert arr.own == set()                 # registration released despite the failure
    assert iface.current_channel == 1       # channel restored despite the failure


async def test_exit_keeps_the_original_error_when_cleanup_also_fails():
    iface, arr = FakeIface(channel=1), FakeArray()
    iface.raise_on = {"disable_rx_acks"}
    with pytest.raises(ValueError, match="body blew up"):
        async with Lease(arr, iface, channel=6, fake_mac=SPOOFABLE, ack_tally=True):
            raise ValueError("body blew up")
    assert arr.own == set()
    assert iface.current_channel == 1


async def test_exit_releases_the_own_mac_even_when_the_mac_cannot_be_cleared():
    iface, arr = FakeIface(active_monitor_mac="02:aa:bb:cc:dd:ee"), FakeArray()
    iface.raise_on = {"clear_fake_mac"}
    with pytest.raises(OSError, match="device gone"):
        async with Lease(arr, iface, fake_mac=SPOOFABLE):
            assert arr.own == {"02:aa:bb:cc:dd:ee"}
    assert arr.own == set()


async def test_exit_raises_the_cleanup_failure_when_the_body_was_clean():
    iface, arr = FakeIface(channel=1), FakeArray()
    iface.raise_on = {"set_channel"}
    with pytest.raises(OSError, match="device gone"):
        async with Lease(arr, iface, channel=6):
            pass
