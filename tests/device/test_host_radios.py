"""Host (non-USB) radio reporting: architecture classification and the honesty rules."""
from __future__ import annotations

import sys

import pytest

from wifit3.device import host_radios


def _radio(**kwargs) -> host_radios.HostRadio:
    base = dict(vendor=host_radios.INTEL_VENDOR, device=0xA0F0)
    base.update(kwargs)
    return host_radios.HostRadio(**base)


def test_verified_cnvi_id_is_classified_as_cnvi_and_passive():
    radio = host_radios._classify(_radio())
    assert radio.architecture is host_radios.Architecture.CNVI
    assert radio.reach is host_radios.Reach.PASSIVE
    assert radio.model == "Intel Wireless-AC 9462"
    assert any("Bluetooth" in note for note in radio.notes)


def test_cnvi_notes_state_that_injection_is_unavailable():
    radio = host_radios._classify(_radio())
    joined = " ".join(radio.notes)
    assert "monitor mode" in joined
    assert "cannot run" in joined


def test_unlisted_intel_id_with_the_windows_driver_makes_no_architecture_claim():
    radio = host_radios._classify(_radio(device=0x9999, driver="Netwtw10.sys"))
    assert radio.architecture is host_radios.Architecture.UNKNOWN
    assert radio.reach is host_radios.Reach.NONE
    assert any("not in the verified CNVi table" in note for note in radio.notes)


def test_non_intel_controller_is_a_discrete_pcie_device():
    radio = host_radios._classify(_radio(vendor=0x14E4, device=0x43A0))
    assert radio.architecture is host_radios.Architecture.PCIE
    assert radio.reach is host_radios.Reach.NONE


def test_pci_and_subsystem_ids_render_like_lspci():
    radio = _radio(subsystem_vendor=0x8086, subsystem_device=0x42A4)
    assert radio.pci_id == "8086:a0f0"
    assert radio.subsystem_id == "8086:42a4"


def test_subsystem_id_is_omitted_when_unknown():
    assert _radio().subsystem_id == ""


def test_render_lists_the_radio_and_its_reach():
    text = host_radios.render([host_radios._classify(_radio())])
    assert "Intel Wireless-AC 9462" in text
    assert "8086:a0f0" in text
    assert "cnvi" in text and "passive" in text


def test_render_handles_an_empty_host():
    assert "none reported" in host_radios.render([])


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows PnP enumeration")
def test_probe_windows_finds_the_cnvi_radio_when_present():
    radios = host_radios.probe_windows()
    for radio in radios:
        assert radio.vendor == host_radios.INTEL_VENDOR
        assert radio.device in host_radios.CNVI_DEVICE_IDS
