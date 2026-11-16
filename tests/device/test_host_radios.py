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
    """Live-host smoke test. Skips when this machine has no CNVi radio, rather than passing
    vacuously on an empty list."""
    radios = host_radios.probe_windows()
    if not radios:
        pytest.skip("this host reports no CNVi radio")
    for radio in radios:
        assert radio.vendor == host_radios.INTEL_VENDOR
        assert radio.device in host_radios.CNVI_DEVICE_IDS


# ---- probe orchestration ----------------------------------------------------
# `python -m wifit3.device.host_radios` is the only visible product surface of this module,
# and none of it was covered: patch a typo into probe_windows or main and every test stayed green.

def _fabricate_pci(root, name, vendor, device, sub_vendor=None, sub_device=None, driver=None):
    """Build one /sys/bus/pci/devices entry so probe_linux can be exercised without that host."""
    entry = root / name
    entry.mkdir(parents=True)
    (entry / "vendor").write_text(f"0x{vendor:04x}\n", encoding="ascii")
    (entry / "device").write_text(f"0x{device:04x}\n", encoding="ascii")
    if sub_vendor is not None:
        (entry / "subsystem_vendor").write_text(f"0x{sub_vendor:04x}\n", encoding="ascii")
    if sub_device is not None:
        (entry / "subsystem_device").write_text(f"0x{sub_device:04x}\n", encoding="ascii")
    if driver is not None:
        target = root.parent / "drivers" / driver
        target.mkdir(parents=True, exist_ok=True)
        try:
            (entry / "driver").symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are unavailable to this user")
    return entry


def test_probe_windows_decodes_the_subsys_pair_in_windows_order(monkeypatch):
    """Windows packs SUBSYS as <device><vendor>; getting the halves backwards is invisible."""
    monkeypatch.setattr(host_radios, "_windows_pci_ids",
                        lambda: [r"PCI\VEN_8086&DEV_A0F0&SUBSYS_42A48086&REV_00"])
    monkeypatch.setattr(host_radios, "_windows_driver_names", lambda: ["Netwtw10.sys"])
    radio = host_radios.probe_windows()[0]
    assert radio.subsystem_vendor == 0x8086
    assert radio.subsystem_device == 0x42A4
    assert radio.subsystem_id == "8086:42a4"


def test_probe_windows_skips_non_intel_ids_and_unlisted_intel_ids(monkeypatch):
    monkeypatch.setattr(host_radios, "_windows_pci_ids", lambda: [
        r"PCI\VEN_10DE&DEV_1C82&SUBSYS_00000000&REV_A1",
        r"PCI\VEN_8086&DEV_9DED&SUBSYS_00000000&REV_00",     # Intel, but not a Wi-Fi function
        "PCI\\VEN_ACPI&DEV_0001",
    ])
    monkeypatch.setattr(host_radios, "_windows_driver_names", lambda: ["Netwtw10.sys"])
    assert host_radios.probe_windows() == []


def test_probe_windows_flags_ambiguity_when_several_drivers_are_installed(monkeypatch):
    monkeypatch.setattr(host_radios, "_windows_pci_ids",
                        lambda: [r"PCI\VEN_8086&DEV_A0F0&SUBSYS_42A48086&REV_00"])
    monkeypatch.setattr(host_radios, "_windows_driver_names",
                        lambda: ["Netwtw06.sys", "Netwtw10.sys"])
    radio = host_radios.probe_windows()[0]
    assert radio.driver == ""
    assert any("several Intel Wi-Fi drivers" in note for note in radio.notes)


def test_probe_linux_reads_a_fabricated_sysfs_tree(tmp_path):
    root = tmp_path / "pci"
    _fabricate_pci(root, "pci-0000-00-14.3", 0x8086, 0xA0F0,
                   sub_vendor=0x8086, sub_device=0x42A4, driver="iwlwifi")
    radios = host_radios.probe_linux(root)
    assert len(radios) == 1
    assert radios[0].architecture is host_radios.Architecture.CNVI
    assert radios[0].driver == "iwlwifi"
    assert radios[0].location == "pci-0000-00-14.3"


def test_probe_linux_reports_an_intel_radio_bound_to_iwlwifi_even_if_unlisted(tmp_path):
    root = tmp_path / "pci"
    _fabricate_pci(root, "pci-0000-00-14.2", 0x8086, 0x2723, driver="iwlwifi")
    radios = host_radios.probe_linux(root)
    assert [(r.device, r.driver) for r in radios] == [(0x2723, "iwlwifi")]


def test_probe_linux_skips_non_intel_and_unbound_unknown_ids(tmp_path):
    root = tmp_path / "pci"
    _fabricate_pci(root, "pci-0000-01-00.0", 0x10DE, 0x1C82)
    _fabricate_pci(root, "pci-0000-00-1f.3", 0x8086, 0x9DC8)      # Intel, unbound, unlisted
    assert host_radios.probe_linux(root) == []


def test_probe_linux_reports_no_driver_rather_than_a_driver_named_driver(tmp_path):
    """resolve(strict=False) returns the literal "driver" for a missing symlink."""
    root = tmp_path / "pci"
    _fabricate_pci(root, "pci-0000-00-14.3", 0x8086, 0xA0F0)
    assert host_radios.probe_linux(root)[0].driver == ""


def test_probe_linux_without_sysfs_returns_nothing(tmp_path):
    assert host_radios.probe_linux(tmp_path / "missing") == []


def test_host_radios_dispatches_on_the_platform(monkeypatch):
    monkeypatch.setattr(host_radios.sys, "platform", "darwin")
    assert host_radios.host_radios() == []


def test_main_prints_the_report_and_exits_zero_when_a_radio_is_found(monkeypatch, capsys):
    monkeypatch.setattr(host_radios, "host_radios",
                        lambda: [host_radios._classify(_radio())])
    assert host_radios.main() == 0
    assert "Intel Wireless-AC 9462" in capsys.readouterr().out


def test_main_exits_nonzero_when_no_radio_is_found(monkeypatch, capsys):
    monkeypatch.setattr(host_radios, "host_radios", list)
    assert host_radios.main() == 1
    assert "none reported" in capsys.readouterr().out
