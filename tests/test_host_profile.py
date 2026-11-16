"""Host profile: the join of the capability probe and the host-radio probe.

The point of this module is that two surfaces (CLI and TUI panel) read one payload, so the tests
that matter are the ones that would catch a second, divergent join: an adapter described with
different fields by the two CLI entry points, or a host summarised as injection capable while its
only radio is a CNVi part that refuses it.
"""
from __future__ import annotations

import json
import sys

import pytest

from wifit3 import host_profile
from wifit3 import wireless_capabilities as wc
from wifit3.device import host_radios as hr


def _cnvi() -> hr.HostRadio:
    return hr._classify(hr.HostRadio(vendor=hr.INTEL_VENDOR, device=0xA0F0))


def _profile(*verdicts: wc.Verdict, radios=(), drivable: int = 382,
             drivable_error: str = "") -> host_profile.HostProfile:
    adapters = [wc.AdapterReport(name=f"WLAN{index}", verdict=verdict)
                for index, verdict in enumerate(verdicts)]
    return host_profile.HostProfile(
        platform="win32",
        capabilities=wc.ProbeReport(platform="win32", adapters=adapters, notes=["a platform note"]),
        radios=list(radios),
        drivable_ids=drivable,
        drivable_error=drivable_error,
        scanned_at="2026-11-16T15:00:00+08:00",
    )


# ---- the headline ---------------------------------------------------------

def test_best_is_the_strongest_verdict_any_adapter_earned():
    """A second, passive card must improve the answer: the host can capture through it."""
    profile = _profile(wc.Verdict.FIRMWARE_REFUSED, wc.Verdict.PASSIVE_ONLY)
    assert profile.best is wc.Verdict.PASSIVE_ONLY
    assert profile.can_inject is False


def test_injection_wins_over_weaker_cards():
    profile = _profile(wc.Verdict.PASSIVE_ONLY, wc.Verdict.INJECTION_CAPABLE)
    assert profile.best is wc.Verdict.INJECTION_CAPABLE
    assert profile.can_inject is True


def test_no_adapter_at_all_is_unknown_and_not_injectable():
    profile = _profile()
    assert profile.best is wc.Verdict.UNKNOWN
    assert profile.can_inject is False
    assert "unknown" in profile.headline()


def test_a_cnvi_radio_never_makes_the_host_look_injectable():
    """The honesty rule: a radio wifit3 cannot open must not be counted as an opportunity."""
    profile = _profile(wc.Verdict.FIRMWARE_REFUSED, radios=[_cnvi()])
    assert profile.can_inject is False
    assert "injection capable" not in profile.headline()
    assert profile.radios[0].reach is hr.Reach.PASSIVE


def test_every_verdict_has_a_headline():
    for verdict in wc.Verdict:
        profile = _profile(verdict)
        assert profile.best is verdict
        assert profile.headline().strip()


# ---- build ----------------------------------------------------------------

def test_build_isolates_a_broken_driver_registry():
    """If the chip registry fails to import, the diagnostic still reports the probes it has."""
    def boom() -> int:
        raise ImportError("no chips here")

    profile = host_profile.build(
        capability_probe=lambda: wc.ProbeReport(platform="win32"),
        radio_probe=lambda: [_cnvi()],
        drivable_count=boom,
    )
    assert profile.drivable_error.startswith("ImportError")
    assert profile.drivable_ids == 0
    assert len(profile.radios) == 1


def test_build_stamps_the_scan_time_and_platform():
    profile = host_profile.build(
        capability_probe=lambda: wc.ProbeReport(platform="linux"),
        radio_probe=list,
        drivable_count=lambda: 7,
    )
    assert profile.scanned_at
    assert profile.platform == "linux"
    assert profile.drivable_ids == 7


# ---- the payload both surfaces read ---------------------------------------

def test_to_dict_carries_both_halves():
    payload = host_profile.to_dict(_profile(wc.Verdict.PASSIVE_ONLY, radios=[_cnvi()]))
    assert payload["best"] == "passive_only"
    assert payload["can_inject"] is False
    assert payload["adapters"][0]["verdict"] == "passive_only"
    assert payload["host_radios"][0]["architecture"] == "cnvi"
    assert payload["drivable"] == {"ids": 382, "error": ""}
    assert payload["notes"] == ["a platform note"]


def test_to_dict_is_json_safe():
    payload = host_profile.to_dict(_profile(wc.Verdict.FIRMWARE_REFUSED, radios=[_cnvi()]))
    assert json.loads(json.dumps(payload, ensure_ascii=False))["best"] == "firmware_refused"


def test_render_text_is_the_two_probe_reports_plus_a_header():
    """Neither probe's rendering is reimplemented here: both are quoted, so a fix in either
    probe reaches the CLI and the panel at once."""
    profile = _profile(wc.Verdict.FIRMWARE_REFUSED, radios=[_cnvi()])
    text = host_profile.render_text(profile)
    assert text.startswith("Host profile (platform: win32)")
    assert wc.render(profile.capabilities) in text
    assert hr.render(profile.radios) in text


def test_render_text_says_so_when_the_registry_is_unavailable():
    text = host_profile.render_text(_profile(drivable=0, drivable_error="OSError: nope"))
    assert "unavailable (OSError: nope)" in text


def test_summary_line_names_the_reason_the_radios_and_the_registry():
    line = host_profile.summary_line(_profile(wc.Verdict.PASSIVE_ONLY, radios=[_cnvi()]))
    assert "passive only" in line
    assert "1 non-USB radio(s) not drivable" in line
    assert "382 supported vid:pid registered" in line


# ---- the two CLI entry points ---------------------------------------------

def test_the_two_cli_entry_points_describe_an_adapter_identically(monkeypatch, capsys):
    """``wifit3 --capabilities json`` and ``python -m wifit3.wireless_capabilities --json``
    must not describe the same adapter with different fields."""
    report = wc.ProbeReport(platform="win32", adapters=[
        wc.AdapterReport(name="WLAN", verdict=wc.Verdict.FIRMWARE_REFUSED, driver="Netwtw10.sys"),
    ])
    monkeypatch.setattr(wc, "probe", lambda: report)

    assert wc.main(["--json"]) == 0
    from_capability_module = json.loads(capsys.readouterr().out)

    profile = host_profile.build(capability_probe=lambda: report, radio_probe=list,
                                 drivable_count=lambda: 1)
    from_host_profile = host_profile.to_dict(profile)

    assert from_capability_module["adapters"] == from_host_profile["adapters"]


def test_main_json_emits_the_payload(monkeypatch, capsys):
    monkeypatch.setattr(host_profile, "build", lambda: _profile(wc.Verdict.INJECTION_CAPABLE))
    assert host_profile.main(["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["best"] == "injection_capable"


def test_main_quiet_prints_only_the_summary(monkeypatch, capsys):
    monkeypatch.setattr(host_profile, "build", lambda: _profile(wc.Verdict.PASSIVE_ONLY))
    assert host_profile.main(["--quiet"]) == 0
    out = capsys.readouterr().out.strip()
    assert out == host_profile.summary_line(_profile(wc.Verdict.PASSIVE_ONLY))


def test_main_exits_nonzero_when_there_is_no_adapter(monkeypatch, capsys):
    """A script gates on the exit code: "it printed fine" is not "there is a radio here"."""
    monkeypatch.setattr(host_profile, "build", lambda: _profile())
    assert host_profile.main([]) == 1
    assert "unknown" in capsys.readouterr().out


def test_the_tui_entry_point_dispatches_capabilities_and_exits(monkeypatch, capsys):
    """``wifit3 --capabilities json`` must not launch the TUI: it is the scriptable half."""
    from wifit3 import __main__ as cli

    monkeypatch.setattr(sys, "argv", ["wifit3", "--capabilities", "json"])
    monkeypatch.setattr(host_profile, "build", lambda: _profile(wc.Verdict.PASSIVE_ONLY))

    with pytest.raises(SystemExit) as exit_info:
        cli.main()

    assert exit_info.value.code == 0
    assert json.loads(capsys.readouterr().out)["best"] == "passive_only"
