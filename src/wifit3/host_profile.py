"""The host in one answer: what its radios can do, and what wifit3 can never touch.

Two probes already answer halves of this and neither is repeated here:

* ``wireless_capabilities.probe()`` gives, per adapter, the OS's own capability report and a
  verdict (injection capable / passive only / firmware refused / no driver / no PHY).
* ``device.host_radios.host_radios()`` gives the controllers that are not on the USB bus at all,
  which the device layer can therefore never open.

Both surfaces need the same picture, so the join lives here once: ``wifit3 --capabilities``
prints it, the TUI panel draws it. One payload, two renderers. Two independent joins would
drift, and the first symptom would be a panel that disagrees with the log a script captured.

The honesty rule the probes keep is kept here too: ``best`` is the strongest verdict an adapter
actually earned, and ``can_inject`` is derived from it, so a host whose only radio is
passive-only can never be summarised as injection capable.
"""
from __future__ import annotations

import argparse
import datetime
import json
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from wifit3 import wireless_capabilities as wc
from wifit3.device import host_radios as hr

# Strongest first: the headline is the first tier any adapter earned. The failure tiers are
# ordered by how much information they give the user, not by severity: "firmware refused" means
# a working radio that will not do it, which is a different remedy from "no driver at all".
_TIER_ORDER = (
    wc.Verdict.INJECTION_CAPABLE,
    wc.Verdict.PASSIVE_ONLY,
    wc.Verdict.FIRMWARE_REFUSED,
    wc.Verdict.HARDWARE_LACKING,
    wc.Verdict.DRIVER_UNSUPPORTED,
    wc.Verdict.UNKNOWN,
)

_HEADLINE: Dict[wc.Verdict, str] = {
    wc.Verdict.INJECTION_CAPABLE:
        "injection capable: monitor mode plus raw TX, so every campaign can run on this card",
    wc.Verdict.PASSIVE_ONLY:
        "passive only: frames can be captured, nothing can be transmitted",
    wc.Verdict.FIRMWARE_REFUSED:
        "refused by firmware: the radio works, but monitor mode is not offered to user space",
    wc.Verdict.HARDWARE_LACKING:
        "no usable PHY: the radio reports neither a radio type nor a capability set",
    wc.Verdict.DRIVER_UNSUPPORTED:
        "no driver: this host exposes no wireless interface",
    wc.Verdict.UNKNOWN:
        "unknown: the OS reported nothing decisive about this radio",
}


@dataclass
class HostProfile:
    """One host, both probes, and what the combination means."""

    platform: str
    capabilities: wc.ProbeReport
    radios: List[hr.HostRadio] = field(default_factory=list)
    drivable_ids: int = 0
    drivable_error: str = ""
    scanned_at: str = ""

    @property
    def adapters(self) -> List[wc.AdapterReport]:
        return self.capabilities.adapters

    @property
    def best(self) -> wc.Verdict:
        earned = {adapter.verdict for adapter in self.adapters}
        for tier in _TIER_ORDER:
            if tier in earned:
                return tier
        return wc.Verdict.UNKNOWN

    @property
    def can_inject(self) -> bool:
        return self.best is wc.Verdict.INJECTION_CAPABLE

    def headline(self) -> str:
        return _HEADLINE[self.best]


def _drivable_count() -> int:
    """How many ``vid:pid`` pairs the chip registry claims, independent of what is plugged in.

    Imported late: ``device.manager`` pulls the chip packages in, which costs most of a second
    and must not slow down importing this module (the TUI imports it on every launch).
    """
    from wifit3.device.manager import supported_ids

    return len(supported_ids())


def build(
    capability_probe: Callable[[], wc.ProbeReport] = wc.probe,
    radio_probe: Callable[[], List[hr.HostRadio]] = hr.host_radios,
    drivable_count: Callable[[], int] = _drivable_count,
) -> HostProfile:
    """Probe this host. The three probes are injectable so tests never touch real hardware."""
    capabilities = capability_probe()
    profile = HostProfile(
        # Taken from the report rather than from sys.platform a second time: the probe already
        # stamped it, and two readings of "which OS is this" is how a header ends up disagreeing
        # with the body it introduces.
        platform=capabilities.platform,
        capabilities=capabilities,
        radios=radio_probe(),
        scanned_at=datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    )
    try:
        profile.drivable_ids = drivable_count()
    except Exception as exc:  # a diagnostic that dies here would report nothing at all
        profile.drivable_error = f"{type(exc).__name__}: {exc}"
    return profile


def to_dict(profile: HostProfile) -> Dict[str, object]:
    """JSON-safe view. Adapter and radio shapes come from their own modules, not from here."""
    return {
        "platform": profile.platform,
        "scanned_at": profile.scanned_at,
        "best": profile.best.value,
        "headline": profile.headline(),
        "can_inject": profile.can_inject,
        "drivable": {"ids": profile.drivable_ids, "error": profile.drivable_error},
        "error": profile.capabilities.error,
        "adapters": [wc.as_dict(adapter) for adapter in profile.adapters],
        "host_radios": [hr.as_dict(radio) for radio in profile.radios],
        "notes": list(profile.capabilities.notes),
    }


def render_text(profile: HostProfile) -> str:
    """The report as plain text: a header we own, then each probe's own rendering verbatim."""
    lines = [
        f"Host profile (platform: {profile.platform})   {profile.scanned_at}",
        f"  best this host can do : {profile.headline()}",
    ]
    if profile.drivable_error:
        lines.append(f"  drivable adapters     : unavailable ({profile.drivable_error})")
    else:
        lines.append(f"  drivable adapters     : {profile.drivable_ids} registered vid:pid "
                     "(a card still has to be plugged in)")
    lines.append("")
    lines.append(wc.render(profile.capabilities))
    lines.append("")
    lines.append(hr.render(profile.radios))
    return "\n".join(lines)


def summary_line(profile: HostProfile) -> str:
    """One line for a footer, a toast, or the top of a panel."""
    parts = [profile.headline()]
    if profile.radios:
        parts.append(f"{len(profile.radios)} non-USB radio(s) not drivable")
    if not profile.drivable_error:
        parts.append(f"{profile.drivable_ids} supported vid:pid registered")
    return " | ".join(parts)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="wifit3-capabilities",
        description="Report this host's adapters, their wireless capabilities, and the radios "
                    "wifit3 cannot drive.")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--quiet", action="store_true",
                        help="print only the summary line (exit code still reports adapters)")
    args = parser.parse_args(argv)

    profile = build()
    if args.json:
        print(json.dumps(to_dict(profile), indent=2, ensure_ascii=False))
    elif args.quiet:
        print(summary_line(profile))
    else:
        print(render_text(profile))
    # Non-zero when there is no adapter to work with: a script gates on this, and an empty
    # host is the one case where "it printed fine" is not the same as "there is something here".
    return 0 if profile.adapters else 1


if __name__ == "__main__":
    raise SystemExit(main())
