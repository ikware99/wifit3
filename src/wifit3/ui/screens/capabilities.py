"""Host capabilities panel: the CLI's host profile, drawn instead of printed.

The data is ``wifit3.host_profile``, the same payload ``wifit3 --capabilities`` emits, so the
panel cannot contradict a log a script captured. "Copy" copies ``render_text(profile)``, which is
byte for byte what the CLI prints: a screenshot and a pasted report are the same evidence.

The probe shells out to netsh / iw and takes about a second, so it runs on a worker thread. The
panel paints a placeholder first and fills in when the profile lands, which keeps a modal that
takes a second from looking like a hung modal.
"""
from __future__ import annotations

from typing import Callable, List, Optional

from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.table import Table
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

from wifit3 import host_profile
from wifit3.host_profile import HostProfile
from wifit3.wireless_capabilities import CAPABILITY_ORDER, Verdict

# One style per verdict, so the colour is decided in one place and the table, the headline and
# the copy action cannot disagree about how a tier is spelled.
_VERDICT_STYLE = {
    Verdict.INJECTION_CAPABLE: "bold green",
    Verdict.PASSIVE_ONLY: "yellow",
    Verdict.FIRMWARE_REFUSED: "red",
    Verdict.HARDWARE_LACKING: "red",
    Verdict.DRIVER_UNSUPPORTED: "red",
    Verdict.UNKNOWN: "dim",
}

_CAP_TITLE = {
    "monitor_mode": "monitor mode",
    "promiscuous": "promiscuous",
    "soft_ap": "soft AP",
    "ibss": "IBSS",
    "action_frames": "action frames",
    "protected_mgmt": "protected mgmt",
}


def _table(*columns: str) -> Table:
    table = Table(box=None, pad_edge=False, show_edge=False, expand=False)
    for column in columns:
        table.add_column(column, no_wrap=False)
    return table


def _header(profile: HostProfile) -> RenderableType:
    head = Text()
    head.append("best this host can do  ", style="dim")
    head.append(profile.headline(), style=_VERDICT_STYLE[profile.best])
    lines = [head]
    detail = Text()
    detail.append("probed ", style="dim")
    detail.append(profile.scanned_at or "just now", style="dim")
    detail.append("  platform ", style="dim")
    detail.append(profile.platform or "?", style="dim")
    lines.append(detail)
    if profile.drivable_error:
        lines.append(Text(f"supported vid:pid unavailable ({profile.drivable_error})",
                          style="red"))
    else:
        lines.append(Text(f"{profile.drivable_ids} supported vid:pid registered "
                          "(a card still has to be plugged in)", style="dim"))
    return Group(*lines)


def adapter_table(profile: HostProfile) -> Optional[Table]:
    """One row per adapter: what the OS calls it, the driver, and the verdict it earned."""
    if not profile.adapters:
        return None
    table = _table("adapter", "driver", "verdict", "monitor  TX")
    for adapter in profile.adapters:
        driver = adapter.driver or "none bound"
        if adapter.driver_version:
            driver = f"{driver} {adapter.driver_version}"
        args = "yes" if adapter.monitor else "no"
        tx = "yes" if adapter.injection else "no"
        table.add_row(
            adapter.name,
            Text(driver, style="dim"),
            Text(adapter.verdict.value, style=_VERDICT_STYLE[adapter.verdict]),
            Text(f"{args:<8} {tx}"),
        )
    return table


def capability_table(profile: HostProfile) -> Optional[Table]:
    """The OS's capability report, transposed: capabilities down, adapters across."""
    reported = [a for a in profile.adapters if a.capabilities]
    if not reported:
        return None
    table = _table("capability", *[a.name for a in reported])
    for key in CAPABILITY_ORDER:
        row = [_CAP_TITLE.get(key, key)]
        for adapter in reported:
            cap = adapter.capabilities.get(key)
            value = cap.rendered() if cap is not None else "-"
            style = {"yes": "green", "no": "red"}.get(value, "dim")
            row.append(Text(value, style=style))
        table.add_row(*row)
    return table


def radio_table(profile: HostProfile) -> Optional[Table]:
    """Controllers that are not on the USB bus, hence outside the device layer entirely."""
    if not profile.radios:
        return None
    table = _table("non-USB radio", "pci", "driver", "kind", "reach")
    for radio in profile.radios:
        table.add_row(
            radio.describe(),
            Text(radio.pci_id, style="dim"),
            Text(radio.driver or "none bound", style="dim"),
            radio.architecture.value,
            Text(radio.reach.value, style="red"),
        )
    return table


def note_block(profile: HostProfile) -> List[RenderableType]:
    out: List[RenderableType] = []
    for radio in profile.radios:
        if not radio.notes:
            continue
        out.append(Text(f"{radio.describe()}:", style="bold"))
        for note in radio.notes:
            # Padding rather than leading spaces: a wrapped note keeps its indent, and these
            # notes are long enough that every one of them wraps at panel width.
            out.append(Padding(Text(f"- {note}", style="dim"), (0, 0, 0, 2)))
    if profile.capabilities.notes:
        out.append(Text("platform notes:", style="bold"))
        for note in profile.capabilities.notes:
            out.append(Padding(Text(f"- {note}", style="dim"), (0, 0, 0, 2)))
    return out


def build_body(profile: HostProfile) -> RenderableType:
    """The whole panel body, as a pure function so a test can render it without a terminal."""
    blocks: List[RenderableType] = [_header(profile)]
    if profile.capabilities.error:
        blocks.append(Text(profile.capabilities.error, style="bold red"))

    for title, table in (
        ("adapters", adapter_table(profile)),
        ("capabilities as the OS reports them", capability_table(profile)),
        ("not drivable by wifit3", radio_table(profile)),
    ):
        if table is None:
            continue
        blocks.append(Text(title, style="bold"))
        blocks.append(table)

    blocks.extend(note_block(profile))
    return Group(*blocks)


class CapabilitiesPanel(ModalScreen[None]):
    """What this host's radios can do, and what wifit3 cannot touch."""

    BINDINGS = [
        Binding("escape", "close", "Close", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("y", "copy", "Copy", show=True),
    ]

    DEFAULT_CSS = """
    CapabilitiesPanel {
        align: center middle;
    }
    CapabilitiesPanel #frame {
        width: 96%;
        max-width: 140;
        height: 90%;
        border: thick $primary;
        background: $surface;
        padding: 0 1;
    }
    CapabilitiesPanel #title {
        width: 1fr;
        text-align: center;
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    CapabilitiesPanel #body {
        height: 1fr;
        padding: 0 1;
        overflow-y: auto;
    }
    CapabilitiesPanel #buttons {
        dock: bottom;
        height: auto;
        align: center middle;
    }
    CapabilitiesPanel Button {
        /* The default Button min-width (16) times three plus margins overflows a 50-column
           terminal, which pushed Close off the right edge. These labels are short, so let the
           button size to them. */
        min-width: 8;
        padding: 0 1;
        margin: 0 1;
    }
    """

    def __init__(self, builder: Optional[Callable[[], HostProfile]] = None) -> None:
        super().__init__()
        # Injectable so a test never shells out to netsh / iw.
        self._build = builder or host_profile.build
        self._profile: Optional[HostProfile] = None
        # The exact renderable handed to the widget. Kept so a test can inspect what is on
        # screen without reaching through Textual's visual wrapper.
        self._body: Optional[RenderableType] = None

    @property
    def profile(self) -> Optional[HostProfile]:
        """The profile on screen, or None while the probe is still running."""
        return self._profile

    @property
    def body(self) -> Optional[RenderableType]:
        """What the panel is displaying right now."""
        return self._body

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield Label("Host radios & wireless capabilities", id="title")
            with VerticalScroll(id="body"):
                yield Static("[dim]Probing this host, this takes about a second...[/dim]",
                             id="report")
            with Horizontal(id="buttons"):
                yield Button("Refresh", id="btn-refresh")
                yield Button("Copy", id="btn-copy")
                yield Button("Close", id="btn-close", variant="primary")

    def on_mount(self) -> None:
        self._start_probe()

    # --- probing ------------------------------------------------------------

    def _start_probe(self) -> None:
        self._profile = None
        self._body = None
        self.query_one("#report", Static).update(
            "[dim]Probing this host, this takes about a second...[/dim]")
        self._probe()

    @work(thread=True, exclusive=True, group="host-profile")
    def _probe(self) -> None:
        try:
            profile = self._build()
        except Exception as exc:  # a diagnostic panel must report the failure, not vanish
            self.app.call_from_thread(self._show_error, f"{type(exc).__name__}: {exc}")
            return
        self.app.call_from_thread(self._show, profile)

    def _show(self, profile: HostProfile) -> None:
        if not self.is_attached:
            return
        self._profile = profile
        self._body = build_body(profile)
        self.query_one("#report", Static).update(self._body)

    def _show_error(self, message: str) -> None:
        if not self.is_attached:
            return
        self._body = Text(f"probe failed: {message}", style="bold red")
        self.query_one("#report", Static).update(self._body)

    # --- actions ------------------------------------------------------------

    def action_refresh(self) -> None:
        self._start_probe()

    def action_close(self) -> None:
        self.dismiss(None)

    def action_copy(self) -> None:
        if self._profile is None:
            self.app.notify("Nothing to copy yet: the probe has not finished", severity="warning")
            return
        # Exactly what the CLI prints, so a pasted report and a screenshot are the same evidence.
        self.app.copy_to_clipboard(host_profile.render_text(self._profile))
        self.app.notify("Host profile copied")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        {
            "btn-refresh": self.action_refresh,
            "btn-copy": self.action_copy,
            "btn-close": self.action_close,
        }[event.button.id]()
