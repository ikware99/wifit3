#!/usr/bin/env python3
"""Run the wifit3 design intent end to end and log every step to disk.

Why a dedicated runner: the intent being verified is "with no USB Wi-Fi card present, the
virtual channel carries the product path to a crackable hash". Proving that needs an ordered
chain (bus -> discovery -> bring-up -> air -> campaign -> hashline -> verdict), and a chain is
only debuggable if each link reports its own intent, expectation and observed value.

Every step writes one JSONL record and one readable block. Credentials are never logged: a
passphrase appears only as a SHA-256 fingerprint, so the log can be shared.

Usage:
    .venv/Scripts/python.exe scripts/verify_design_intent.py
    .venv/Scripts/python.exe scripts/verify_design_intent.py --psk-file .secrets/lab.psk
    .venv/Scripts/python.exe scripts/verify_design_intent.py \\
        --target "enhua:24:f6:03:27:76:cc:.secrets/enhua.psk" \\
        --target "Enhua_a:90:76:9f:ae:8d:e8:.secrets/enhua_a.psk"

The passphrase is never accepted on a command line: only a file path, stdin or a no-echo
prompt. A single device may carry its own file in the third field of ``--target``; when that
field is omitted the shared ``--psk-file`` value is used instead.
"""
from __future__ import annotations

import asyncio
import datetime
import argparse
import getpass
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wifit3.campaigns.pmkid import PmkidHarvestAttack                      # noqa: E402
from wifit3.chips.sim import SIM_PID, SIM_VID                            # noqa: E402
from wifit3.chips.sim.backend import reset_usb_backend, use_sim_backend   # noqa: E402
from wifit3.chips.sim.driver import SimulatedDriver                      # noqa: E402
from wifit3.crack.hc22000_format import parse_hc22000                    # noqa: E402
from wifit3.crack.wpa_psk import derive_pmk, pmkid as pmkid_of, psk_matches             # noqa: E402
from wifit3.device import manager                                        # noqa: E402
from wifit3.persist.save import save_pmkid                               # noqa: E402
from wifit3.wlan.array import WlanArray                                  # noqa: E402

PSK_AP = "02:00:5e:1a:00:01"
HASHCAT_VECTOR = ("WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4"
                  "*686173686361742d6573736964***")


REDACTED = "«已脱敏»"


class Redactor:
    """Scrubs secrets from every string on its way to a log.

    Defence in depth, not the primary control: the primary control is that a secret is never
    accepted on a command line and never written except as a fingerprint. This catches the case
    where a value ends up inside an exception message, a path, or a name by accident.

    Accepts several secrets because a multi-device run may hold one passphrase per network.
    Longer secrets are replaced first, so a short secret that happens to be a substring of a
    longer one cannot leave a tail behind.
    """

    def __init__(self, secrets: "str | Iterable[str] | None" = None) -> None:
        if isinstance(secrets, str):
            found = [secrets]
        else:
            found = [s for s in (secrets or []) if s]
        self._secrets = sorted(set(found), key=len, reverse=True)

    def __call__(self, text: str) -> str:
        if not self._secrets or not isinstance(text, str):
            return text
        out = text
        for secret in self._secrets:
            out = out.replace(secret, REDACTED)
            for variant in (secret.encode().hex(), secret.encode().hex().upper()):
                out = out.replace(variant, REDACTED)
        return out


def read_secret(args: argparse.Namespace) -> str | None:
    """Resolve the passphrase without ever putting it on a command line.

    Refusing an inline ``WIFIT3_PSK`` is deliberate: an environment variable set inline is
    visible in the shell history, in ``ps``/Task Manager while the process runs, and in any
    child process that dumps its environment. A file, stdin or a no-echo prompt does not.
    """
    if os.environ.get("WIFIT3_PSK"):
        raise SystemExit(
            "拒绝执行：检测到 WIFIT3_PSK 以明文环境变量传入。\n"
            "明文环境变量会进入 shell 历史与进程列表。请改用下列任一方式：\n"
            "  --psk-file <文件>     从文件读取（推荐，配合 chmod 600）\n"
            "  --psk-stdin           从标准输入读取（管道/heredoc）\n"
            "  --psk-prompt          交互式无回显输入\n"
            "  WIFIT3_PSK_FILE=<文件> 用环境变量只传路径")
    path = args.psk_file or os.environ.get("WIFIT3_PSK_FILE")
    if path:
        raw = Path(path).read_text(encoding="utf-8")
        return raw.strip() or None
    if args.psk_stdin:
        return sys.stdin.read().strip() or None
    if args.psk_prompt:
        return getpass.getpass("WPA 口令（不回显）：").strip() or None
    return None


def _display_width(text: str) -> int:
    """Terminal columns a string occupies. CJK glyphs are double width."""
    return sum(2 if ord(ch) > 0x2E80 else 1 for ch in text)


def render_bar(done: int, total: int, width: int = 22, unicode_ok: bool = True) -> str:
    """The filled portion of the bar. Pure, so its shape is easy to reason about."""
    total = max(total, 1)
    done = max(0, min(done, total))
    filled = int(round(done / total * width))
    full, empty = ("█", "░") if unicode_ok else ("#", "-")
    return full * filled + empty * (width - filled)


class ProgressBar:
    """A single line pinned under the log blocks, redrawn in place.

    Why it exists: the run prints one multi-line block per step, so without a persistent bar the
    operator sees only a growing wall of text and cannot tell how much is left. The bar is drawn
    after each block and blanked before the next one, which also keeps the on-disk log free of
    carriage returns: only ``_emit`` writes to the file, and it never calls the bar.
    """

    def __init__(self, stream, total: int, mode: str = "auto") -> None:
        self._stream = stream
        self.total = max(total, 0)
        self.mode = mode
        self._drawn = False
        self._t0 = time.perf_counter()
        is_tty = bool(getattr(stream, "isatty", lambda: False)())
        if mode == "none":
            self.enabled = False
        elif mode == "auto":
            self.enabled = is_tty
        else:
            self.enabled = True
        enc = (getattr(stream, "encoding", "") or "").lower().replace("-", "").replace("_", "")
        self._unicode = "utf8" in enc

    def _fit(self, text: str) -> str:
        cols = shutil.get_terminal_size(fallback=(110, 24)).columns
        limit = max(cols - 1, 20)
        if _display_width(text) <= limit:
            return text
        out, used = [], 0
        for ch in text:
            w = 2 if ord(ch) > 0x2E80 else 1
            if used + w > limit - 1:
                break
            out.append(ch)
            used += w
        return "".join(out) + "…"

    def draw(self, done: int, note: str = "") -> None:
        if not self.enabled:
            return
        total = max(self.total, 1)
        done = max(0, min(done, total))
        pct = done / total * 100
        elapsed = time.perf_counter() - self._t0
        if self.mode == "plain":
            line = f"进度 {pct:3.0f}%  {done}/{total}  {elapsed:5.1f}s"
        else:
            line = (f"{render_bar(done, total, 22, self._unicode)} "
                    f"{pct:3.0f}%  {done}/{total}  {elapsed:5.1f}s")
        if note:
            line += f"  {note}"
        self._stream.write("\r" + self._fit(line) + "\x1b[K")
        self._stream.flush()
        self._drawn = True

    def clear_line(self) -> None:
        """Blank the bar so the next block starts on a clean row."""
        if self.enabled and self._drawn:
            self._stream.write("\r\x1b[K")
            self._stream.flush()
            self._drawn = False

    def close(self) -> None:
        self.clear_line()
        self.enabled = False


class Recorder:
    """One JSONL record plus one readable block per step."""

    def __init__(self, log_dir: Path, redact: Redactor | None = None,
                 total: int = 0, progress: str = "auto") -> None:
        self._redact = redact or Redactor(None)
        stamp = datetime.datetime.now().strftime("%Y-%m-%d")
        log_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl = log_dir / f"{stamp}-设计意图验证.jsonl"
        self.text = log_dir / f"{stamp}-设计意图验证.log"
        self.jsonl.write_text("", encoding="utf-8", newline="\n")
        self.text.write_text("", encoding="utf-8", newline="\n")
        self.rows: list[dict] = []
        self.n = 0
        self._planned = total
        self._bar = ProgressBar(sys.stdout, total, progress)
        self._mark = time.perf_counter()

    def expect(self, total: int) -> None:
        """Declare how many steps the run intends to emit, so the bar can show a real total."""
        self._planned = total
        self._bar.total = total

    def mark(self) -> None:
        """Start timing the next step's work."""
        self._mark = time.perf_counter()

    def _emit(self, line: str) -> None:
        self._bar.clear_line()
        line = self._redact(line)
        print(line)
        with self.text.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")

    def tick(self, note: str) -> None:
        """Show what is being worked on right now, for steps slow enough to notice."""
        self._bar.draw(self.n, note)

    def head(self, title: str, subtitle: str) -> None:
        bar = "=" * 78
        self._emit(bar)
        self._emit(f"{title}")
        self._emit(f"{subtitle}")
        self._emit(bar)

    def step(self, title: str, intent: str, action: str, expected: str,
             actual: str, ok: bool, detail: str = "") -> bool:
        self.n += 1
        sid = f"S{self.n:02d}"
        elapsed_ms = (time.perf_counter() - self._mark) * 1000
        self._emit("")
        self._emit(f"[{sid}] {title}   ({elapsed_ms:.0f} ms)")
        self._emit(f"     意图  {intent}")
        self._emit(f"     动作  {action}")
        self._emit(f"     期望  {expected}")
        self._emit(f"     实测  {actual}")
        if detail:
            self._emit(f"     备注  {detail}")
        self._emit(f"     结论  {'PASS' if ok else 'FAIL'}")
        row = dict(ts=datetime.datetime.now().isoformat(timespec="seconds"), step=sid,
                   title=title, intent=intent, action=action, expected=expected,
                   actual=actual, ok=ok, detail=detail, elapsed_ms=round(elapsed_ms, 1),
                   progress=f"{self.n}/{self._planned or '?'}")
        row = {k: self._redact(v) if isinstance(v, str) else v for k, v in row.items()}
        self.rows.append(row)
        with self.jsonl.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        self._bar.draw(self.n, f"完成 {sid}")
        self._mark = time.perf_counter()
        return ok

    def summary(self, wall_s: float) -> bool:
        self._bar.close()
        passed = sum(1 for r in self.rows if r["ok"])
        consistent = not self._planned or self._planned == len(self.rows)
        bar = "=" * 78
        self._emit("")
        self._emit(bar)
        self._emit("效率统计")
        self._emit(bar)
        self._emit(f"  {'步骤':<6}{'耗时':>10}   标题")
        for r in sorted(self.rows, key=lambda x: -x["elapsed_ms"]):
            self._emit(f"  {r['step']:<6}{r['elapsed_ms']:>8.0f} ms   {r['title']}")
        self._emit("")
        step_s = sum(r["elapsed_ms"] for r in self.rows) / 1000
        self._emit(f"  步骤累计      {step_s:>8.2f} s")
        self._emit(f"  端到端墙钟    {wall_s:>8.2f} s")
        self._emit(f"  平均每步      {step_s / max(len(self.rows), 1) * 1000:>8.0f} ms")
        self._emit(f"  步骤数        {len(self.rows):>8d}  （PASS {passed} / FAIL {len(self.rows) - passed}）")
        if self._planned:
            verdict = "一致" if consistent else "不一致（进度条总数与实际步数不符）"
            self._emit(f"  进度计划      {len(self.rows)}/{self._planned}  {verdict}")
        self._emit("")
        self._emit(f"日志  {self.jsonl}")
        self._emit(f"      {self.text}")
        self._emit(bar)
        return passed == len(self.rows) and consistent


def ref_pmkid(psk: str, essid: bytes, aa: bytes, spa: bytes) -> str:
    """The algorithm restated independently, so a bug shared with wifit3 cannot pass."""
    pmk = hashlib.pbkdf2_hmac("sha1", psk.encode(), essid, 4096, 32)
    return hmac.new(pmk, b"PMK Name" + aa + spa, hashlib.sha1).digest()[:16].hex()


def fingerprint(secret: str) -> str:
    """A stable, non-reversible tag for a credential, safe to write to a log."""
    return hashlib.sha256(secret.encode()).hexdigest()[:12]


def read_target_secret(keyfile: str | None, shared: str | None) -> str | None:
    """Resolve one device's passphrase: its own file wins, otherwise the shared source.

    Only a path is ever passed on the command line, so a per-device secret stays out of
    ``sys.argv`` exactly like the shared one. A missing or unreadable file is a hard error
    rather than a silent fallback: silently using another network's passphrase would produce a
    green run that proves nothing.
    """
    if not keyfile:
        return shared
    path = Path(keyfile)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(
            f"读不到该设备的口令文件：{keyfile}（{exc.strerror or exc}）\n"
            f"  要么补上这个文件，要么省略 --target 的第三段以复用 --psk-file") from exc
    if os.name != "nt":
        wide = path.stat().st_mode & 0o077
        if wide:
            print(f"注意：{keyfile} 权限为 {path.stat().st_mode & 0o777:o}，"
                  f"建议 chmod 600（当前同组或其他用户可读）", file=sys.stderr)
    return raw.strip() or None


def scan_for_plaintext(paths: list[Path], secrets: Iterable[str],
                       extra: Iterable[str] = ()) -> tuple[bool, str]:
    """Read the finished logs back as bytes and look for any passphrase or derived secret.

    This is the assertion that makes the promise checkable: if a future edit starts logging a
    secret, the run fails instead of quietly writing it to disk. ``extra`` carries derived
    material that is just as sensitive as the passphrase: a PMKID plus its SSID/BSSID pair is
    an offline-crackable target, so leaving one in the log quietly weakens the network.
    """
    secrets = [s for s in secrets if s]
    extra = [e for e in extra if e]
    if not secrets and not extra:
        return True, "未提供口令，跳过扫描"
    needles: list[bytes] = []
    for secret in secrets:
        needles += [secret.encode(), secret.encode().hex().encode(),
                    secret.encode().hex().upper().encode()]
    for item in extra:
        needles += [item.encode(), item.upper().encode()]
    hits = [p.name for p in paths if p.exists() and any(n in p.read_bytes() for n in needles)]
    if hits:
        return False, f"命中明文：{hits}"
    return True, (f"扫描 {len(paths)} 个文件 x {len(secrets)} 份口令 + "
                  f"{len(extra)} 份派生值，明文与两种十六进制形式均未命中")


async def wait_for(pred, rounds: int = 80, step: float = 0.05) -> bool:
    for _ in range(rounds):
        if pred():
            return True
        await asyncio.sleep(step)
    return False


def mac_hex(text: str) -> str:
    """Normalise any MAC spelling (colons, dashes, dots) to 12 lowercase hex digits."""
    return re.sub(r"[^0-9A-Fa-f]", "", text or "").lower()


def system_wifi_state() -> dict[str, str]:
    """What the operating system itself says about the current association.

    This is the only anchor in the run that does not pass through wifit3, so it can catch a
    target whose SSID/BSSID pair was typed wrong. Without it, a typo would still produce a
    perfectly self-consistent PMKID for a network that does not exist.
    """
    if os.name != "nt":
        return {}
    try:
        raw = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                             capture_output=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    fields = {"SSID": "ssid", "BSSID": "bssid", "信号": "signal", "Signal": "signal",
              "状态": "state", "State": "state", "身份验证": "auth", "Authentication": "auth",
              "加密": "cipher", "密码": "cipher", "Cipher": "cipher",
              "信道": "channel", "Channel": "channel"}
    out: dict[str, str] = {}
    for line in raw.decode("gbk", errors="replace").splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        field = fields.get(key.strip())
        if field and field not in out:
            out[field] = value.strip()
    return out


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="验证 wifit3 设计意图；口令永不出现在命令行上。",
        epilog="口令只会以 SHA-256 指纹写入日志，明文既不落盘也不回显。")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--psk-file", metavar="PATH", help="从文件读取 WPA 口令（推荐）")
    src.add_argument("--psk-stdin", action="store_true", help="从标准输入读取")
    src.add_argument("--psk-prompt", action="store_true", help="交互式无回显输入")
    ap.add_argument("--fingerprint", action="store_true",
                    help="只打印口令指纹后退出，用于自行核对，不必把口令发出去")
    ap.add_argument("--target", action="append", metavar="SSID:BSSID[:PSKFILE]",
                    help="真实设备，可重复。第三段是该设备自己的口令文件路径，"
                         "省略时回退到 --psk-file 提供的口令")
    ap.add_argument("--progress", choices=("auto", "bar", "plain", "none"), default="auto",
                    help="进度显示：auto 在终端画进度条、重定向时关闭（默认）；"
                         "bar 强制画条；plain 只输出百分比行；none 关闭")
    return ap.parse_args(argv)


_MAC_RE = r"[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}"
_TARGET_RE = re.compile(rf"^(?P<ssid>.+?):(?P<bssid>{_MAC_RE})(?::(?P<keyfile>.+))?$")


def parse_targets(args: argparse.Namespace) -> list[tuple[str, str, str | None]]:
    """Split ``SSID:BSSID[:PSKFILE]`` records. Only a path travels here, never the secret."""
    out: list[tuple[str, str, str | None]] = []
    for raw in (args.target or []):
        m = _TARGET_RE.match(raw.strip())
        if not m:
            raise SystemExit(
                f"--target 格式应为 SSID:BSSID[:PSKFILE]，收到 {raw!r}\n"
                f"  BSSID 必须是 6 组十六进制，例如 24:f6:03:27:76:cc")
        ssid = m.group("ssid")
        bssid = m.group("bssid")
        if not ssid or ssid.startswith(":"):
            raise SystemExit(f"--target 缺少 SSID：{raw!r}")
        out.append((ssid, bssid, m.group("keyfile") or None))
    return out


async def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    shared = read_secret(args)
    targets = parse_targets(args)
    per_target: list[tuple[str, str, str | None]] = [
        (ssid, bssid, read_target_secret(keyfile, shared)) for ssid, bssid, keyfile in targets
    ]
    secrets = [s for _, _, s in per_target if s]
    if shared and shared not in secrets:
        secrets.append(shared)

    if args.fingerprint:
        if not secrets:
            print("需要先提供口令（--psk-file / --psk-stdin / --psk-prompt）", file=sys.stderr)
            return 2
        for ssid, bssid, psk in per_target:
            if psk:
                print(f"{ssid} @ {bssid}  口令指纹 sha256[:12] = {fingerprint(psk)}")
        if shared and not per_target:
            print(f"共用口令  指纹 sha256[:12] = {fingerprint(shared)}")
        return 0

    wall_start = time.perf_counter()
    # PMKIDs derived from a real network's passphrase are as sensitive as the passphrase: each
    # one is a ready-made offline-crackable target. They are collected here only so the closing
    # leak scan can assert that none of them reached the disk.
    derived_pmkids: list[str] = []
    # Ten fixed steps, one reconciliation per device, one cross-check against the host's own
    # association, one leak scan. The summary re-checks this number against what was emitted,
    # so a step added without updating it turns the run red rather than lying in the bar.
    planned = 10 + len(per_target) + (1 if per_target else 0) + 1
    rec = Recorder(ROOT / "logs", Redactor(secrets), total=planned, progress=args.progress)
    rec.head("wifit3 设计意图端到端验证",
             "无 USB Wi-Fi 卡前提下，靠虚拟通道把产品链路跑到可破解的 hash 行")
    rec.tick("准备开始")

    # -- S01 -----------------------------------------------------------------
    rec.tick("S01 枚举真实 USB 总线")
    rec.mark()
    real = manager.devices()
    rec.step(
        "硬件前提：本机是否存在受支持的 USB 网卡",
        "先钉死前提。若无卡，则后续所有结果只能来自虚拟通道，而不是偷偷用了真硬件。",
        "manager.devices()（真实 libusb 后端，未注入任何替身）",
        "0 张受支持的卡",
        f"{len(real)} 张" + (f" -> {[(f'{d.vid:04x}:{d.pid:04x}') for d in real]}" if real else ""),
        len(real) == 0,
        "Intel 9462 为 CNVi 架构，USB 上只有蓝牙 8087:0aaa，不构成 Wi-Fi 功能",
    )

    # -- S02 -----------------------------------------------------------------
    use_sim_backend()
    iface = None
    try:
        rec.mark()
        sims = manager.devices()
        sim = next((d for d in sims if (d.vid, d.pid) == (SIM_VID, SIM_PID)), None)
        rec.step(
            "虚拟通道建立：官方后端钩子是否生效",
            "验证用的是 device/backend.py 公开的工厂钩子，不是改 Driver 抽象基类、不是改 manager。",
            "use_sim_backend() 后再次 manager.devices()",
            "发现 1 张合成卡 5e1a:0001",
            f"{len(sims)} 张，命中合成卡：{sim is not None}",
            sim is not None,
            "这条通路决定了上游合并时不会与 chips/ 的移植规则冲突",
        )

        # -- S03 -------------------------------------------------------------
        rec.mark()
        iface = manager.wlan_iface(sim, name="wlan9")
        ok3 = iface is not None and isinstance(iface.driver, SimulatedDriver)
        rec.step(
            "产品化 bring-up：发现层到驱动层的契约",
            "确认发现层能独立构造出可用的 WlanInterface，而不是测试里手工 new 出来的。",
            "manager.wlan_iface(sim, name='wlan9')",
            "WlanInterface + SimulatedDriver",
            f"{type(iface).__name__ if iface else None} + "
            f"{type(iface.driver).__name__ if iface else None}",
            ok3,
            "此前所有 sim 测试都绕过 manager 手工拼装，这一条才真正覆盖产品路径",
        )
        if not ok3:
            raise RuntimeError("bring-up 失败，后续步骤无意义")

        await iface.connect()
        array = WlanArray()
        array.attach(iface)
        await iface.set_channel(6)

        # -- S04 -------------------------------------------------------------
        rec.mark()
        got_ap = await wait_for(lambda: array.access_points.get(PSK_AP) is not None)
        ap = array.access_points.get(PSK_AP)
        rec.step(
            "空口到 sink：信标解析与状态折叠",
            "验证虚拟射频发出的信标经真实 parser 与 WlanSink 折叠成 AP 条目。",
            "connect() 后监听 RX 通道，等待 access_points 出现目标 BSSID",
            "AP sim-lab-2g / ch6 / WPA2-PSK-CCMP",
            f"{ap.ssid} / ch{ap.channel} / {ap.encryption}" if ap else "未出现",
            got_ap and ap is not None and ap.encryption == "WPA2-PSK-CCMP",
            "加密类型由 RSN IE 解析得出，不是硬编码",
        )

        # -- S05 -------------------------------------------------------------
        rec.tick("S05 等待 M1（最长 1.5s）")
        rec.mark()
        attack = PmkidHarvestAttack(array, ap, attempts=2, m1_timeout=1.5)
        attack.run()
        await wait_for(lambda: attack.done)
        await attack.stop()
        rec.step(
            "campaign 采集：不改一行代码即可用",
            "campaign 是产品真正的执行单元。它若能跑，说明虚拟驱动满足它对驱动的全部契约。",
            "PmkidHarvestAttack(array, ap).run() 并等待终态",
            "done=True, fail_reason=None, 拿到 PMKID",
            f"done={attack.done}, fail_reason={attack.fail_reason}, "
            f"pmkid={attack.pmkid.hex() if attack.pmkid else None}",
            attack.done and attack.fail_reason is None and attack.pmkid is not None,
            f"使用的客户端 MAC {attack.client_mac}",
        )

        # -- S06 -------------------------------------------------------------
        rec.mark()
        result = save_pmkid(ap, attack.client_mac)
        # The capture file accumulates one record per harvested PMKID, so the record this run
        # produced is the last line, not the whole file.
        blob = Path(result.path).read_text(encoding="utf-8") if result else ""
        records = [ln.strip() for ln in blob.splitlines() if ln.strip()]
        raw = records[-1] if records else ""
        line = parse_hc22000(raw) if raw else None
        rec.step(
            "落盘与格式：生成 hashcat 22000 记录",
            "采集结果必须落成工具链能直接吃的格式，否则前面的采集没有出口。",
            "save_pmkid() 写出文件后 parse_hc22000() 回读",
            "kind=01 的 PMKID 记录，可被解析器接受",
            f"{result.path.name if result else None} -> kind={line.kind if line else None}",
            line is not None and line.kind == "01",
            f"文件累计 {len(records)} 条；本条 {raw}",
        )

        # -- S07 -------------------------------------------------------------
        rec.mark()
        radio_ap = next(a for a in iface.driver.radio.aps if a.bssid.lower() == PSK_AP)
        expected = ref_pmkid(radio_ap.psk, b"sim-lab-2g",
                             bytes.fromhex(PSK_AP.replace(":", "")),
                             bytes.fromhex(attack.client_mac.replace(":", "")))
        rec.step(
            "独立对账：实测值 vs 按规范另算的值",
            "这一步是核心。用不经 wifit3 任何辅助函数的独立实现算期望值，避免自己验自己。",
            "hashlib.pbkdf2_hmac + hmac(PMK Name||AP||STA) 独立计算后比对落盘值",
            expected,
            line.pmkid_or_mic if line else None,
            line is not None and line.pmkid_or_mic == expected,
            "两侧共享的只有算法定义，没有代码",
        )

        # -- S08 -------------------------------------------------------------
        rec.mark()
        pos = psk_matches(radio_ap.psk, line) if line else False
        neg = psk_matches("definitely-not-the-passphrase", line) if line else True
        rec.step(
            "判定正反向：防止恒真",
            "只测「对的判真」不够，实现若恒返回 True 也会绿。必须同时验证错口令判假。",
            "psk_matches(正确口令) 与 psk_matches(错误口令)",
            "前者 True，后者 False",
            f"正确={pos}, 错误={neg}",
            pos is True and neg is False,
        )

        # -- S09 -------------------------------------------------------------
        rec.mark()
        vec = parse_hc22000(HASHCAT_VECTOR)
        ours = ref_pmkid("hashcat!", bytes.fromhex(vec.essid),
                         bytes.fromhex(vec.mac_ap), bytes.fromhex(vec.mac_sta))
        rec.step(
            "外部锚点：与 hashcat 公布向量对账",
            "自证只能证明内部一致。用 hashcat wiki 公布的 22000 示例做外部锚点，才是真的算法一致。",
            "独立实现复算 hashcat 示例（口令 hashcat!，SSID hashcat-essid）",
            "4d4fe7aac3a2cecab195321ceb99a7d0",
            ours,
            ours == "4d4fe7aac3a2cecab195321ceb99a7d0" and psk_matches("hashcat!", vec) is True,
        )

        # -- S10 -------------------------------------------------------------
        rec.mark()
        client = "02:11:22:33:44:66"
        iface.driver.radio.add_station(client)
        res = await iface.deauth_client(PSK_AP, client, rounds=2)
        rec.step(
            "链路 ACK：本轮修复点回归",
            "虚拟射频此前不回应 deauth 的链路层 ACK，导致 campaign 恒判「双方静默」。验证已修好。",
            "deauth_client() 打 2 轮，读两方向的 ACK 计数",
            "measured=True 且两侧 acks 均为 2",
            f"measured={res.measured}, client {res.client_acks}/{res.client_sent}, "
            f"ap {res.ap_acks}/{res.ap_sent}",
            res.measured and res.client_acks == 2 and res.ap_acks == 2,
        )

        # -- S11..S11+n：逐台真实设备对账 -----------------------------------
        # 每台设备一个独立步骤，而不是合成一步：任何一台失败都必须单独可见，
        # 否则「两台都跑了」与「只跑通一台」在日志里长得一样。
        client_hex = bytes.fromhex(attack.client_mac.replace(":", ""))
        for idx, (ssid, bssid, psk) in enumerate(per_target, 1):
            rec.mark()
            title = f"真实设备对账 {idx}/{len(per_target)}：{ssid} @ {bssid}"
            if not psk:
                rec.step(
                    title,
                    "把同一派生链路换成该设备的真实 SSID/BSSID 跑一遍，确认参数变化不改变正确性。",
                    "读取 --target 第三段指定的该设备口令文件",
                    "提供口令后做派生对账",
                    "未提供口令文件，本步未执行",
                    False,
                    "口令缺失时不做任何猜测性派生，宁可这一步红着",
                )
                continue
            essid = ssid.encode()
            aa = bytes.fromhex(mac_hex(bssid))
            derived = pmkid_of(derive_pmk(psk, essid), aa, client_hex).hex()
            independent = ref_pmkid(psk, essid, aa, client_hex)
            derived_pmkids.append(derived)
            if derived == independent:
                actual = f"两侧一致（PMKID 已隐去）；口令指纹 {fingerprint(psk)}"
                detail = ("PMKID 与该网络的 SSID/BSSID 一起就是一份可直接离线爆破的 hash，"
                          "故不入日志；只留指纹用于事后核对用的是哪份口令")
            else:
                actual = (f"不一致：wifit3 {derived[:8]}… / 独立 {independent[:8]}…；"
                          f"口令指纹 {fingerprint(psk)}")
                detail = "只打印前 8 位用于定位，完整值不入日志"
            rec.step(
                title,
                "把同一派生链路换成该设备的真实 SSID/BSSID 跑一遍，确认参数变化不改变正确性。"
                "两侧共享的只有算法定义，实现是各写各的。",
                f"derive_pmk(口令, '{ssid}') + pmkid(PMK, {bssid}, {attack.client_mac})",
                "wifit3 派生 == 独立实现派生",
                actual,
                derived == independent,
                detail,
            )

        # -- S12：与操作系统实时状态交叉核对 ---------------------------------
        if per_target:
            rec.mark()
            state = system_wifi_state()
            live_bssid = mac_hex(state.get("bssid", ""))
            live_ssid = state.get("ssid", "")
            clashes = [f"{ssid} != 系统 {live_ssid}"
                       for ssid, bssid, _ in per_target
                       if live_bssid and mac_hex(bssid) == live_bssid and ssid != live_ssid]
            matched = [ssid for ssid, bssid, _ in per_target
                       if live_bssid and mac_hex(bssid) == live_bssid]
            if not live_bssid:
                actual = "本机当前未关联任何网络，无外部状态可对照"
                note = "无冲突可言，本步不提供信息量"
            else:
                actual = (f"系统当前关联 {live_ssid} @ {state.get('bssid')}"
                          f"（{state.get('auth', '?')} / {state.get('cipher', '?')}，"
                          f"信道 {state.get('channel', '?')}），命中 {len(matched)} 个目标")
                note = ("声明的 SSID 与系统一致" if not clashes
                        else "；".join(clashes))
            rec.step(
                "目标参数自检：与操作系统实时关联状态对账",
                "参数若填错，前面所有对账都在验证一个不存在的目标，而且照样自洽。"
                "本步用不经 wifit3 的系统状态做外部锚点。",
                "netsh wlan show interfaces 读出当前关联，与 --target 声明的 SSID/BSSID 比对",
                "凡本机正关联的 BSSID，其声明 SSID 必须与系统一致",
                actual,
                not clashes,
                note,
            )
    finally:
        if iface is not None:
            await iface.close()
        reset_usb_backend()

    rec.mark()
    ok_scan, scan_detail = scan_for_plaintext([rec.jsonl, rec.text], secrets, derived_pmkids)
    rec.step(
        "密钥不落地：回读日志确认无明文",
        "把承诺变成可执行断言。若将来有人把口令写进日志，这一步会失败而不是悄悄写盘。",
        "以字节形式回读 JSONL 与 .log，扫描口令明文、两种十六进制形式，以及真实网络派生出的 PMKID",
        "两处日志均不含任何一份口令，也不含真实网络的 PMKID",
        scan_detail,
        ok_scan,
        "" if ok_scan else "已删除日志，避免明文继续留存",
    )
    if not ok_scan:
        for path in (rec.jsonl, rec.text):
            path.write_bytes(b"")
    return 0 if rec.summary(time.perf_counter() - wall_start) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(sys.argv[1:])))
