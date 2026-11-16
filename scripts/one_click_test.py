#!/usr/bin/env python3
"""One command that answers "is this repository deliverable right now".

A complete check is four phases: environment, static analysis, regression tests, and the design
intent chain. Run by hand that is four commands to remember, and a phase someone forgets looks
exactly like a phase that passed. This script runs them in order, prints which one is in flight
with a running percentage, and ends with one verdict plus a single log file worth handing over.

Per-device credentials are read from ``.secrets/targets.txt`` (one ``SSID:BSSID:PSKFILE`` per
line), or typed at a prompt with ``--ask-targets``. Only file paths ever reach a command line,
and the path itself is masked in the printed command, so a passphrase cannot end up in the log
or the shell history.

Exit codes follow ``verify_design_intent.py``: ``0`` every phase passed, ``3`` nothing failed
but at least one check was suspended (see ``--debug-plaintext``), ``1`` something failed.

Usage:
    .venv/Scripts/python.exe scripts/one_click_test.py
    .venv/Scripts/python.exe scripts/one_click_test.py --fast
    .venv/Scripts/python.exe scripts/one_click_test.py --include-slow --no-verify
    .venv/Scripts/python.exe scripts/one_click_test.py --ask-targets
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts" / "verify_design_intent.py"
TARGETS_FILE = ROOT / ".secrets" / "targets.txt"
# A healthy table is ~58k prefixes. The floor is deliberately loose: it is here to catch a
# truncated or dropped table, not to fail whenever Wireshark's feed shifts by a few hundred.
MIN_OUI_ENTRIES = 40000


def _encodable(text: str) -> bool:
    """Can the current stdout carry this glyph?

    A Windows console redirected to a file, or one whose code page is 936, cannot represent
    U+2591: printing it raises UnicodeEncodeError and kills a run that was otherwise finished.
    The bar is decoration, so it degrades to ASCII instead of taking the whole report down.
    """
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        text.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


BAR_FULL, BAR_EMPTY = ("█", "░") if _encodable("█") and _encodable("░") else ("#", "-")

# Mirrors verify_design_intent.py: a phase can pass while containing a suspended check, and a
# wrapper that reported that as a plain pass would be repeating a claim nobody verified.
EXIT_SUSPENDED = 3
DEFAULT_DEBUG_PLAINTEXT = "logout.txt"

# The subset that covers everything this branch touched, for a check that finishes while you
# wait. It is a convenience, never the release gate: a green --fast run proves less than a full
# run and the summary says so out loud.
FAST_PATHS = [
    "tests/test_style.py",
    "tests/test_host_profile.py",
    "tests/test_verify_design_intent.py",
    "tests/test_wireless_capabilities.py",
    "tests/chips/sim",
    "tests/wlan",
    "tests/device",
]

_TARGET_RE = re.compile(r"^(.+?):([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?::(.+))?$")


def venv_python() -> Path:
    """Prefer the project interpreter, fall back to whatever is running this script."""
    for candidate in (ROOT / ".venv" / "Scripts" / "python.exe",
                      ROOT / ".venv" / "bin" / "python"):
        if candidate.exists():
            return candidate
    return Path(sys.executable)


def hide_keyfile(arg: str) -> str:
    """Mask the passphrase-file field of a target so the printed command stays shareable."""
    m = _TARGET_RE.match(arg)
    if m and m.group(3):
        return f"{m.group(1)}:{m.group(2)}:<口令文件已隐去>"
    return arg


def hide_cmd(cmd: list[str]) -> str:
    """Render a command line for the log with any credential path masked."""
    return " ".join(f'"{hide_keyfile(c)}"' if " " in c else hide_keyfile(c) for c in cmd)


def load_targets() -> list[str]:
    """Read the per-device list. A missing file means "no devices configured", not an error."""
    if not TARGETS_FILE.exists():
        return []
    out = []
    for raw in TARGETS_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def find_build_artifact() -> Path | None:
    """Locate a PyInstaller output, if one was ever built.

    A packaged binary is a separate product from the source tree: it resolves drivers by a
    pkgutil walk that PyInstaller cannot see statically, so it can ship with zero drivers and
    still exit cleanly. ``--smoke`` renders headless and returns, which is exactly the check that
    catches that class of packaging break.
    """
    for name in ("wifit3.exe", "wifit3"):
        candidate = ROOT / "dist" / name
        if candidate.exists():
            return candidate
    return None


def bar(done: int, total: int, width: int = 22) -> str:
    total = max(total, 1)
    filled = int(round(max(0, min(done, total)) / total * width))
    return BAR_FULL * filled + BAR_EMPTY * (width - filled)


def _width(text: str) -> int:
    """Terminal columns a string occupies. CJK glyphs are double width."""
    return sum(2 if ord(ch) > 0x2E80 else 1 for ch in text)


def _pad(text: str, width: int, right: bool = False) -> str:
    """Pad to a display width, not a character count, or CJK headers drift out of column."""
    gap = max(0, width - _width(text))
    return (" " * gap + text) if right else (text + " " * gap)


class Run:
    """Prints every line, tees it to disk, and keeps one row per phase."""

    def __init__(self, log_path: Path, total: int) -> None:
        self.log_path = log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("", encoding="utf-8", newline="\n")
        self.total = total
        self.rows: list[dict] = []
        # Phases that passed but contain a check nobody executed. Kept separate from rows so the
        # summary can say so out loud instead of letting a PASS cell carry the whole story.
        self.paused: list[str] = []
        self._t0 = time.perf_counter()

    def emit(self, line: str = "") -> None:
        print(line)
        with self.log_path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")

    def head(self, title: str) -> None:
        rule = "=" * 78
        self.emit(rule)
        self.emit(title)
        self.emit(rule)

    def start(self, idx: int, name: str) -> float:
        self.emit("")
        self.emit(f"--- {name} " + "-" * max(0, 60 - len(name)))
        return time.perf_counter()

    def end(self, idx: int, name: str, started: float, ok: bool, note: str = "",
            suspended: bool = False) -> bool:
        took = time.perf_counter() - started
        pct = idx / max(self.total, 1) * 100
        mark = "PASS" if ok else "FAIL"
        if ok and suspended:
            mark = "PASS*"
            self.paused.append(name)
        self.emit("")
        self.emit(f"[{idx}/{self.total}] {bar(idx, self.total)} {pct:3.0f}%  "
                  f"{name}  {mark}  {took:.1f}s"
                  + (f"  {note}" if note else ""))
        self.rows.append(dict(phase=name, ok=ok, seconds=round(took, 1), note=note,
                              suspended=suspended))
        return ok

    def run_stream(self, cmd: list[str], env: dict[str, str]) -> tuple[int, str]:
        """Run a child process, echoing its output as it arrives, and return (rc, tail)."""
        self.emit(f"  $ {hide_cmd(cmd)}")
        proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                errors="replace", bufsize=1, env=env)
        tail: list[str] = []
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip("\r\n")
            self.emit(line)
            tail.append(line)
            del tail[:-40]
        return proc.wait(), "\n".join(tail)

    def summary(self, wall_s: float, fast: bool) -> bool:
        rule = "=" * 78
        self.emit("")
        self.emit(rule)
        self.emit("一键测试汇总")
        self.emit(rule)
        self.emit(f"  {_pad('#', 4)}{_pad('阶段', 26)}{_pad('结果', 6)}"
                  f"{_pad('耗时', 9, right=True)}   说明")
        for i, row in enumerate(self.rows, 1):
            mark = "PASS*" if (row["ok"] and row.get("suspended")) else (
                "PASS" if row["ok"] else "FAIL")
            cost = f"{row['seconds']:.1f}s"
            self.emit(f"  {_pad(str(i), 4)}{_pad(row['phase'], 26)}{_pad(mark, 6)}"
                      f"{_pad(cost, 9, right=True)}   {row['note']}")
        self.emit("-" * 78)
        ok = all(row["ok"] for row in self.rows)
        self.emit(f"  {_pad('', 4)}{_pad('总计', 26)}{_pad('PASS' if ok else 'FAIL', 6)}"
                  f"{_pad(f'{wall_s:.1f}s', 9, right=True)}")
        if self.paused:
            self.emit("")
            self.emit(f"  * 暂停：{'、'.join(self.paused)} 里有断言按当前开关没有执行，"
                      f"既不算通过也不算失败。")
            self.emit("    本轮结论不是「干净通过」，退出码 3。关闭调试开关后才是完整门禁。")
        if fast:
            self.emit("")
            self.emit("  注意：本次为 --fast 子集，不能作为发布门禁结论；"
                      "发布前请去掉 --fast 跑一次全量。")
        self.emit("")
        self.emit(f"  日志  {self.log_path}")
        self.emit(rule)
        return ok


def env_check(py: Path) -> tuple[bool, str]:
    """Fail loudly on the cheap mistakes, so a later phase failure is not misread as a code bug."""
    problems: list[str] = []
    if sys.version_info < (3, 11):
        problems.append(f"Python {sys.version.split()[0]} < 3.11")
    for mod in ("pytest", "ruff"):
        probe = subprocess.run([str(py), "-m", mod, "--version"],
                               capture_output=True, text=True)
        if probe.returncode != 0:
            problems.append(f"{mod} 不可用")
    if not (ROOT / "src" / "wifit3").is_dir():
        problems.append("src/wifit3 不存在（工作目录不对？）")
    return (not problems), ("一切就绪" if not problems else "；".join(problems))


def git_snapshot(py: Path) -> str:
    """Record what exactly was tested. A verdict without a commit id cannot be reproduced."""
    def run(*args: str) -> str:
        try:
            out = subprocess.run(["git", *args], cwd=str(ROOT), capture_output=True,
                                 text=True, timeout=15)
            return out.stdout.strip() if out.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            return ""

    branch = run("rev-parse", "--abbrev-ref", "HEAD")
    head = run("rev-parse", "--short", "HEAD")
    dirty = run("status", "--porcelain")
    dirty_note = f"+{len(dirty.splitlines())} 处未提交改动" if dirty else "工作树干净"
    return f"{branch or '?'} @ {head or '?'}（{dirty_note}）"


def read_verify_counts(stamp: str) -> tuple[int, int, int]:
    """Count the verification steps that passed, the total, and how many were suspended.

    Read from the JSONL rather than the exit code so the note can carry numbers: "14/15 通过，
    1 暂停" says more than "rc=3", and a reader who only skims the summary still learns that
    something was switched off.
    """
    path = ROOT / "logs" / f"{stamp}-设计意图验证.jsonl"
    if not path.exists():
        return 0, 0, 0
    ok = total = suspended = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        total += 1
        # A missing key counts as not-passed; only an explicit null means "suspended", which is
        # what verify_design_intent.py writes for a check the run itself switched off.
        outcome = row.get("ok", False)
        if outcome is True:
            ok += 1
        elif outcome is None:
            suspended += 1
    return ok, total, suspended


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="一键跑完环境自检、静态检查、回归测试与设计意图验证，给出单一结论。",
        epilog="口令只经文件路径传递，命令行与日志中均不出现明文。")
    ap.add_argument("--fast", action="store_true",
                    help="只跑本轮改动涉及的核心子集，耗时约 10 秒；不能作发布门禁")
    ap.add_argument("--include-slow", action="store_true",
                    help="连 @pytest.mark.slow 一起跑（默认按 pyproject 排除）")
    ap.add_argument("--no-lint", action="store_true", help="跳过静态检查")
    ap.add_argument("--no-tests", action="store_true", help="跳过回归测试")
    ap.add_argument("--no-verify", action="store_true", help="跳过设计意图验证")
    ap.add_argument("--no-smoke", action="store_true",
                    help="跳过打包产物自检（默认在 dist/ 存在产物时自动执行）")
    ap.add_argument("--progress", choices=("plain", "bar", "none"), default="plain",
                    help="设计意图验证阶段的进度显示方式（默认 plain，适合被本脚本接管输出）")
    ap.add_argument("--ask-targets", action="store_true",
                    help="在验证阶段交互式输入 SSID/BSSID（口令仍只从文件路径取），"
                         "不必维护 .secrets/targets.txt")
    ap.add_argument("--debug-plaintext", nargs="?", const=DEFAULT_DEBUG_PLAINTEXT,
                    metavar="PATH",
                    help="调试开关，透传给验证阶段：把口令明文与 PMKID 写到 PATH"
                         f"（默认 ./{DEFAULT_DEBUG_PLAINTEXT}）。打开后本轮不再是干净通过")
    return ap.parse_args(argv)


def harden_stdout() -> None:
    """Never die on an unencodable glyph.

    A stray box character or a redaction mark should not turn a completed test run into a
    traceback: degraded output beats no output. The bar itself degrades gracefully above, so
    this is the safety net for everything else that gets printed.
    """
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is None:
        return
    try:
        reconfigure(errors="replace")
    except (ValueError, OSError):
        pass


def main(argv: list[str] | None = None) -> int:
    harden_stdout()
    args = parse_args(argv)
    py = venv_python()
    stamp = datetime.datetime.now().strftime("%Y-%m-%d")
    artifact = None if args.no_smoke else find_build_artifact()
    total = 2 + (0 if args.no_lint else 1) + (0 if args.no_tests else 1) \
        + (0 if args.no_verify else 1) + (1 if artifact else 0)
    run = Run(ROOT / "logs" / f"{stamp}-一键测试.log", total)
    wall = time.perf_counter()

    run.head("wifit3 一键测试")
    run.emit(f"  解释器  {py}")
    run.emit(f"  代码状态  {git_snapshot(py)}")
    run.emit(f"  打包产物  {artifact if artifact else '未发现（dist/ 下无 wifit3）'}")
    run.emit(f"  时间  {datetime.datetime.now().isoformat(timespec='seconds')}")

    child_env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
    idx = 0

    idx += 1
    t = run.start(idx, "环境自检")
    ok, note = env_check(py)
    run.end(idx, "环境自检", t, ok, note)
    if not ok:
        run.summary(time.perf_counter() - wall, args.fast)
        return 1

    if not args.no_lint:
        idx += 1
        t = run.start(idx, "静态检查（ruff）")
        rc, _ = run.run_stream([str(py), "-m", "ruff", "check", "src", "tests"], child_env)
        run.end(idx, "静态检查（ruff）", t, rc == 0,
                "全部通过" if rc == 0 else f"ruff 退出码 {rc}")

    idx += 1
    t = run.start(idx, "指纹库自检")
    # Probes the table directly instead of calling local_fingerprint.py: the full `stats` command
    # walks all 58k prefixes to build its human-facing report, which costs ~14 s here, and this
    # phase only needs to know the table is present and complete.
    probe = ("import sys; sys.path.insert(0, 'src'); "
             "from wifit3.id import VENDOR_BY_OUI as v; "
             "print('OUI_ENTRIES=%d' % len(v))")
    rc, out = run.run_stream([str(py), "-c", probe], child_env)
    match = re.search(r"OUI_ENTRIES=(\d+)", out)
    oui_count = int(match.group(1)) if match else 0
    fp_ok = rc == 0 and oui_count >= MIN_OUI_ENTRIES
    run.end(idx, "指纹库自检", t, fp_ok,
            f"{oui_count} 条 OUI"
            + ("" if fp_ok else f"（低于 {MIN_OUI_ENTRIES}，生成的表可能被截断或未被打包收录）"))

    if not args.no_tests:
        idx += 1
        t = run.start(idx, "回归测试（pytest）")
        cmd = [str(py), "-m", "pytest", "--tb=short", "-p", "no:cacheprovider"]
        if args.include_slow:
            cmd += ["-m", "slow or not slow"]
        if args.fast:
            cmd += FAST_PATHS
        rc, tail = run.run_stream(cmd, child_env)
        last = next((ln for ln in reversed(tail.splitlines())
                     if " passed" in ln or " failed" in ln or " error" in ln), "")
        run.end(idx, "回归测试（pytest）", t, rc == 0,
                (last.strip("= ")[:70] or f"pytest 退出码 {rc}"))

    if not args.no_verify:
        idx += 1
        t = run.start(idx, "设计意图验证")
        targets = load_targets()
        if not targets and not args.ask_targets:
            run.emit(f"  未发现 {TARGETS_FILE.relative_to(ROOT)}，跳过设备对账阶段。")
            run.emit("  建立该文件即可启用：每行写 SSID:BSSID:口令文件路径")
            run.emit("  或者加 --ask-targets，直接在这里输入 SSID/BSSID。")
            run.end(idx, "设计意图验证", t, True, "无设备配置，仅未执行")
        else:
            if targets:
                run.emit(f"  设备 {len(targets)} 台（口令文件路径在输出中已隐藏）")
            else:
                run.emit("  未配置目标文件，改为交互输入 SSID/BSSID。")
            cmd = [str(py), str(VERIFY), "--progress", args.progress]
            for target in targets:
                cmd += ["--target", target]
            if args.ask_targets:
                cmd += ["--ask-targets"]
            if args.debug_plaintext:
                cmd += ["--debug-plaintext", args.debug_plaintext]
                run.emit(f"  调试开关已打开：明文写入 {args.debug_plaintext}，"
                         f"本轮不会判定为干净通过。")
            rc, _ = run.run_stream(cmd, child_env)
            ok2, total2, susp2 = read_verify_counts(stamp)
            note = f"{ok2}/{total2} 步通过" + (f"，{susp2} 步暂停" if susp2 else "")
            # 3 is "nothing failed, one check switched off" rather than "something broke", so it
            # keeps the phase green while still reaching the final exit code.
            run.end(idx, "设计意图验证", t, rc in (0, EXIT_SUSPENDED), note,
                    suspended=rc == EXIT_SUSPENDED or susp2 > 0)

    if artifact is not None:
        idx += 1
        t = run.start(idx, "打包产物自检")
        run.emit(f"  $ \"{artifact}\" --smoke")
        try:
            probe = subprocess.run([str(artifact), "--smoke"], cwd=str(ROOT),
                                   capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", timeout=180)
            rc = probe.returncode
            tail = ((probe.stdout or "") + (probe.stderr or "")).strip().splitlines()[-12:]
        except subprocess.TimeoutExpired:
            rc, tail = 124, ["超时 180s 未退出"]
        except OSError as exc:
            rc, tail = 126, [f"无法执行：{exc}"]
        for line in tail:
            run.emit("  " + line)
        run.end(idx, "打包产物自检", t, rc == 0,
                f"{artifact.name} --smoke 退出码 {rc}")

    clean = run.summary(time.perf_counter() - wall, args.fast)
    if not clean:
        return 1
    return EXIT_SUSPENDED if run.paused else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
