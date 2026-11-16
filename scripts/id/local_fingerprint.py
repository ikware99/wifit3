#!/usr/bin/env python3
"""Unlock the fingerprint data that ships inside wifit3, offline and without a radio.

Why a separate script: ``id/vendors.py`` is a 2 MB generated table and the brand rules are a
private tuple inside ``id/client.py``. Both ship as code, so today the only ways to read them are
to start the TUI and hover a device, or to poke at them in a REPL. Neither answers the questions
an operator actually asks: how big is the library, what does this MAC resolve to, which OUIs do
our own captures use that the library has never heard of.

Everything here reads local module data. Nothing transmits, opens a socket, or touches a device.

Usage:
    python scripts/id/local_fingerprint.py stats
    python scripts/id/local_fingerprint.py lookup 24:f6:03:27:76:cc 90:76:9f:ae:8d:e8
    python scripts/id/local_fingerprint.py dump --format csv --out oui.csv
    python scripts/id/local_fingerprint.py gaps captures logs
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from wifit3.id import VENDOR_BY_OUI, fingerprint, hex_mac, lookup_oui, vendor_for_mac  # noqa: E402
from wifit3.id import canonical_vendor  # noqa: E402
from wifit3.id.client import _RULES  # noqa: E402  # private on purpose: introspection is the point
from wifit3.id.common import _PREFIX_LENGTHS  # noqa: E402

# Dotted / colon / dash separated MACs. The unseparated 12-hex form is deliberately excluded from
# text scanning: a bare 12 hex characters is far more often a PMKID fragment than an address, so
# that form is only read from 22000 records, where the field position is defined.
_SEP_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b")


def _pad(text: str, width: int, right: bool = False) -> str:
    gap = max(0, width - sum(2 if ord(ch) > 0x2E80 else 1 for ch in text))
    return (" " * gap + text) if right else (text + " " * gap)


def prefix_of(mac: str) -> tuple[str, int] | None:
    """The longest registered prefix for ``mac`` and how many nibbles it used."""
    raw = hex_mac(mac)
    for n in _PREFIX_LENGTHS:
        if raw[:n] in VENDOR_BY_OUI:
            return raw[:n], n
    return None


def describe(mac: str) -> list[tuple[str, str]]:
    """Every field the library can say about one address."""
    hit = prefix_of(mac)
    canon = vendor_for_mac(mac)
    fp = fingerprint(mac)
    raw_vendor = lookup_oui(mac)
    rows = [("输入", mac), ("规范化", hex_mac(mac))]
    if hit is None:
        rows += [("前缀", "未收录（指纹库无此前缀）"), ("结论", "该地址在本库中无身份可解")]
        return rows
    prefix, nibbles = hit
    bits = {6: "24 位 OUI", 7: "28 位 MA-M", 9: "36 位 MA-S"}.get(nibbles, f"{nibbles} 位")
    rows += [("命中前缀", f"{prefix}（{bits}）"),
             ("注册厂商", raw_vendor or "?")]
    if canon and canon != raw_vendor:
        rows.append(("归一化厂商", canon))
    if fp is not None:
        rows.append(("指纹标签", f"{fp.emoji} {fp.label}"))
    return rows


def prefix_to_mac(prefix: str) -> str:
    """Pad a registered prefix to a full address, so the public lookup path can be reused."""
    return prefix + "0" * (12 - len(prefix))


def cmd_stats(_args: argparse.Namespace) -> int:
    lens = Counter(len(key) for key in VENDOR_BY_OUI)
    vendors = set(VENDOR_BY_OUI.values())
    canon = {c for key in VENDOR_BY_OUI
             if (c := vendor_for_mac(prefix_to_mac(key))) is not None}
    by_oui = [r for r in _RULES if r.ouis is not None]
    by_pattern = [r for r in _RULES if r.pattern is not None]
    emojis = Counter(r.emoji for r in _RULES)
    covered = set()
    for rule in by_oui:
        covered |= set(rule.ouis or ())
    biggest = max(by_oui, key=lambda r: len(r.ouis or ()), default=None)

    print("指纹库规模（离线读取，未联网）")
    print(f"  OUI 条目总数        {len(VENDOR_BY_OUI):>8d}")
    for nibbles in (6, 7, 9):
        if lens.get(nibbles):
            label = {6: "24 位 OUI ", 7: "28 位 MA-M", 9: "36 位 MA-S"}[nibbles]
            print(f"    {label}      {lens[nibbles]:>8d}")
    print(f"  不同注册厂商名      {len(vendors):>8d}")
    print(f"  归一化后品牌        {len(canon):>8d}")
    groups: dict[str, set[str]] = {}
    for raw_name in vendors:
        c = canonical_vendor(raw_name)
        if c is not None:
            groups.setdefault(c, set()).add(raw_name)
    merged = sorted(((c, n) for c, n in groups.items() if len(n) > 1),
                    key=lambda kv: (-len(kv[1]), kv[0]))[:8]
    if merged:
        print("  收敛最多的品牌（多种 IEEE 法人名归并为同一品牌）")
        for c, names in merged:
            print(f"    {_pad(c, 14)}<- {len(names):>3} 种写法")
    print()
    print(f"  品牌规则            {len(_RULES):>8d}"
          f"（按 OUI 直指 {len(by_oui)} / 按厂商名正则 {len(by_pattern)}）")
    print(f"  规则覆盖的 OUI      {len(covered):>8d}")
    print(f"  不同符号            {len(emojis):>8d}")
    if biggest is not None:
        print(f"  单条规则最大 OUI 数 {len(biggest.ouis or ()):>8d}"
              f"（{biggest.label or biggest.pattern}）")
    return 0


def cmd_lookup(args: argparse.Namespace) -> int:
    for i, mac in enumerate(args.macs):
        if i:
            print()
        rows = describe(mac)
        print(rows[0][1])
        for label, value in rows[1:]:
            print(f"  {_pad(label, 10)}{value}")
    return 0


def cmd_dump(args: argparse.Namespace) -> int:
    items = sorted(VENDOR_BY_OUI.items())
    if args.out:
        target = Path(args.out)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8", newline="") as fh:
            if args.format == "csv":
                writer = csv.writer(fh)
                writer.writerow(["prefix", "nibbles", "vendor"])
                for key, vendor in items:
                    writer.writerow([key, len(key), vendor])
            else:
                json.dump({k: v for k, v in items}, fh, ensure_ascii=False, indent=0)
                fh.write("\n")
        print(f"已导出 {len(items)} 条 -> {target}")
        spread = Counter(len(k) for k, _ in items)
        print("  按前缀长度：" + " / ".join(f"{n} 位 {c}" for n, c in sorted(spread.items())))
        return 0

    # stdout stays a clean data stream so it can be piped; the count goes to stderr.
    if args.format == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(["prefix", "nibbles", "vendor"])
        for key, vendor in items:
            writer.writerow([key, len(key), vendor])
    else:
        json.dump(dict(items), sys.stdout, ensure_ascii=False, indent=0)
        sys.stdout.write("\n")
    print(f"已输出 {len(items)} 条", file=sys.stderr)
    return 0


def extract_macs(path: Path) -> set[str]:
    """Addresses worth resolving: 22000 fields plus separated MACs anywhere in the text."""
    out: set[str] = set()
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        if line.startswith("WPA*"):
            fields = line.split("*")
            for idx in (3, 4):
                if idx < len(fields) and len(fields[idx]) == 12:
                    out.add(fields[idx])
            continue
        out.update(m.group(0) for m in _SEP_MAC_RE.finditer(line))
    return out


def is_local_admin(mac: str) -> bool:
    """True when the U/L bit is set: a locally administered (usually randomised) address.

    These are never in the IEEE registry by construction, so counting them as library gaps
    would bury the handful of real blind spots under every randomised client MAC.
    """
    return bool(int(mac[0:2], 16) & 0x02)


def cmd_gaps(args: argparse.Namespace) -> int:
    files: list[Path] = []
    for raw in args.paths:
        p = Path(raw)
        if p.is_dir():
            files += [f for f in p.rglob("*")
                      if f.is_file() and f.suffix.lower() in {".hc22000", ".22000", ".log", ".jsonl", ".txt"}]
        elif p.is_file():
            files.append(p)
        else:
            print(f"跳过（不存在）：{raw}", file=sys.stderr)
    if not files:
        print("没有可读取的文件。指定目录或 22000/日志文件路径。", file=sys.stderr)
        return 2

    seen: dict[str, set[str]] = {}
    for f in files:
        for mac in extract_macs(f):
            seen.setdefault(hex_mac(mac), set()).add(f.name)

    known = {m: src for m, src in seen.items() if lookup_oui(m)}
    unknown = {m: src for m, src in seen.items() if not lookup_oui(m)}
    local = {m: src for m, src in unknown.items() if is_local_admin(m)}
    global_unknown = {m: src for m, src in unknown.items() if not is_local_admin(m)}

    print(f"扫描文件 {len(files)} 个，抽出地址 {len(seen)} 个（去重）")
    print(f"  已收录 {len(known)}")
    print(f"  未收录 {len(unknown)}"
          + (f"，其中本地管理地址 {len(local)}（随机 MAC，按设计不属 IEEE 注册，不计入盲区）"
             if local else ""))
    print(f"  真实盲区 {len(global_unknown)}")
    if not global_unknown:
        print("\n没有真实盲区：每个全局地址都能解析出厂商。")
        return 0

    print("\n真实盲区明细（指纹库补充候选，按出现文件数排序）")
    print(f"  {_pad('地址', 20)}{_pad('前缀', 10)}来源")
    for mac, srcs in sorted(global_unknown.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"  {_pad(':'.join(mac[i:i + 2] for i in range(0, 12, 2)), 20)}"
              f"{_pad(mac[:6], 10)}{', '.join(sorted(srcs))}")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="离线解锁 wifit3 内嵌的指纹数据：规模、反查、全量导出、盲区发现。",
        epilog="纯本地读取，不联网、不打开射频、不发起任何发送。")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("stats", help="指纹库规模与规则覆盖概览").set_defaults(func=cmd_stats)

    p_lookup = sub.add_parser("lookup", help="反查一个或多个 MAC 的身份字段")
    p_lookup.add_argument("macs", nargs="+", metavar="MAC")
    p_lookup.set_defaults(func=cmd_lookup)

    p_dump = sub.add_parser("dump", help="全量导出 OUI 厂商表")
    p_dump.add_argument("--format", choices=("csv", "json"), default="csv")
    p_dump.add_argument("--out", metavar="PATH", help="写文件；省略则输出到 stdout")
    p_dump.set_defaults(func=cmd_dump)

    p_gaps = sub.add_parser("gaps", help="从采集与日志中找出指纹库未收录的地址")
    p_gaps.add_argument("paths", nargs="+", metavar="PATH",
                        help="目录（递归扫描 .hc22000/.log/.jsonl/.txt）或具体文件")
    p_gaps.set_defaults(func=cmd_gaps)
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
