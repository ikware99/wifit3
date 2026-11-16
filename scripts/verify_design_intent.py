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
    WIFIT3_SSID=... WIFIT3_PSK=... WIFIT3_BSSID=... .venv/Scripts/python.exe scripts/verify_design_intent.py
"""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wifit3.campaigns.pmkid import PmkidHarvestAttack                      # noqa: E402
from wifit3.chips.sim import SIM_PID, SIM_VID                            # noqa: E402
from wifit3.chips.sim.backend import reset_usb_backend, use_sim_backend   # noqa: E402
from wifit3.chips.sim.driver import SimulatedDriver                      # noqa: E402
from wifit3.crack.hc22000_format import parse_hc22000                    # noqa: E402
from wifit3.crack.wpa_psk import derive_pmk, psk_matches                  # noqa: E402
from wifit3.device import manager                                        # noqa: E402
from wifit3.persist.save import save_pmkid                               # noqa: E402
from wifit3.wlan.array import WlanArray                                  # noqa: E402

PSK_AP = "02:00:5e:1a:00:01"
HASHCAT_VECTOR = ("WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4"
                  "*686173686361742d6573736964***")


class Recorder:
    """One JSONL record plus one readable block per step."""

    def __init__(self, log_dir: Path) -> None:
        stamp = datetime.datetime.now().strftime("%Y-%m-%d")
        log_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl = log_dir / f"{stamp}-设计意图验证.jsonl"
        self.text = log_dir / f"{stamp}-设计意图验证.log"
        self.jsonl.write_text("", encoding="utf-8")
        self.text.write_text("", encoding="utf-8")
        self.rows: list[dict] = []
        self.n = 0
        self._mark = time.perf_counter()

    def mark(self) -> None:
        """Start timing the next step's work."""
        self._mark = time.perf_counter()

    def _emit(self, line: str) -> None:
        print(line)
        with self.text.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

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
                   actual=actual, ok=ok, detail=detail, elapsed_ms=round(elapsed_ms, 1))
        self.rows.append(row)
        with self.jsonl.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        self._mark = time.perf_counter()
        return ok

    def summary(self, wall_s: float) -> bool:
        passed = sum(1 for r in self.rows if r["ok"])
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
        self._emit("")
        self._emit(f"日志  {self.jsonl}")
        self._emit(f"      {self.text}")
        self._emit(bar)
        return passed == len(self.rows)


def ref_pmkid(psk: str, essid: bytes, aa: bytes, spa: bytes) -> str:
    """The algorithm restated independently, so a bug shared with wifit3 cannot pass."""
    pmk = hashlib.pbkdf2_hmac("sha1", psk.encode(), essid, 4096, 32)
    return hmac.new(pmk, b"PMK Name" + aa + spa, hashlib.sha1).digest()[:16].hex()


def fingerprint(secret: str) -> str:
    """A stable, non-reversible tag for a credential, safe to write to a log."""
    return hashlib.sha256(secret.encode()).hexdigest()[:12]


async def wait_for(pred, rounds: int = 80, step: float = 0.05) -> bool:
    for _ in range(rounds):
        if pred():
            return True
        await asyncio.sleep(step)
    return False


async def main() -> int:
    wall_start = time.perf_counter()
    rec = Recorder(ROOT / "logs")
    rec.head("wifit3 设计意图端到端验证",
             "无 USB Wi-Fi 卡前提下，靠虚拟通道把产品链路跑到可破解的 hash 行")

    # -- S01 -----------------------------------------------------------------
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

        # -- S11 (可选) ------------------------------------------------------
        rec.mark()
        psk = os.environ.get("WIFIT3_PSK", "")
        if psk:
            ssid = os.environ.get("WIFIT3_SSID", "")
            bssid = os.environ.get("WIFIT3_BSSID", "")
            essid = ssid.encode()
            aa = bytes.fromhex(bssid.replace(":", ""))
            spa = bytes.fromhex(attack.client_mac.replace(":", ""))
            their = derive_pmk(psk, essid)
            from wifit3.crack.wpa_psk import pmkid as pmkid_of
            real_pmkid = pmkid_of(their, aa, spa).hex()
            rec.step(
                "真实参数对账（可选，需环境变量）",
                "把同一派生链路换成真实 SSID/BSSID 跑一遍，确认参数变化不改变正确性。"
                "口令只以 SHA-256 指纹入日志，明文不落盘。",
                f"derive_pmk(口令, '{ssid}') + pmkid(PMK, {bssid}, {attack.client_mac})",
                "wifit3 派生 == 独立实现派生",
                f"PMKID {real_pmkid}",
                real_pmkid == ref_pmkid(psk, essid, aa, spa),
                f"口令指纹 sha256[:12]={fingerprint(psk)}；"
                f"这一步只证明链路一致，不证明该口令能打开该 AP",
            )
    finally:
        if iface is not None:
            await iface.close()
        reset_usb_backend()

    return 0 if rec.summary(time.perf_counter() - wall_start) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
