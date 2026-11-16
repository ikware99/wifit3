"""The three-outcome contract of ``scripts/verify_design_intent.py``.

Two outcomes were enough while every check always ran. The debug switch breaks that: with it on,
the "keys never touch disk" assertion cannot be made, and reporting it as PASS would be the exact
false green the assertion exists to prevent. SUSPENDED is the third answer, and the only thing
stopping it from rotting into a PASS is a test that reads what it actually writes.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_design_intent.py"


@pytest.fixture(scope="module")
def verify():
    """Load the script as a module: it is a tool, not an importable package."""
    spec = importlib.util.spec_from_file_location("verify_design_intent_under_test", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _recorder(verify, tmp_path, total: int):
    return verify.Recorder(tmp_path / "logs", total=total, progress="none")


def _rows(rec) -> list[dict]:
    return [json.loads(line) for line in rec.jsonl.read_text(encoding="utf-8").splitlines()]


# --- the third state --------------------------------------------------------


def test_suspended_is_never_spelled_as_a_pass(verify):
    assert verify.verdict_of(verify.SUSPENDED) != "PASS"
    assert "SUSPENDED" in verify.verdict_of(verify.SUSPENDED)
    assert verify.verdict_of(True) == "PASS"
    assert verify.verdict_of(False) == "FAIL"


def test_a_suspended_step_does_not_fail_the_run_but_is_not_counted_as_passed(verify, tmp_path):
    rec = _recorder(verify, tmp_path, total=2)
    rec.step("a", "intent", "action", "expected", "observed", True)
    rec.step("b", "intent", "action", "expected", "observed", verify.SUSPENDED, "switched off")

    assert rec.counts() == (1, 0, 1)
    assert rec.summary(0.1) is True, "nothing failed, so the run is not red"

    rows = _rows(rec)
    assert rows[1]["ok"] is None, "a JSONL reader must be able to tell it from a pass"
    assert rows[1]["verdict"] == "suspended"
    # The operator reads the log, not the JSONL: the caveat has to be in the text too.
    assert "暂停" in rec.text.read_text(encoding="utf-8")


def test_a_real_failure_still_fails_while_a_suspension_is_pending(verify, tmp_path):
    rec = _recorder(verify, tmp_path, total=2)
    rec.step("a", "intent", "action", "expected", "observed", verify.SUSPENDED)
    rec.step("b", "intent", "action", "expected", "observed", False)

    assert rec.counts() == (0, 1, 1)
    assert rec.summary(0.1) is False


# --- targets typed at a prompt ---------------------------------------------


def test_typed_targets_go_through_the_same_validator_as_command_line_ones(verify):
    assert verify.parse_targets(["lab:24:f6:03:27:76:cc"]) == [
        ("lab", "24:f6:03:27:76:cc", None)]
    assert verify.parse_targets(["lab:24-F6-03-27-76-CC:secrets/lab.psk"]) == [
        ("lab", "24-F6-03-27-76-CC", "secrets/lab.psk")]
    with pytest.raises(SystemExit):
        verify.parse_targets(["lab:24:f6:03:27:76"])


def test_prompting_refuses_a_pipe_rather_than_returning_no_targets(verify, monkeypatch):
    """Zero targets must never be the silent result of a pipe: that run proves nothing."""

    class _Pipe:
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr(verify.sys, "stdin", _Pipe())
    with pytest.raises(SystemExit) as caught:
        verify.ask_targets()
    assert "--ask-targets" in str(caught.value)


# --- the debug dump --------------------------------------------------------


def _entry(**kwargs) -> dict:
    base = dict(ssid="lab", bssid="24:f6:03:27:76:cc", psk="pw-one", fp="abc123def456",
                sta="02:11:22:33:44:55", pmkid="deadbeef" * 4)
    base.update(kwargs)
    return base


def test_the_debug_dump_carries_the_fingerprint_mapping_and_the_pmkid(verify, tmp_path):
    path = tmp_path / "logout.txt"
    assert verify.write_debug_plaintext(path, [_entry()], None) == 1
    text = path.read_text(encoding="utf-8")

    assert "sha256[:12]=abc123def456" in text and "psk=pw-one" in text
    assert "pmkid=" + "deadbeef" * 4 in text and "hashcat -m 22000" in text
    assert "不要放进共享盘" in text, "the file itself has to say how to dispose of it"


def test_the_shared_passphrase_is_not_dumped_twice(verify, tmp_path):
    path = tmp_path / "logout.txt"
    verify.write_debug_plaintext(path, [_entry()], "pw-one")
    assert path.read_text(encoding="utf-8").count("psk=pw-one") == 1

    verify.write_debug_plaintext(path, [_entry()], "pw-unused")
    assert "psk=pw-unused" in path.read_text(encoding="utf-8")


def test_fingerprint_only_mode_writes_no_pmkid_section(verify, tmp_path):
    path = tmp_path / "logout.txt"
    verify.write_debug_plaintext(path, [_entry(pmkid="", sta="")], None)
    assert "派生 PMKID" not in path.read_text(encoding="utf-8")


def test_the_default_dump_path_is_ignored_by_git(verify):
    """The default path only stays harmless while .gitignore keeps up with it."""
    if not (verify.ROOT / ".git").exists():
        pytest.skip("不在 git 工作树内")
    note = verify.git_ignore_note(verify.ROOT / verify.DEFAULT_DEBUG_PLAINTEXT)
    if note:
        pytest.skip(f"git 无法判定该路径：{note}")
    assert note == ""


def test_a_dump_outside_the_repository_earns_no_warning(verify, tmp_path):
    """Nothing inside tmp_path can be committed, so a git warning would be noise."""
    assert verify.git_ignore_note(tmp_path / "logout.txt") == ""
