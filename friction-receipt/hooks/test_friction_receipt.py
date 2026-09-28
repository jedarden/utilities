#!/usr/bin/env python3
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
HOOK = HERE / "friction-receipt.py"


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="friction-receipt-test-"))
        self.receipts = self.root / "receipts"
        self.state = self.root / "state"
        self.transcript = self.root / "session.jsonl"
        self.env = dict(os.environ, TWILL_RECEIPTS_DIR=str(self.receipts),
                        ORG_RULE_GUARD_STATE_DIR=str(self.state / "org-rule-guard"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def run_hook(self, payload):
        return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                              text=True, capture_output=True, env=self.env, timeout=20)

    def test_round_trip_records_rules_denials_and_unresolved_errors(self):
        self.transcript.write_text("\n".join([
            json.dumps({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "read", "name": "Read",
                 "input": {"file_path": "/repo/AGENTS.md"}},
                {"type": "tool_use", "id": "bash", "name": "Bash",
                 "input": {"command": "pytest -q"}},
            ]}}),
            json.dumps({"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "bash", "is_error": True,
                 "content": "Exit code 2: token ghp_" + "A" * 40},
            ]}}),
            "",
        ]))
        denial_dir = self.state / "org-rule-guard"
        denial_dir.mkdir(parents=True)
        (denial_dir / "denials.jsonl").write_text(json.dumps({
            "ts": "2026-09-28T20:00:00Z", "rule_id": "latest-image-tag",
            "tool": "Write", "session_id": "sess-1",
            "fragment": "safe",
        }) + "\n")
        result = self.run_hook({"session_id": "sess-1", "cwd": "/repo",
                                "reason": "other", "transcript_path": str(self.transcript)})
        self.assertEqual(result.returncode, 0)
        receipt = json.loads((self.receipts / "sess-1.json").read_text())
        self.assertEqual(receipt["schema"], "twill-friction-receipt/v1")
        self.assertEqual(receipt["rules_consulted"], ["AGENTS.md"])
        self.assertEqual(receipt["denials"][0]["rule_id"], "latest-image-tag")
        self.assertEqual(receipt["unresolved_errors"][0]["kind"], "tool_error")
        self.assertNotIn("ghp_", (self.receipts / "sess-1.json").read_text())
        self.assertFalse(receipt["ended_mid_task"])
        self.assertEqual(stat.S_IMODE(self.receipts.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.receipts / "sess-1.json").stat().st_mode), 0o600)

    def test_pending_bash_marks_session_mid_task_and_missing_input_is_fail_open(self):
        self.transcript.write_text(json.dumps({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "bash", "name": "Bash",
             "input": {"command": "git status"}},
        ]}}) + "\n")
        result = self.run_hook({"session_id": "sess-2", "transcript_path": str(self.transcript)})
        self.assertEqual(result.returncode, 0)
        self.assertTrue(json.loads((self.receipts / "sess-2.json").read_text())["ended_mid_task"])
        empty = subprocess.run([sys.executable, str(HOOK)], input="not json", text=True,
                                capture_output=True, env=self.env, timeout=20)
        self.assertEqual(empty.returncode, 0)

    def test_installer_wires_one_session_end_command_and_is_idempotent(self):
        hooks = self.root / "hooks"
        settings = self.root / "settings.json"
        env = dict(os.environ, HOME=str(self.root), CLAUDE_HOOKS_DIR=str(hooks),
                   CLAUDE_SETTINGS=str(settings))
        installer = HERE.parent / "install.sh"
        first = subprocess.run(["sh", str(installer), "--wire"], env=env,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(first.returncode, 0, first.stderr)
        second = subprocess.run(["sh", str(installer), "--wire"], env=env,
                                 capture_output=True, text=True, timeout=20)
        self.assertEqual(second.returncode, 0, second.stderr)
        data = json.loads(settings.read_text())
        commands = [
            hook.get("command")
            for entry in data["hooks"]["SessionEnd"]
            for hook in entry.get("hooks", [])
            if isinstance(hook, dict)
        ]
        self.assertEqual(commands, [f"python3 {hooks / 'friction-receipt.py'}"])

    def test_installer_does_not_overwrite_without_force(self):
        hooks = self.root / "hooks"
        hooks.mkdir()
        destination = hooks / "friction-receipt.py"
        destination.write_text("operator copy\n")
        env = dict(os.environ, HOME=str(self.root), CLAUDE_HOOKS_DIR=str(hooks),
                   CLAUDE_SETTINGS=str(self.root / "settings.json"))
        installer = HERE.parent / "install.sh"
        result = subprocess.run(["sh", str(installer)], env=env,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(destination.read_text(), "operator copy\n")


if __name__ == "__main__":
    unittest.main()
