#!/usr/bin/env python3
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
HOOK = HERE / "friction-receipt.py"
RECEIPT_DOC = HERE.parent / "docs" / "receipt-contract.md"


def load_hook_module():
    spec = importlib.util.spec_from_file_location("friction_receipt", HOOK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def documented_table(heading):
    lines = RECEIPT_DOC.read_text(encoding="utf-8").splitlines()
    try:
        start = lines.index(heading)
    except ValueError as error:
        raise AssertionError(f"receipt contract is missing table {heading!r}") from error
    rows = []
    for line in lines[start + 1:]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if cells and all(set(cell) <= {"-", ":", " "} for cell in cells):
            continue
        rows.append(cells)
    return rows


def code_cells(cell):
    return re.findall(r"`([^`]+)`", cell)


class DocumentationSync(unittest.TestCase):
    """Keep the normative receipt document tied to the producer code."""

    def test_documented_top_level_fields_match_hook(self):
        module = load_hook_module()
        rows = documented_table("| Field | JSON type | Bound or fixed value |")
        documented = [
            (code_cells(row[0])[0], code_cells(row[1])[0], code_cells(row[2])[0])
            for row in rows
        ]
        self.assertEqual(documented, list(module.RECEIPT_FIELD_CONTRACT))
        self.assertEqual(
            tuple(field for field, _kind, _bound in documented),
            module._RECEIPT_KEYS,
        )
        self.assertEqual(
            set(module.build_receipt({})), set(module._RECEIPT_KEYS)
        )

    def test_documented_nested_records_match_hook(self):
        module = load_hook_module()
        rows = documented_table("| Collection | Object keys | Per-key bounds |")
        documented = [
            (
                code_cells(row[0])[0],
                tuple(code_cells(row[1])),
                tuple(code_cells(row[2])),
            )
            for row in rows
        ]
        self.assertEqual(documented, list(module.RECEIPT_NESTED_CONTRACT))

    def test_documented_redaction_patterns_match_hook(self):
        module = load_hook_module()
        rows = documented_table("| Label | Python `re` pattern |")
        documented = [(row[0], code_cells(row[1])[0]) for row in rows]
        expected = [
            (label, pattern) for label, pattern in module._REDACTION_PATTERNS
        ]
        self.assertEqual(documented, expected)
        self.assertEqual(
            [pattern.pattern for pattern in module._SECRET_PATTERNS],
            [pattern for _label, pattern in expected],
        )

    def test_documented_redaction_steps_match_hook(self):
        module = load_hook_module()
        rows = documented_table("| Step | Hook symbol | Effect |")
        documented = [(row[0], code_cells(row[1])[0]) for row in rows]
        self.assertEqual(documented, list(module.REDACTION_STEPS))


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

    def run_hook_raw(self, raw):
        return subprocess.run([sys.executable, str(HOOK)], input=raw,
                              text=True, capture_output=True, env=self.env, timeout=20)

    def receipt_text(self, session_id):
        return (self.receipts / (session_id + ".json")).read_text()

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

    def test_receipt_store_and_files_are_private_with_permissive_umask(self):
        old_umask = os.umask(0)
        try:
            result = self.run_hook({"session_id": "private-receipt"})
        finally:
            os.umask(old_umask)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(self.receipts.stat().st_mode), 0o700)
        self.assertEqual(
            stat.S_IMODE((self.receipts / "private-receipt.json").stat().st_mode),
            0o600,
        )

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

    def test_malformed_or_missing_session_end_input_is_fail_open(self):
        for raw in ("", "not json", "null", "[]", '{"session_id":'):
            with self.subTest(raw=raw):
                result = self.run_hook_raw(raw)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")
        self.assertFalse(self.receipts.exists())

        missing_transcript = self.run_hook({
            "session_id": "missing-transcript",
            "transcript_path": str(self.root / "does-not-exist.jsonl"),
        })
        self.assertEqual(missing_transcript.returncode, 0)
        self.assertEqual(missing_transcript.stdout, "")
        self.assertEqual(missing_transcript.stderr, "")
        receipt = json.loads(self.receipt_text("missing-transcript"))
        self.assertEqual(receipt["rules_consulted"], [])
        self.assertEqual(receipt["unresolved_errors"], [])

    def test_receipt_bounds_text_and_collection_sizes(self):
        session_id = "bounded-session"
        content = []
        for index in range(100):
            content.append({
                "type": "tool_use",
                "id": "read-" + str(index),
                "name": "Read",
                "input": {
                    "file_path": "/repo/.claude/skills/skill-" + str(index) + "/README.md",
                },
            })
            content.extend([
                {
                    "type": "tool_use",
                    "id": "bash-" + str(index),
                    "name": "Bash",
                    "input": {"command": "command-" + str(index)},
                },
                {
                    "type": "tool_result",
                    "tool_use_id": "bash-" + str(index),
                    "is_error": True,
                    "content": "error-" + str(index) + "-" + ("x" * 500),
                },
            ])
        self.transcript.write_text(json.dumps({
            "type": "assistant", "message": {"content": content},
        }) + "\n")

        denial_dir = self.state / "org-rule-guard"
        denial_dir.mkdir(parents=True)
        with (denial_dir / "denials.jsonl").open("w") as handle:
            for index in range(200):
                handle.write(json.dumps({
                    "ts": "t" * 200,
                    "rule_id": "rule-" + ("r" * 400) + str(index),
                    "tool": "tool-" + ("t" * 400) + str(index),
                    "session_id": session_id,
                }) + "\n")

        result = self.run_hook({
            "session_id": session_id,
            "cwd": "/repo/" + ("c" * 500),
            "reason": "r" * 500,
            "transcript_path": str(self.transcript),
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(self.receipt_text(session_id))
        self.assertLessEqual(len(receipt["session_id"]), 128)
        self.assertLessEqual(len(receipt["reason"]), 128)
        self.assertLessEqual(len(receipt["cwd"]), 160)
        self.assertEqual(len(receipt["rules_consulted"]), 64)
        self.assertEqual(len(receipt["unresolved_errors"]), 64)
        self.assertEqual(len(receipt["denials"]), 128)
        for denial in receipt["denials"]:
            self.assertEqual(len(denial["ts"]), 32)
            self.assertEqual(len(denial["rule_id"]), 128)
            self.assertEqual(len(denial["tool"]), 128)
        for error in receipt["unresolved_errors"]:
            self.assertEqual(len(error["signature"]), 240)

    def test_oversized_receipt_is_valid_json_under_the_hard_byte_bound(self):
        module = load_hook_module()
        module.MAX_RECEIPT_BYTES = 1024
        previous = os.environ.get(module.RECEIPTS_DIR_ENV)
        os.environ[module.RECEIPTS_DIR_ENV] = str(self.receipts)
        try:
            module.write_receipt({
                "schema": module.SCHEMA,
                "session_id": "oversized",
                "ended_at": "2026-09-28T20:00:00Z",
                "reason": "other",
                "cwd": "/repo",
                "rules_consulted": [],
                "denials": [],
                "unresolved_errors": [
                    {"kind": "tool_error", "signature": "x" * 100_000}
                    for _ in range(10)
                ],
                "ended_mid_task": False,
            }, {"session_id": "oversized"})
        finally:
            if previous is None:
                os.environ.pop(module.RECEIPTS_DIR_ENV, None)
            else:
                os.environ[module.RECEIPTS_DIR_ENV] = previous
        path = self.receipts / "oversized.json"
        self.assertLessEqual(path.stat().st_size, module.MAX_RECEIPT_BYTES)
        self.assertEqual(json.loads(path.read_text())['schema'], module.SCHEMA)

    def test_receipt_redacts_credential_like_content(self):
        credential_values = [
            "ghp_" + ("A" * 40),
            "github_pat_" + ("B" * 45),
            "AKIA" + "0123456789ABCDEF",
            "xoxb-" + ("C" * 24),
            "sk-ant-" + ("D" * 35),
            "Bearer " + ("E" * 24),
            "-----BEGIN PRIVATE KEY-----\\n" + ("F" * 40)
            + "\\n-----END PRIVATE KEY-----",
        ]
        marker = "transcript-payload-must-not-be-copied"
        secret_blob = " ".join(credential_values)
        self.transcript.write_text(json.dumps({
            "type": "assistant", "message": {"content": [{
                "type": "tool_use", "id": "secret-bash", "name": "Bash",
                "input": {"command": secret_blob},
            }]},
        }) + "\n")
        with self.transcript.open("a") as handle:
            handle.write(json.dumps({
                "type": "user", "message": {"content": [{
                    "type": "tool_result", "tool_use_id": "secret-bash",
                    "is_error": True, "content": secret_blob,
                }]},
            }) + "\n")
            handle.write(json.dumps({
                "type": "user", "message": {"content": [{
                    "type": "text", "text": marker + " " + secret_blob,
                }]},
            }) + "\n")

        session_id = "receipt-redaction"
        result = self.run_hook({
            "session_id": session_id,
            "cwd": "/repo/" + credential_values[0],
            "reason": credential_values[1],
            "transcript_path": str(self.transcript),
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        emitted = self.receipt_text(session_id)
        for credential in credential_values:
            self.assertNotIn(credential, emitted)
        self.assertNotIn(marker, emitted)

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

    def run_installer(self, settings, *arguments):
        hooks = self.root / "hooks"
        environment = dict(
            os.environ,
            HOME=str(self.root),
            CLAUDE_HOOKS_DIR=str(hooks),
            CLAUDE_SETTINGS=str(settings),
        )
        return subprocess.run(
            ["sh", str(HERE.parent / "install.sh"), *arguments],
            env=environment,
            capture_output=True,
            text=True,
            timeout=20,
        )

    @staticmethod
    def session_command(settings):
        return [
            hook.get("command")
            for entry in settings.get("hooks", {}).get("SessionEnd", [])
            for hook in entry.get("hooks", [])
            if isinstance(hook, dict) and "command" in hook
        ]

    def test_wire_current_entry_is_byte_idempotent_and_keeps_one_backup(self):
        settings = self.root / "settings.json"
        settings.parent.mkdir(parents=True, exist_ok=True)
        original = {
            "model": "opus",
            "hooks": {"SessionEnd": [{"hooks": [{
                "type": "command", "command": "printf unrelated",
            }]}]},
        }
        settings.write_text(json.dumps(original, indent=2) + "\n")
        before = settings.read_bytes()

        first = self.run_installer(settings, "--wire")
        self.assertEqual(first.returncode, 0, first.stderr)
        after_first = settings.read_bytes()
        self.assertIn("wired", first.stdout)
        self.assertEqual(
            self.session_command(json.loads(after_first)),
            ["printf unrelated", f"python3 {self.root / 'hooks/friction-receipt.py'}"],
        )
        owned = json.loads(after_first)["hooks"]["SessionEnd"][1]["hooks"][0]
        self.assertEqual(owned["timeout"], 10)
        self.assertEqual((Path(str(settings) + ".bak")).read_bytes(), before)

        second = self.run_installer(settings, "--wire")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("already", second.stdout)
        self.assertEqual(settings.read_bytes(), after_first)

    def test_wire_refreshes_the_known_legacy_entry_in_place(self):
        settings = self.root / "settings.json"
        settings.parent.mkdir(parents=True, exist_ok=True)
        command = f"python3 {self.root / 'hooks/friction-receipt.py'}"
        original = {
            "model": "opus",
            "hooks": {"SessionEnd": [
                {"hooks": [{"type": "command", "command": "printf keep"}]},
                {"hooks": [{"type": "command", "command": command}]},
            ]},
        }
        settings.write_text(json.dumps(original, indent=2) + "\n")
        before = settings.read_bytes()

        result = self.run_installer(settings, "--wire")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("refreshed", result.stdout)
        merged = json.loads(settings.read_text())
        self.assertEqual(merged["model"], "opus")
        self.assertEqual(merged["hooks"]["SessionEnd"][0], original["hooks"]["SessionEnd"][0])
        self.assertEqual(merged["hooks"]["SessionEnd"][1]["hooks"][0]["timeout"], 10)
        self.assertEqual(
            json.loads(Path(str(settings) + ".bak").read_text()),
            json.loads(before),
        )

    def test_wire_preserves_customized_entry_and_reports_exit_two(self):
        settings = self.root / "settings.json"
        settings.parent.mkdir(parents=True, exist_ok=True)
        command = f"python3 {self.root / 'hooks/friction-receipt.py'}"
        original = {
            "hooks": {"SessionEnd": [{"hooks": [{
                "type": "command",
                "command": command,
                "timeout": 7,
                "operator_note": "keep this",
            }]}]},
        }
        settings.write_text(json.dumps(original, indent=2) + "\n")
        before = settings.read_bytes()

        result = self.run_installer(settings, "--wire")

        self.assertEqual(result.returncode, 2)
        self.assertEqual(settings.read_bytes(), before)
        self.assertFalse(Path(str(settings) + ".bak").exists())
        self.assertEqual(result.stderr.count("preserved"), 1)
        self.assertIn("use --wire --force", result.stderr)

    def test_wire_force_replaces_only_customized_timeout(self):
        settings = self.root / "settings.json"
        settings.parent.mkdir(parents=True, exist_ok=True)
        command = f"python3 {self.root / 'hooks/friction-receipt.py'}"
        settings.write_text(json.dumps({
            "model": "opus",
            "hooks": {"SessionEnd": [{
                "operator_note": "keep entry",
                "hooks": [{
                    "type": "command",
                    "command": command,
                    "timeout": 7,
                    "operator_note": "keep handler",
                }],
            }]},
        }, indent=2) + "\n")

        result = self.run_installer(settings, "--wire", "--force")

        self.assertEqual(result.returncode, 0, result.stderr)
        handler = json.loads(settings.read_text())["hooks"]["SessionEnd"][0]
        self.assertEqual(handler["operator_note"], "keep entry")
        self.assertEqual(handler["hooks"][0]["operator_note"], "keep handler")
        self.assertEqual(handler["hooks"][0]["timeout"], 10)
        self.assertEqual(handler["hooks"][0]["command"], command)

    def test_uninstall_refuses_foreign_hook_and_leaves_it_in_place(self):
        hooks = self.root / "hooks"
        hooks.mkdir()
        destination = hooks / "friction-receipt.py"
        destination.write_text("operator copy\n")

        result = self.run_installer(self.root / "settings.json", "--uninstall")

        self.assertEqual(result.returncode, 1)
        self.assertIn("refusing to remove", result.stderr)
        self.assertEqual(destination.read_text(), "operator copy\n")

    def test_uninstall_removes_owned_session_end_entry_but_keeps_backup_and_others(self):
        settings = self.root / "settings.json"
        settings.parent.mkdir(parents=True, exist_ok=True)
        unrelated = {"hooks": [{"type": "command", "command": "printf keep"}]}
        settings.write_text(json.dumps({"hooks": {"SessionEnd": [unrelated]}}) + "\n")
        first = self.run_installer(settings, "--wire")
        self.assertEqual(first.returncode, 0, first.stderr)
        backup = Path(str(settings) + ".bak")
        backup.write_text("operator backup\n")
        before_backup = backup.read_bytes()

        result = self.run_installer(settings, "--uninstall")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "hooks" / "friction-receipt.py").exists())
        self.assertEqual(backup.read_bytes(), before_backup)
        merged = json.loads(settings.read_text())
        self.assertEqual(merged["hooks"].get("SessionEnd"), [unrelated])
        self.assertFalse(Path(str(settings) + ".lock").exists())

    def test_uninstall_leaves_receipt_state_in_place(self):
        settings = self.root / "settings.json"
        self.receipts.mkdir()
        receipt = self.receipts / "already-written.json"
        receipt.write_text('{"schema":"twill-friction-receipt/v1"}\n')
        before = receipt.read_bytes()
        first = self.run_installer(settings, "--wire")
        self.assertEqual(first.returncode, 0, first.stderr)

        result = self.run_installer(settings, "--uninstall")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.receipts.is_dir())
        self.assertEqual(receipt.read_bytes(), before)

    def test_uninstall_preserves_customized_entry_until_force(self):
        settings = self.root / "settings.json"
        first = self.run_installer(settings, "--wire")
        self.assertEqual(first.returncode, 0, first.stderr)
        data = json.loads(settings.read_text())
        data["hooks"]["SessionEnd"][0]["hooks"][0]["timeout"] = 7
        settings.write_text(json.dumps(data, indent=2) + "\n")
        before = settings.read_bytes()

        refused = self.run_installer(settings, "--uninstall")
        self.assertEqual(refused.returncode, 2)
        self.assertEqual(settings.read_bytes(), before)
        self.assertTrue((self.root / "hooks" / "friction-receipt.py").exists())

        forced = self.run_installer(settings, "--uninstall", "--force")
        self.assertEqual(forced.returncode, 0, forced.stderr)
        self.assertFalse((self.root / "hooks" / "friction-receipt.py").exists())
        self.assertEqual(json.loads(settings.read_text())["hooks"]["SessionEnd"], [])


if __name__ == "__main__":
    unittest.main()
