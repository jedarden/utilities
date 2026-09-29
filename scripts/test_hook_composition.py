#!/usr/bin/env python3
"""Integration tests for the two guards and the SessionEnd producer.

The guards deliberately remain separate processes. These tests model the
host passing the same payload to both handlers, in either order, and verify
that the optional companion cannot remove org-rule-guard's standalone
credential coverage. The combined settings example also carries the
event-scoped friction-receipt entry.
"""

import json
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ORG_HOOK = ROOT / "org-rule-guard" / "hooks" / "org-rule-guard.py"
CREDENTIAL_HOOK = ROOT / "agent-secrets" / "hooks" / "credential-guard.py"
COMBINED_SETTINGS = ROOT / "docs" / "examples" / "settings-composed.json"
STRUCTURE_DOC = ROOT / "docs" / "structure-check.md"


def load_hook(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def documented_hook_tools():
    """Read the code-valued hook tool inventory from the structure guide."""
    lines = STRUCTURE_DOC.read_text(encoding="utf-8").splitlines()
    try:
        section = lines.index("## Hook matcher inventory")
    except ValueError as error:
        raise AssertionError(
            "structure-check reference is missing the hook matcher inventory"
        ) from error

    try:
        start = lines.index("```text", section + 1) + 1
        end = lines.index("```", start)
    except ValueError as error:
        raise AssertionError(
            "structure-check reference is missing the hook tool inventory"
        ) from error

    tools = [line.strip() for line in lines[start:end] if line.strip()]
    if any(" " in tool or "`" in tool for tool in tools):
        raise AssertionError("malformed hook tool inventory")
    return tools


ORG_MODULE = load_hook(ORG_HOOK, "org_rule_guard_for_composition")
CREDENTIAL_MODULE = load_hook(CREDENTIAL_HOOK, "credential_guard_for_composition")


def alnum(length, seed=0):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(alphabet[(index * 7 + seed) % len(alphabet)] for index in range(length))


def token(prefix="ghp_", length=36, seed=0):
    return prefix + alnum(length, seed)


def write_payload(content, path="notes.txt"):
    return {
        "tool_name": "Write",
        "tool_input": {"file_path": path, "content": content},
        "session_id": "composition-test",
        "cwd": str(ROOT),
    }


def multiedit_payload(content, path="notes.txt"):
    return {
        "tool_name": "MultiEdit",
        "tool_input": {
            "file_path": path,
            "edits": [{"old_string": "placeholder", "new_string": content}],
        },
        "session_id": "composition-test",
        "cwd": str(ROOT),
    }


def notebook_edit_payload(content, path="notes.ipynb"):
    return {
        "tool_name": "NotebookEdit",
        "tool_input": {
            "notebook_path": path,
            "cell_id": "cell-1",
            "cell_type": "code",
            "edit_mode": "replace",
            "new_source": content,
        },
        "session_id": "composition-test",
        "cwd": str(ROOT),
    }


def run_hook(hook, payload, state_home):
    env = dict(os.environ)
    env["XDG_CONFIG_HOME"] = str(state_home / "config")
    env["XDG_STATE_HOME"] = str(state_home / "state")
    env.pop("ORG_RULE_GUARD_STATE_DIR", None)
    result = subprocess.run(
        [sys.executable, str(hook)],
        input=json.dumps(payload).encode(),
        capture_output=True,
        env=env,
        timeout=20,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"{hook} exited {result.returncode}: {result.stderr.decode()}"
        )
    stdout = result.stdout.decode().strip()
    return json.loads(stdout) if stdout else None


def denied(result):
    return bool(result) and result["hookSpecificOutput"]["permissionDecision"] == "deny"


class HookComposition(unittest.TestCase):
    def test_documented_inventory_equals_hooks_supported_tools(self):
        expected_tools = set(ORG_MODULE.SUPPORTED_TOOLS) | set(
            CREDENTIAL_MODULE.SUPPORTED_TOOLS
        )
        documented = documented_hook_tools()
        self.assertEqual(len(documented), len(set(documented)))
        self.assertEqual(set(documented), expected_tools)

    def test_combined_settings_wires_all_shipped_handlers(self):
        with COMBINED_SETTINGS.open(encoding="utf-8") as handle:
            settings = json.load(handle)

        entries = settings["hooks"]["PreToolUse"]
        self.assertEqual(len(entries), 2)
        commands = [entry["hooks"][0]["command"] for entry in entries]
        self.assertEqual(commands, [
            "python3 ~/.claude/hooks/org-rule-guard.py",
            "python3 ~/.claude/hooks/credential-guard.py",
        ])
        self.assertEqual(entries[0]["matcher"], "Write|Edit|MultiEdit|NotebookEdit|Bash")
        self.assertEqual(entries[1]["matcher"], "Write|Edit|MultiEdit|NotebookEdit|Bash")
        self.assertEqual(entries[0]["hooks"][0]["timeout"], 10)
        self.assertEqual(entries[1]["hooks"][0]["timeout"], 10)

        session_end = settings["hooks"]["SessionEnd"]
        self.assertEqual(len(session_end), 1)
        self.assertNotIn("matcher", session_end[0])
        self.assertEqual(
            session_end[0]["hooks"][0],
            {
                "type": "command",
                "command": "python3 ~/.claude/hooks/friction-receipt.py",
                "timeout": 10,
            },
        )

    def test_shipped_matchers_equal_each_hooks_supported_tools(self):
        with COMBINED_SETTINGS.open(encoding="utf-8") as handle:
            entries = json.load(handle)["hooks"]["PreToolUse"]

        inspected_tools = {
            "python3 ~/.claude/hooks/org-rule-guard.py":
                set(ORG_MODULE.SUPPORTED_TOOLS),
            "python3 ~/.claude/hooks/credential-guard.py":
                set(CREDENTIAL_MODULE.SUPPORTED_TOOLS),
        }
        expected_tools = {"Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"}
        for entry in entries:
            command = entry["hooks"][0]["command"]
            with self.subTest(command=command):
                self.assertIn(command, inspected_tools)
                self.assertEqual(inspected_tools[command], expected_tools)
                matcher_tools = entry["matcher"].split("|")
                self.assertEqual(len(matcher_tools), len(set(matcher_tools)))
                missing = inspected_tools[command] - set(matcher_tools)
                self.assertEqual(missing, set(),
                                 "matcher omits inspected tool classes")
                extra = set(matcher_tools) - inspected_tools[command]
                self.assertEqual(extra, set(),
                                 "matcher names an uninspected tool class")

    def test_notebook_edit_credential_is_denied_by_both_hooks(self):
        payload = notebook_edit_payload("stored value: " + token(seed=17))
        with tempfile.TemporaryDirectory(prefix="hook-composition-") as directory:
            state_home = Path(directory)
            self.assertTrue(denied(run_hook(ORG_HOOK, payload, state_home)))
            self.assertTrue(denied(run_hook(CREDENTIAL_HOOK, payload, state_home)))

    def test_org_guard_inspects_multiedit_file_rules(self):
        cases = (
            ("workflow", ".github/workflows/ci.yml", "name: build\non: push\n"),
            ("job", "k8s/batch.yaml", "apiVersion: batch/v1\nkind: Job\n"),
            ("latest", "k8s/deploy.yaml", "image: example/app:latest\n"),
        )
        for name, path, content in cases:
            with self.subTest(rule=name), tempfile.TemporaryDirectory(
                prefix="hook-composition-"
            ) as directory:
                result = run_hook(
                    ORG_HOOK, multiedit_payload(content, path), Path(directory)
                )
                self.assertTrue(denied(result))

    def test_both_hooks_deny_one_credential_and_record_separately(self):
        payload = write_payload("stored value: " + token(seed=3))
        with tempfile.TemporaryDirectory(prefix="hook-composition-") as directory:
            state_home = Path(directory)
            org_result = run_hook(ORG_HOOK, payload, state_home)
            credential_result = run_hook(CREDENTIAL_HOOK, payload, state_home)

            self.assertTrue(denied(org_result))
            self.assertTrue(denied(credential_result))
            org_log = state_home / "state" / "org-rule-guard" / "denials.jsonl"
            credential_log = state_home / "state" / "credential-guard" / "denials.jsonl"
            with org_log.open(encoding="utf-8") as handle:
                org_records = [json.loads(line) for line in handle if line.strip()]
            with credential_log.open(encoding="utf-8") as handle:
                credential_records = [json.loads(line) for line in handle if line.strip()]
            self.assertEqual([record["rule_id"] for record in org_records], [
                "credential-value",
            ])
            self.assertEqual([record["rule_id"] for record in credential_records], [
                "credential-value",
            ])
            self.assertEqual(credential_records[0]["payload_shape"], "Write.content")
            self.assertNotIn("stored value: " + token(seed=3), credential_log.read_text())

    def test_optional_companion_does_not_change_org_standalone_coverage(self):
        payload = write_payload(
            "apiVersion: batch/v1\n" + "kind" + ": " + "Job\n",
            path="k8s/batch.yaml",
        )
        with tempfile.TemporaryDirectory(prefix="hook-composition-") as directory:
            result = run_hook(ORG_HOOK, payload, Path(directory))
            self.assertTrue(denied(result))

    def test_non_credential_org_denial_is_not_duplicated_by_companion(self):
        payload = write_payload(
            "apiVersion: batch/v1\n" + "kind" + ": " + "CronJob\n",
            path="k8s/batch.yaml",
        )
        with tempfile.TemporaryDirectory(prefix="hook-composition-") as directory:
            state_home = Path(directory)
            org_result = run_hook(ORG_HOOK, payload, state_home)
            credential_result = run_hook(CREDENTIAL_HOOK, payload, state_home)

            self.assertTrue(denied(org_result))
            self.assertIsNone(credential_result)
            with (state_home / "state" / "org-rule-guard" / "denials.jsonl").open(
                encoding="utf-8"
            ) as handle:
                records = [json.loads(line) for line in handle if line.strip()]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["rule_id"], "k8s-job-cronjob")

    def test_order_does_not_change_the_composed_decision(self):
        payloads = {
            "allow": write_payload("The secret path is secret/apps/demo/key."),
            "credential": write_payload("value: " + token(seed=8)),
            "org": write_payload(
                "apiVersion: batch/v1\n" + "kind" + ": " + "Job\n",
                path="k8s/batch.yaml",
            ),
        }
        for name, payload in payloads.items():
            with self.subTest(payload=name), tempfile.TemporaryDirectory(
                prefix="hook-composition-"
            ) as directory:
                state_home = Path(directory)
                first = {
                    "org": run_hook(ORG_HOOK, payload, state_home),
                    "credential": run_hook(CREDENTIAL_HOOK, payload, state_home),
                }
                second = {
                    "credential": run_hook(CREDENTIAL_HOOK, payload, state_home),
                    "org": run_hook(ORG_HOOK, payload, state_home),
                }
                self.assertEqual(
                    {name: denied(result) for name, result in first.items()},
                    {name: denied(result) for name, result in second.items()},
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
