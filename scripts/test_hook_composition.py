#!/usr/bin/env python3
"""Integration tests for the two independent PreToolUse guards.

The guards deliberately remain separate processes. These tests model the
host passing the same payload to both handlers, in either order, and verify
that the optional companion cannot remove org-rule-guard's standalone
credential coverage.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ORG_HOOK = ROOT / "org-rule-guard" / "hooks" / "org-rule-guard.py"
CREDENTIAL_HOOK = ROOT / "agent-secrets" / "hooks" / "credential-guard.py"
COMBINED_SETTINGS = ROOT / "docs" / "examples" / "settings-both.json"


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
    def test_combined_settings_wire_both_independent_handlers(self):
        with COMBINED_SETTINGS.open(encoding="utf-8") as handle:
            settings = json.load(handle)

        entries = settings["hooks"]["PreToolUse"]
        self.assertEqual(len(entries), 2)
        commands = [entry["hooks"][0]["command"] for entry in entries]
        self.assertEqual(commands, [
            "python3 ~/.claude/hooks/org-rule-guard.py",
            "python3 ~/.claude/hooks/credential-guard.py",
        ])
        self.assertEqual(entries[0]["matcher"], "Write|Edit|Bash")
        self.assertEqual(entries[1]["matcher"], "Write|Edit|MultiEdit|Bash")

    def test_both_hooks_deny_one_credential_without_a_runtime_dependency(self):
        payload = write_payload("stored value: " + token(seed=3))
        with tempfile.TemporaryDirectory(prefix="hook-composition-") as directory:
            state_home = Path(directory)
            org_result = run_hook(ORG_HOOK, payload, state_home)
            credential_result = run_hook(CREDENTIAL_HOOK, payload, state_home)

            self.assertTrue(denied(org_result))
            self.assertTrue(denied(credential_result))
            log = state_home / "state" / "org-rule-guard" / "denials.jsonl"
            with log.open(encoding="utf-8") as handle:
                records = [json.loads(line) for line in handle if line.strip()]
            self.assertEqual([record["rule_id"] for record in records], [
                "credential-value",
            ])

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
