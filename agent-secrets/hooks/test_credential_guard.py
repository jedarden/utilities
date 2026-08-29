#!/usr/bin/env python3
"""Tests for credential-guard.py.

Every credential-shaped fixture is BUILT at runtime from pieces, so this file
never contains a token-shaped literal -- which matters, because the guard
under test is usually installed on the machine editing this file, and it
would (correctly) refuse to write a real-looking token into it.

Run:  python3 -m unittest discover -s agent-secrets/hooks -v
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.path.join(HERE, "credential-guard.py")

spec = importlib.util.spec_from_file_location("credential_guard", HOOK)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def alnum(n, seed=0):
    """A deterministic, non-repeating alphanumeric body of length n."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(alphabet[(i * 7 + seed) % len(alphabet)] for i in range(n))


def token(prefix, n=40, seed=0):
    return prefix + alnum(n, seed)


PEM_HEADER = "-----BEGIN " + "PRIVATE KEY-----"


def run_hook(payload, env=None):
    """Run the hook as Claude Code would: JSON on stdin, decision on stdout."""
    e = dict(os.environ)
    e["XDG_CONFIG_HOME"] = tempfile.mkdtemp()   # never pick up the user's extras
    if env:
        e.update(env)
    proc = subprocess.run(
        [sys.executable, HOOK], input=json.dumps(payload).encode(),
        capture_output=True, env=e, timeout=20,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    out = proc.stdout.decode().strip()
    return json.loads(out) if out else None


def denied(result):
    return bool(result) and result["hookSpecificOutput"]["permissionDecision"] == "deny"


class FindCredential(unittest.TestCase):
    """The pure matcher."""

    def test_github_token_denied(self):
        hit = guard.find_credential("token: " + token("ghp_"))
        self.assertEqual(hit[0], "GitHub token")

    def test_every_builtin_prefix_denies_a_real_shape(self):
        samples = {
            "GitHub token": token("gho_", 36),
            "GitHub fine-grained PAT": token("github_pat_", 60),
            "GitLab token": token("glpat-", 24),
            "npm token": token("npm_", 36),
            "AWS access key id": "AKIA" + "".join("ABCDEFGHJKLMNPQRSTUVWXYZ2345"[(i * 3) % 28] for i in range(16)),
            "Google API key": "AIza" + alnum(35),
            "Slack token": token("xoxb-", 30),
            "Stripe live key": token("sk_live_", 28),
            "Anthropic API key": token("sk-ant-", 48),
            "OpenAI API key": token("sk-proj-", 48),
            "Vault/OpenBao token": token("hvs.", 28),
        }
        for label, sample in samples.items():
            with self.subTest(label=label):
                hit = guard.find_credential("x = " + sample)
                self.assertIsNotNone(hit, sample)
                self.assertEqual(hit[0], label)

    def test_pem_header_without_placeholder_body_denied(self):
        body = PEM_HEADER + "\n" + alnum(64) + "\n" + alnum(64, 3) + "\n"
        self.assertEqual(guard.find_credential(body)[0], "PEM private key header")

    def test_pem_template_with_placeholder_body_allowed(self):
        body = PEM_HEADER + "\nYOUR_PRIVATE_KEY_HERE\n-----END PRIVATE KEY-----\n"
        self.assertIsNone(guard.find_credential(body))

    def test_repeated_character_body_is_placeholder(self):
        self.assertIsNone(guard.find_credential("GITHUB_TOKEN=ghp_" + "x" * 40))
        self.assertIsNone(guard.find_credential("key: sk-ant-" + "0" * 40))

    def test_placeholder_word_in_value_allowed(self):
        self.assertIsNone(guard.find_credential("ghp_" + "REPLACEME" + alnum(31)))

    def test_prose_naming_a_token_type_allowed(self):
        self.assertIsNone(guard.find_credential(
            "Rotate the ghp_ token, then store the new sk-ant- key by reference."))

    def test_short_body_below_floor_allowed(self):
        self.assertIsNone(guard.find_credential("ghp_" + alnum(12)))

    def test_gitleaks_allow_marker_on_the_line(self):
        body = "fixture = " + token("ghp_") + "  # gitleaks:allow\n"
        self.assertIsNone(guard.find_credential(body))

    def test_gitleaks_allow_on_a_different_line_does_not_excuse(self):
        body = "# gitleaks:allow\nfixture = " + token("ghp_") + "\n"
        self.assertIsNotNone(guard.find_credential(body))

    def test_extra_patterns_file(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "credential-guard"))
        with open(os.path.join(d, "credential-guard", "patterns.json"), "w") as fh:
            json.dump([{"label": "Acme key", "pattern": r"\bacme_[a-z0-9]{32}"}], fh)
        pats = guard.load_patterns(os.path.join(d, "credential-guard", "patterns.json"))
        hit = guard.find_credential("k=acme_" + alnum(32).lower(), pats)
        self.assertEqual(hit[0], "Acme key")

    def test_malformed_extra_patterns_ignored(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "patterns.json")
        with open(p, "w") as fh:
            fh.write("{not json")
        self.assertEqual(len(guard.load_patterns(p)), len(guard.BUILTIN_PATTERNS))


class HookProcess(unittest.TestCase):
    """End to end, through stdin/stdout, as the harness invokes it."""

    def test_write_with_token_denied(self):
        r = run_hook({"tool_name": "Write", "tool_input": {
            "file_path": "/tmp/notes.md",
            "content": "how to fetch it: " + token("gho_", 36)}})
        self.assertTrue(denied(r))
        self.assertIn("BY REFERENCE", r["hookSpecificOutput"]["permissionDecisionReason"])

    def test_edit_new_string_denied(self):
        r = run_hook({"tool_name": "Edit", "tool_input": {
            "file_path": "/tmp/a.py", "old_string": "x",
            "new_string": "KEY = '" + token("sk-ant-", 48) + "'"}})
        self.assertTrue(denied(r))

    def test_multiedit_edits_array_denied(self):
        r = run_hook({"tool_name": "MultiEdit", "tool_input": {
            "file_path": "/tmp/a.py",
            "edits": [{"old_string": "a", "new_string": "b"},
                      {"old_string": "c", "new_string": token("npm_", 36)}]}})
        self.assertTrue(denied(r))

    def test_bash_command_with_token_denied(self):
        r = run_hook({"tool_name": "Bash", "tool_input": {
            "command": "curl -H 'Authorization: Bearer " + token("ghp_") + "' https://api.example"}})
        self.assertTrue(denied(r))

    def test_bash_by_reference_allowed(self):
        r = run_hook({"tool_name": "Bash", "tool_input": {
            "command": "openssl rand -base64 32 | bao kv put secret/app/db password=-"}})
        self.assertIsNone(r)

    def test_write_placeholder_allowed(self):
        r = run_hook({"tool_name": "Write", "tool_input": {
            "file_path": "/tmp/README.md",
            "content": "export GITHUB_TOKEN=ghp_" + "x" * 40}})
        self.assertIsNone(r)

    def test_malformed_json_fails_open(self):
        proc = subprocess.run([sys.executable, HOOK], input=b"{not json",
                              capture_output=True, timeout=20)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), b"")

    def test_non_dict_payload_fails_open(self):
        self.assertIsNone(run_hook(["list", "not", "dict"]))

    def test_unknown_tool_without_fields_allowed(self):
        self.assertIsNone(run_hook({"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}}))


if __name__ == "__main__":
    unittest.main()
