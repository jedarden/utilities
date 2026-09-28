#!/usr/bin/env python3
"""Tests for credential-guard.py.

The suite runs against whichever hook file CREDENTIAL_GUARD_UNDER_TEST names,
defaulting to the copy beside this file -- so the same fixtures are what
proves an installed copy is the real guard:

    python3 -m unittest discover -s agent-secrets/hooks -v
    CREDENTIAL_GUARD_UNDER_TEST=~/.claude/hooks/credential-guard.py \
      python3 -m unittest discover -s agent-secrets/hooks -v

Every credential-shaped fixture is BUILT at runtime from pieces, so this file
never contains a token-shaped literal -- which matters, because the guard
under test is usually installed on the machine editing this file, and it
would (correctly) refuse to write a real-looking token into it.
"""
import importlib.util
import inspect
import json
import os
import re
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.environ.get("CREDENTIAL_GUARD_UNDER_TEST") or os.path.join(HERE, "credential-guard.py")
PATTERN_DOC = os.path.join(HERE, os.pardir, "docs", "credential-patterns.md")

_CLEANUP = []


def tearDownModule():
    for d in _CLEANUP:
        shutil.rmtree(d, ignore_errors=True)


spec = importlib.util.spec_from_file_location("credential_guard", HOOK)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def alnum(n, seed=0):
    """A deterministic, non-repeating alphanumeric body of length n."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(alphabet[(i * 7 + seed) % len(alphabet)] for i in range(n))


def token(prefix, n=40, seed=0):
    return prefix + alnum(n, seed)


def placeholder(prefix, n=40):
    marker = "REPLACE"
    return prefix + marker + alnum(n - len(marker))


PEM_HEADER = "-----BEGIN " + "PRIVATE KEY-----"


def run_hook_process(payload, env=None):
    """Run the hook as Claude Code would and return its completed process."""
    e = dict(os.environ)
    config_home = tempfile.mkdtemp()
    state_home = tempfile.mkdtemp()
    _CLEANUP.extend((config_home, state_home))
    e["XDG_CONFIG_HOME"] = config_home   # never pick up the user's extras
    e["XDG_STATE_HOME"] = state_home     # never write the operator's log
    if env:
        e.update(env)
    return subprocess.run(
        [sys.executable, HOOK], input=json.dumps(payload).encode(),
        capture_output=True, env=e, timeout=20,
    )


def run_hook(payload, env=None):
    """Run the hook as Claude Code would: JSON on stdin, decision on stdout."""
    proc = run_hook_process(payload, env)
    assert proc.returncode == 0, proc.stderr.decode()
    out = proc.stdout.decode().strip()
    return json.loads(out) if out else None


def denied(result):
    return bool(result) and result["hookSpecificOutput"]["permissionDecision"] == "deny"


def _documented_table_rows(table_header):
    """Read the code-valued rows in one table from the pattern inventory."""
    with open(PATTERN_DOC, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    try:
        header = lines.index(table_header)
    except ValueError as error:
        raise AssertionError(
            f"credential pattern inventory is missing table {table_header!r}"
        ) from error

    row = re.compile(
        r"^\|\s*([^|]+?)\s*\|\s*`([^`]+)`\s*(?:\|.*)?$"
    )
    rows = []
    for line in lines[header + 1:]:
        if not line.startswith("|"):
            break
        match = row.fullmatch(line)
        if match:
            rows.append((match.group(1), match.group(2)))
    return rows


def documented_builtin_patterns():
    return _documented_table_rows(
        "| Label | Regex | Minimum shape / context |"
    )


def documented_exemptions():
    return _documented_table_rows(
        "| Exemption | Executable definition |"
    )


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


class DocumentationSync(unittest.TestCase):
    """Keep the human-readable inventory tied to executable matcher rules."""

    def test_documented_builtin_patterns_match_hook(self):
        expected = [
            (label, pattern)
            for label, pattern, _window in guard.BUILTIN_PATTERNS
        ]
        self.assertEqual(documented_builtin_patterns(), expected)

    def test_documented_exemptions_match_hook(self):
        documented = documented_exemptions()
        self.assertEqual(
            [label for label, _definition in documented],
            [
                "Placeholder regex",
                "Repeated-character body",
                "Fixture line marker",
            ],
        )
        definitions = dict(documented)
        self.assertEqual(definitions["Placeholder regex"], guard.PLACEHOLDER.pattern)
        self.assertIn(
            definitions["Repeated-character body"],
            inspect.getsource(guard.is_placeholder),
        )
        self.assertEqual(
            definitions["Fixture line marker"], guard.GITLEAKS_ALLOW_MARKER
        )


class HookProcess(unittest.TestCase):
    """End to end, through stdin/stdout, as the harness invokes it."""

    def test_high_signal_credentials_denied_for_every_supported_tool(self):
        aws_key = "AKIA" + "ABCDEFGHJKLMNPQRSTUVWXYZ2345"[:16]
        cases = (
            ("Write", {"file_path": "/tmp/notes.md",
                        "content": "token = " + token("ghp_", 40)},
             "GitHub token"),
            ("Edit", {"file_path": "/tmp/config.py", "old_string": "x",
                       "new_string": "token = " + token("glpat-", 24)},
             "GitLab token"),
            ("MultiEdit", {"file_path": "/tmp/config.py", "edits": [
                {"old_string": "x", "new_string": "access_key = " + aws_key}]},
             "AWS access key id"),
            ("NotebookEdit", {"notebook_path": "/tmp/analysis.ipynb",
                               "cell_id": "cell-1", "new_source":
                               "token = " + token("github_pat_", 60)},
             "GitHub fine-grained PAT"),
            ("Bash", {"command": "bao kv put secret/app token="
                      + token("hvs.", 28)},
             "Vault/OpenBao token"),
        )
        for tool, tool_input, label in cases:
            with self.subTest(tool=tool):
                result = run_hook({"tool_name": tool, "tool_input": tool_input})
                self.assertTrue(denied(result))
                self.assertIn(label,
                              result["hookSpecificOutput"][
                                  "permissionDecisionReason"])

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

    def test_notebook_edit_new_source_denied(self):
        r = run_hook({"tool_name": "NotebookEdit", "tool_input": {
            "notebook_path": "/tmp/analysis.ipynb", "cell_id": "cell-1",
            "new_source": "KEY = '" + token("sk-ant-", 48) + "'"}})
        self.assertTrue(denied(r))

    def test_bash_command_with_token_denied(self):
        r = run_hook({"tool_name": "Bash", "tool_input": {
            "command": "curl -H 'Authorization: Bearer " + token("ghp_") + "' https://api.example"}})
        self.assertTrue(denied(r))

    def test_denial_log_redacts_payload_for_each_supported_tool(self):
        write_secret = token("ghp_")
        edit_secret = token("glpat-", 24)
        multiedit_secret = token("npm_", 36)
        notebook_secret = token("github_pat_", 60)
        bash_secret = token("hvs.", 28)
        cases = (
            ("Write", {
                "file_path": "/tmp/write-payload-path-marker",
                "content": "write-payload-before-" + write_secret
                           + "-write-payload-after",
            }, "Write.content", write_secret),
            ("Edit", {
                "file_path": "/tmp/edit-payload-path-marker",
                "old_string": "edit-old-payload-marker",
                "new_string": "edit-payload-before-" + edit_secret
                              + "-edit-payload-after",
            }, "Edit.new_string", edit_secret),
            ("MultiEdit", {
                "file_path": "/tmp/multiedit-payload-path-marker",
                "edits": [{
                    "old_string": "multiedit-old-payload-marker",
                    "new_string": "multiedit-payload-before-"
                                  + multiedit_secret
                                  + "-multiedit-payload-after",
                }],
            }, "MultiEdit.edits[].new_string", multiedit_secret),
            ("NotebookEdit", {
                "notebook_path": "/tmp/notebook-payload-path-marker.ipynb",
                "cell_id": "cell-1",
                "new_source": "notebook-payload-before-"
                              + notebook_secret
                              + "-notebook-payload-after",
            }, "NotebookEdit.new_source", notebook_secret),
            ("Bash", {
                "command": "printf '%s' 'bash-command-before-"
                           + bash_secret
                           + "-bash-command-after'",
                "description": "bash-command-metadata-marker",
            }, "Bash.command", bash_secret),
        )
        for tool, tool_input, shape, secret in cases:
            with self.subTest(tool=tool):
                state = tempfile.mkdtemp(prefix="credential-guard-log-")
                _CLEANUP.append(state)
                result = run_hook({
                    "tool_name": tool,
                    "tool_input": tool_input,
                    "cwd": "/tmp/credential-guard-test",
                    "session_id": "session-property-only",
                }, {"CREDENTIAL_GUARD_STATE_DIR": state})
                self.assertTrue(denied(result))
                log_path = os.path.join(state, "denials.jsonl")
                with open(log_path, encoding="utf-8") as fh:
                    serialized = fh.read()
                records = [json.loads(line) for line in serialized.splitlines()]
                self.assertEqual(len(records), 1)
                self.assertEqual(set(records[0]), {
                    "ts", "rule_id", "tool", "cwd", "session_id", "payload_shape",
                })
                record = records[0]
                self.assertEqual(record["rule_id"], "credential-value")
                self.assertEqual(record["tool"], tool)
                self.assertEqual(record["payload_shape"], shape)
                self.assertEqual(record["cwd"], "/tmp/credential-guard-test")
                self.assertEqual(record["session_id"], "session-property-only")

                self.assertNotIn(secret, serialized)
                for key, value in tool_input.items():
                    if isinstance(value, str):
                        self.assertNotIn(value, serialized, key)
                for edit in tool_input.get("edits", []):
                    for value in edit.values():
                        if isinstance(value, str):
                            self.assertNotIn(value, serialized)

    def test_fresh_denial_log_and_directory_are_private(self):
        """Creation modes must protect metadata even with a permissive umask."""
        state_home = tempfile.mkdtemp(prefix="credential-guard-mode-")
        _CLEANUP.append(state_home)
        payload = {"tool_name": "Bash", "tool_input": {
            "command": "printf '%s' '" + token("ghp_") + "'"}}
        previous_umask = os.umask(0)
        try:
            result = run_hook(payload, {"XDG_STATE_HOME": state_home})
        finally:
            os.umask(previous_umask)

        self.assertTrue(denied(result))
        log_dir = os.path.join(state_home, "credential-guard")
        log_path = os.path.join(log_dir, guard.LOG_NAME)
        self.assertEqual(stat.S_IMODE(os.stat(log_dir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(log_path).st_mode), 0o600)

    def test_concurrent_denials_append_complete_jsonl_records(self):
        count = 32
        state_home = tempfile.mkdtemp(prefix="credential-guard-concurrent-")
        config_home = tempfile.mkdtemp(prefix="credential-guard-concurrent-config-")
        _CLEANUP.extend((state_home, config_home))
        env = dict(os.environ,
                   XDG_STATE_HOME=state_home,
                   XDG_CONFIG_HOME=config_home)
        payloads = [
            {"tool_name": "Bash", "tool_input": {
                "command": "printf '%s' '" + token("ghp_", 40, seed=index) + "'",
            }, "cwd": "/repo/concurrent", "session_id":
                "credential-concurrent-" + str(index)}
            for index in range(count)
        ]
        processes = [
            subprocess.Popen(
                [sys.executable, HOOK], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            for _payload in payloads
        ]

        def finish(item):
            process, payload = item
            stdout, stderr = process.communicate(
                input=json.dumps(payload).encode(), timeout=20)
            return process.returncode, stdout, stderr

        with ThreadPoolExecutor(max_workers=count) as pool:
            results = list(pool.map(finish, zip(processes, payloads)))

        for returncode, stdout, stderr in results:
            self.assertEqual(returncode, 0, stderr.decode())
            self.assertEqual(stderr, b"")
            self.assertTrue(denied(json.loads(stdout.decode())))

        log_path = os.path.join(state_home, "credential-guard", guard.LOG_NAME)
        with open(log_path, "rb") as handle:
            lines = handle.readlines()
        self.assertEqual(len(lines), count)
        self.assertTrue(all(line.endswith(b"\n") for line in lines))
        records = [json.loads(line) for line in lines]
        self.assertEqual(
            {record["session_id"] for record in records},
            {payload["session_id"] for payload in payloads},
        )

    def test_allow_writes_no_denial_record(self):
        state = tempfile.mkdtemp(prefix="credential-guard-allow-")
        _CLEANUP.append(state)
        result = run_hook({"tool_name": "Write", "tool_input": {
            "file_path": "/tmp/notes.md", "content": "ordinary documentation"}},
            {"CREDENTIAL_GUARD_STATE_DIR": state})
        self.assertIsNone(result)
        self.assertFalse(os.path.exists(os.path.join(state, "denials.jsonl")))

    def test_failed_log_persistence_preserves_deny_without_exposing_value(self):
        secret = token("ghp_")
        payload = {"tool_name": "Bash", "tool_input": {
            "command": "printf '%s' '" + secret + "'"}}

        healthy_state = tempfile.mkdtemp(prefix="credential-guard-log-healthy-")
        _CLEANUP.append(healthy_state)
        expected = run_hook_process(payload, {
            "CREDENTIAL_GUARD_STATE_DIR": healthy_state,
        })
        self.assertEqual(expected.returncode, 0, expected.stderr.decode())
        expected_result = json.loads(expected.stdout.decode())
        self.assertTrue(denied(expected_result))

        unavailable_parent = tempfile.mkdtemp(
            prefix="credential-guard-log-unavailable-")
        _CLEANUP.append(unavailable_parent)
        unavailable_marker = os.path.join(unavailable_parent, "not-a-directory")
        with open(unavailable_marker, "w", encoding="utf-8") as fh:
            fh.write("operator data")

        unwritable_state = tempfile.mkdtemp(
            prefix="credential-guard-log-unwritable-")
        _CLEANUP.append(unwritable_state)
        os.symlink("/dev/full", os.path.join(unwritable_state, guard.LOG_NAME))

        malformed_parent = tempfile.mkdtemp(
            prefix="credential-guard-log-malformed-")
        _CLEANUP.append(malformed_parent)
        malformed_state = os.path.join(malformed_parent, "not-a-directory")
        with open(malformed_state, "w", encoding="utf-8") as fh:
            fh.write("operator data")

        destinations = (
            ("unavailable", os.path.join(unavailable_marker, "state")),
            ("unwritable", unwritable_state),
            ("malformed", malformed_state),
        )
        for label, destination in destinations:
            with self.subTest(destination=label):
                failed = run_hook_process(payload, {
                    "CREDENTIAL_GUARD_STATE_DIR": destination,
                })
                self.assertEqual(failed.returncode, 0,
                                 failed.stderr.decode())
                self.assertEqual(failed.stderr, b"")
                result = json.loads(failed.stdout.decode())
                self.assertEqual(result, expected_result)
                self.assertNotIn(secret, failed.stdout.decode())
                self.assertNotIn(secret, failed.stderr.decode())

    def test_bash_by_reference_allowed(self):
        r = run_hook({"tool_name": "Bash", "tool_input": {
            "command": "openssl rand -base64 32 | bao kv put secret/app/db password=-"}})
        self.assertIsNone(r)

    def test_write_placeholder_allowed(self):
        r = run_hook({"tool_name": "Write", "tool_input": {
            "file_path": "/tmp/README.md",
            "content": "export GITHUB_TOKEN=ghp_" + "x" * 40}})
        self.assertIsNone(r)

    def test_placeholder_values_allowed_for_every_supported_tool(self):
        cases = (
            ("Write", {"file_path": "/tmp/README.md",
                       "content": "export GITHUB_TOKEN=" + placeholder("ghp_", 40)}),
            ("Edit", {"file_path": "/tmp/config.py", "old_string": "x",
                      "new_string": "KEY = '" + placeholder("sk-ant-", 48) + "'"}),
            ("MultiEdit", {"file_path": "/tmp/config.py", "edits": [
                {"old_string": "x", "new_string": placeholder("npm_", 36)}]}),
            ("NotebookEdit", {"notebook_path": "/tmp/notes.ipynb",
                               "cell_id": "cell-1",
                               "new_source": placeholder("ghp_", 40)}),
            ("Bash", {"command": "curl -H 'Authorization: Bearer "
                       + placeholder("ghp_", 40) + "' https://api.example"}),
        )
        for tool, tool_input in cases:
            with self.subTest(tool=tool):
                self.assertIsNone(run_hook({"tool_name": tool, "tool_input": tool_input}))

    def test_gitleaks_allow_marker_suppresses_denial_for_every_supported_tool(self):
        cases = (
            ("Write", {"file_path": "/tmp/fixture.py",
                       "content": "fixture = " + token("ghp_")
                       + "  # gitleaks:allow"}),
            ("Edit", {"file_path": "/tmp/fixture.py", "old_string": "x",
                      "new_string": "fixture = " + token("sk-ant-", 48)
                      + "  # gitleaks:allow"}),
            ("MultiEdit", {"file_path": "/tmp/fixture.py", "edits": [
                {"old_string": "x", "new_string": "fixture = "
                 + token("npm_", 36) + "  # gitleaks:allow"}]}),
            ("NotebookEdit", {"notebook_path": "/tmp/fixture.ipynb",
                               "cell_id": "cell-1", "new_source":
                               "fixture = " + token("ghp_")
                               + "  # gitleaks:allow"}),
            ("Bash", {"command": "printf '%s\\n' '" + token("ghp_")
                       + "' # gitleaks:allow"}),
        )
        for tool, tool_input in cases:
            with self.subTest(tool=tool):
                self.assertIsNone(run_hook({"tool_name": tool, "tool_input": tool_input}))

    def test_ordinary_non_secret_content_allowed_for_every_supported_tool(self):
        cases = (
            ("Write", {"file_path": "/tmp/notes.md",
                        "content": "Document the deployment checklist."}),
            ("Edit", {"file_path": "/tmp/config.py", "old_string": "x",
                       "new_string": "timeout = 30"}),
            ("MultiEdit", {"file_path": "/tmp/config.py", "edits": [
                {"old_string": "debug = false", "new_string": "debug = true"},
                {"old_string": "port = 80", "new_string": "port = 8080"}]}),
            ("NotebookEdit", {"notebook_path": "/tmp/notes.ipynb",
                               "cell_id": "cell-1", "new_source": "print(42)"}),
            ("Bash", {"command": "printf '%s\\n' 'deployment complete'"}),
        )
        for tool, tool_input in cases:
            with self.subTest(tool=tool):
                self.assertIsNone(run_hook({"tool_name": tool, "tool_input": tool_input}))

    def test_malformed_json_fails_open(self):
        proc = subprocess.run([sys.executable, HOOK], input=b"{not json",
                              capture_output=True, timeout=20)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), b"")

    def test_non_dict_payload_fails_open(self):
        self.assertIsNone(run_hook(["list", "not", "dict"]))

    def test_unexpected_hook_input_fails_open(self):
        cases = (
            {},
            {"tool_name": "Write"},
            {"tool_name": "Write", "tool_input": None},
            {"tool_name": "Write", "tool_input": []},
            {"tool_name": "Write", "tool_input": {"content": ["not", "text"]}},
            {"tool_name": "Edit", "tool_input": {"new_string": {"not": "text"}}},
            {"tool_name": "MultiEdit", "tool_input": {
                "edits": [{"new_string": {"not": "text"}}]}},
            {"tool_name": "NotebookEdit", "tool_input": {
                "new_source": {"not": "text"}}},
            {"tool_name": "Bash", "tool_input": {"command": {"not": "text"}}},
        )
        for payload in cases:
            with self.subTest(payload=payload):
                self.assertIsNone(run_hook(payload))

    def test_unknown_tool_without_fields_allowed(self):
        self.assertIsNone(run_hook({"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}}))

    def test_unknown_tool_with_write_like_field_is_allowed(self):
        self.assertIsNone(run_hook({"tool_name": "FutureWrite", "tool_input": {
            "content": token("ghp_")}}))


class Install(unittest.TestCase):
    """The installer's contract. Runs against a throwaway hooks dir, bin dir,
    settings path and bao-as config dir, so the live hook, the live wrapper
    and the live settings are never touched."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="agent-secrets-install-")
        _CLEANUP.append(self.root)
        self.hooks_dir = os.path.join(self.root, "hooks")
        self.bin_dir = os.path.join(self.root, "bin")
        self.settings = os.path.join(self.root, "settings.json")
        self.conf_dir = os.path.join(self.root, "conf", "bao-as")
        self.script = os.path.join(HERE, os.pardir, "install.sh")
        self.env = dict(os.environ,
                        CLAUDE_HOOKS_DIR=self.hooks_dir,
                        BIN_DIR=self.bin_dir,
                        CLAUDE_SETTINGS=self.settings,
                        BAO_AS_CONFIG_DIR=self.conf_dir)

    def run_install(self, *args):
        proc = self.run_install_raw(*args)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        return proc.stdout.decode()

    def run_install_expect_failure(self, *args):
        proc = self.run_install_raw(*args)
        self.assertNotEqual(proc.returncode, 0, proc.stdout.decode())
        return proc

    def run_install_raw(self, *args, env=None, cwd=None):
        return subprocess.run(["bash", self.script, *args], capture_output=True,
                              env=self.env if env is None else env, cwd=cwd,
                              timeout=30)

    def hook_dst(self):
        return os.path.join(self.hooks_dir, "credential-guard.py")

    def bin_dst(self):
        return os.path.join(self.bin_dir, "bao-as")

    def conf(self):
        return os.path.join(self.conf_dir, "instances.conf")

    def run_concurrent_wires(self, other_script, other_env):
        specs = ((self.script, self.env), (other_script, other_env))
        procs = [subprocess.Popen(["bash", script, "--wire"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env=env)
                 for script, env in specs]
        try:
            results = [proc.communicate(timeout=60) for proc in procs]
        finally:
            for proc in procs:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
        for proc, (stdout, stderr) in zip(procs, results):
            self.assertEqual(proc.returncode, 0,
                             stderr.decode() + stdout.decode())

    def hold_settings_lock(self):
        code = """import fcntl
import os
import sys
import time

fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
print("ready", flush=True)
time.sleep(60)
"""
        proc = subprocess.Popen(
            [sys.executable, "-c", code, self.settings + ".lock"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        ready = proc.stdout.readline().decode().strip()
        proc.stdout.close()
        proc.stderr.close()
        if ready != "ready":
            proc.kill()
            proc.wait()
        self.assertEqual(ready, "ready")
        return proc

    def read(self, path):
        with open(path) as fh:
            return fh.read()

    def settings_temp_files(self, settings, utility):
        directory = os.path.dirname(settings)
        prefix = ".%s.%s." % (os.path.basename(settings), utility)
        return [name for name in os.listdir(directory)
                if name.startswith(prefix) and name.endswith(".tmp")]

    def test_first_install_copies_everything_and_leaves_settings_alone(self):
        out = self.run_install()
        for path in (self.hook_dst(), self.bin_dst(), self.conf()):
            self.assertTrue(os.path.exists(path), out)
        self.assertFalse(os.path.exists(self.settings), out)

    def test_default_destinations_come_from_home(self):
        """With no override env var set, the conventional locations derive
        from $HOME itself -- the contract plan.md states is about
        ~/.claude/hooks/ and ~/.local/bin/, not about the env vars. A temp
        HOME keeps the live destinations out of the picture."""
        home = tempfile.mkdtemp(prefix="agent-secrets-home-")
        _CLEANUP.append(home)
        env = dict(os.environ, HOME=home)
        for var in ("CLAUDE_HOOKS_DIR", "BIN_DIR", "CLAUDE_SETTINGS",
                    "BAO_AS_CONFIG_DIR", "XDG_CONFIG_HOME"):
            env.pop(var, None)
        proc = subprocess.run(["bash", self.script], capture_output=True,
                              env=env, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        out = proc.stdout.decode()
        self.assertTrue(os.path.exists(
            os.path.join(home, ".claude", "hooks", "credential-guard.py")), out)
        self.assertTrue(os.path.exists(
            os.path.join(home, ".local", "bin", "bao-as")), out)
        self.assertTrue(os.path.exists(
            os.path.join(home, ".config", "bao-as", "instances.conf")), out)
        self.assertFalse(os.path.exists(
            os.path.join(home, ".claude", "settings.json")), out)

    def test_modes_are_executable_code_and_private_credentials(self):
        """The hook and the wrapper are world-executable; the bao-as config
        directory and the instance table it seeds are private -- 0700 and
        0600, matching the modes bao-as itself re-enforces at runtime."""
        self.run_install()
        self.assertTrue(os.stat(self.hook_dst()).st_mode & stat.S_IXUSR)
        self.assertTrue(os.stat(self.bin_dst()).st_mode & stat.S_IXUSR)
        self.assertEqual(stat.S_IMODE(os.stat(self.conf_dir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.conf()).st_mode), 0o600)

    def test_instances_conf_is_seeded_once_and_never_rewritten(self):
        """The table is the operator's data, not code: even --force replaces
        only the hook and the wrapper, never the file that points bao-as at
        its instances."""
        self.run_install()
        with open(self.conf(), "a") as fh:
            fh.write("local-only   https://bao.internal\n")
        out = self.run_install("--force")
        self.assertIn("local-only", self.read(self.conf()), out)

    def test_rerun_is_a_noop(self):
        """Idempotent means a bare re-run changes nothing and fails nothing:
        identical bytes everywhere, settings still unwritten."""
        self.run_install()
        before = {p: self.read(p)
                  for p in (self.hook_dst(), self.bin_dst(), self.conf())}
        out = self.run_install()
        self.assertEqual({p: self.read(p) for p in before}, before, out)
        self.assertIn("not overwritten", out)
        self.assertFalse(os.path.exists(self.settings), out)

    def test_locally_edited_copies_survive_a_plain_rerun(self):
        self.run_install()
        for path in (self.hook_dst(), self.bin_dst()):
            with open(path, "a") as fh:
                fh.write("\n# local edit\n")
        before = {p: self.read(p) for p in (self.hook_dst(), self.bin_dst())}
        out = self.run_install()
        self.assertEqual({p: self.read(p) for p in before}, before, out)
        self.assertIn("not overwritten", out)
        self.assertFalse(os.path.exists(self.settings), out)

    def test_force_overwrites_both_copies_but_still_leaves_settings_alone(self):
        self.run_install()
        for path in (self.hook_dst(), self.bin_dst()):
            with open(path, "a") as fh:
                fh.write("\n# local edit\n")
        out = self.run_install("--force")
        for path in (self.hook_dst(), self.bin_dst()):
            self.assertNotIn("# local edit", self.read(path), out)
        self.assertFalse(os.path.exists(self.settings), out)

    def test_wire_installs_and_writes_the_settings_entry(self):
        out = self.run_install("--wire")
        self.assertIn("wired", out)
        with open(self.settings) as fh:
            s = json.load(fh)
        entries = s["hooks"]["PreToolUse"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["matcher"], "Write|Edit|MultiEdit|NotebookEdit|Bash")
        self.assertEqual(entries[0]["hooks"][0]["command"],
                         "python3 %s" % self.hook_dst())
        self.assertFalse(os.path.exists(self.settings + ".bak"), out)

    def test_wire_refreshes_the_previous_shipped_matcher_in_place(self):
        command = "python3 %s" % self.hook_dst()
        with open(self.settings, "w") as fh:
            json.dump({"hooks": {"PreToolUse": [{
                "matcher": "Write|Edit|MultiEdit|Bash",
                "hooks": [{"type": "command", "command": command}],
            }]}}, fh)

        out = self.run_install("--wire")

        with open(self.settings) as fh:
            entry = json.load(fh)["hooks"]["PreToolUse"][0]
        self.assertEqual(entry["matcher"], "Write|Edit|MultiEdit|NotebookEdit|Bash")
        self.assertIn("refreshed", out)

    def test_wire_creates_a_private_persistent_lock_file(self):
        previous_umask = os.umask(0)
        try:
            self.run_install("--wire")
        finally:
            os.umask(previous_umask)

        lock_path = self.settings + ".lock"
        self.assertTrue(os.path.exists(lock_path))
        self.assertEqual(stat.S_IMODE(os.stat(lock_path).st_mode), 0o600)

    def test_wire_recovers_after_the_previous_lock_holder_dies(self):
        holder = self.hold_settings_lock()
        try:
            holder.kill()
            holder.wait(timeout=10)
            out = self.run_install("--wire")
        finally:
            if holder.poll() is None:
                holder.kill()
                holder.wait()
        self.assertIn("wired", out)
        self.assertTrue(os.path.exists(self.settings + ".lock"), out)

    def test_wire_times_out_when_the_settings_lock_is_held(self):
        original = b'{"model": "keep"}\n'
        with open(self.settings, "wb") as fh:
            fh.write(original)
        holder = self.hold_settings_lock()
        try:
            env = dict(self.env, CLAUDE_SETTINGS_LOCK_TIMEOUT="0.2")
            result = self.run_install_raw("--wire", env=env)
        finally:
            if holder.poll() is None:
                holder.kill()
            holder.wait()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not acquire settings lock", result.stderr.decode())
        self.assertIn("within 0.2 seconds", result.stderr.decode())
        with open(self.settings, "rb") as fh:
            self.assertEqual(fh.read(), original)

    def test_wire_fails_cleanly_when_the_lock_path_cannot_be_opened(self):
        os.mkdir(self.settings + ".lock")

        result = self.run_install_raw("--wire")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not create settings lock", result.stderr.decode())
        self.assertFalse(os.path.exists(self.settings))

    def test_wire_preserves_a_user_modified_entry(self):
        custom = {
            "hooks": {"PreToolUse": [{
                "matcher": "Write|Edit",
                "description": "operator policy",
                "hooks": [{
                    "type": "command",
                    "command": "python3 %s" % self.hook_dst(),
                    "timeout": 5,
                }],
            }]},
        }
        with open(self.settings, "w") as fh:
            json.dump(custom, fh)

        result = self.run_install_raw("--wire")

        self.assertEqual(result.returncode, 2, result.stderr.decode())
        with open(self.settings) as fh:
            self.assertEqual(json.load(fh), custom)
        self.assertIn("customized", result.stderr.decode())
        self.assertIn("(exit 2)", result.stderr.decode())
        self.assertFalse(os.path.exists(self.settings + ".bak"))

    def test_wire_force_refreshes_a_user_modified_entry(self):
        custom = {
            "hooks": {"PreToolUse": [{
                "matcher": "Write|Edit",
                "description": "operator policy",
                "hooks": [{
                    "type": "command",
                    "command": "python3 %s" % self.hook_dst(),
                    "timeout": 5,
                }],
            }]},
        }
        with open(self.settings, "w") as fh:
            json.dump(custom, fh)

        result = self.run_install_raw("--wire", "--force")

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        with open(self.settings) as fh:
            entry = json.load(fh)["hooks"]["PreToolUse"][0]
        self.assertEqual(entry["matcher"], "Write|Edit|MultiEdit|NotebookEdit|Bash")
        self.assertNotIn("timeout", entry["hooks"][0])
        self.assertEqual(entry["description"], "operator policy")
        self.assertIn("refreshed", result.stdout.decode())

    def test_wire_rejects_a_nonexistent_settings_parent(self):
        settings = os.path.join(self.root, "missing", "settings.json")
        env = dict(self.env, CLAUDE_SETTINGS=settings)

        proc = self.run_install_raw("--wire", env=env)

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("settings parent directory does not exist",
                      proc.stderr.decode())
        self.assertFalse(os.path.exists(os.path.dirname(settings)))
        self.assertFalse(os.path.exists(settings))

    def test_wire_resolves_a_relative_settings_path_from_the_current_directory(self):
        cwd = tempfile.mkdtemp(prefix="agent-secrets-relative-cwd-")
        _CLEANUP.append(cwd)
        relative = os.path.join("settings", "settings.json")
        expected = os.path.join(cwd, relative)
        os.makedirs(os.path.dirname(expected))
        env = dict(self.env, CLAUDE_SETTINGS=relative)

        proc = self.run_install_raw("--wire", env=env, cwd=cwd)

        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        with open(expected) as fh:
            settings = json.load(fh)
        self.assertEqual(
            settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "python3 %s" % self.hook_dst(),
        )
        self.assertFalse(os.path.exists(os.path.join(self.root, relative)))

    def test_wire_follows_a_settings_symlink_without_replacing_it(self):
        target = os.path.join(self.root, "target", "settings.json")
        os.makedirs(os.path.dirname(target))
        original = b'{"model": "opus"}\n'
        with open(target, "wb") as fh:
            fh.write(original)
        link = os.path.join(self.root, "settings-link.json")
        os.symlink(target, link)
        env = dict(self.env, CLAUDE_SETTINGS=link)

        proc = self.run_install_raw("--wire", env=env)

        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertTrue(os.path.islink(link))
        with open(target) as fh:
            settings = json.load(fh)
        self.assertEqual(
            settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "python3 %s" % self.hook_dst(),
        )
        with open(target + ".bak", "rb") as fh:
            self.assertEqual(fh.read(), original)
        self.assertFalse(os.path.exists(link + ".bak"))

    def test_wire_paths_are_independent_when_the_two_utilities_use_different_files(self):
        first = os.path.join(self.root, "first", "settings.json")
        second = os.path.join(self.root, "second", "settings.json")
        for path, model in ((first, "first"), (second, "second")):
            os.makedirs(os.path.dirname(path))
            with open(path, "w") as fh:
                json.dump({"model": model}, fh)

        first_env = dict(self.env, CLAUDE_SETTINGS=first)
        first_result = self.run_install_raw("--wire", env=first_env)
        self.assertEqual(first_result.returncode, 0, first_result.stderr.decode())

        org_script = os.path.join(HERE, os.pardir, os.pardir,
                                  "org-rule-guard", "install.sh")
        second_env = dict(self.env, CLAUDE_SETTINGS=second)
        second_result = subprocess.run(
            ["bash", org_script, "--wire"], capture_output=True,
            env=second_env, timeout=30)
        self.assertEqual(second_result.returncode, 0,
                         second_result.stderr.decode())

        with open(first) as fh:
            first_settings = json.load(fh)
        with open(second) as fh:
            second_settings = json.load(fh)
        first_commands = [entry["hooks"][0]["command"]
                          for entry in first_settings["hooks"]["PreToolUse"]]
        second_commands = [entry["hooks"][0]["command"]
                           for entry in second_settings["hooks"]["PreToolUse"]]
        self.assertEqual(first_commands, ["python3 %s" % self.hook_dst()])
        self.assertEqual(
            second_commands,
            ["python3 %s" % os.path.join(self.hooks_dir, "org-rule-guard.py")],
        )
        with open(first + ".bak") as fh:
            self.assertEqual(json.load(fh), {"model": "first"})
        with open(second + ".bak") as fh:
            self.assertEqual(json.load(fh), {"model": "second"})

    def test_wire_snapshots_existing_settings_before_first_change(self):
        original = b'{"model": "opus", "hooks": {"Stop": []}}\n'
        with open(self.settings, "wb") as fh:
            fh.write(original)
        os.chmod(self.settings, 0o600)

        out = self.run_install("--wire")

        self.assertIn("backup", out)
        with open(self.settings + ".bak", "rb") as fh:
            self.assertEqual(fh.read(), original)
        self.assertEqual(stat.S_IMODE(os.stat(self.settings + ".bak").st_mode),
                         0o600)

    def test_wire_replaces_settings_atomically(self):
        original = b'{"model": "opus"}\n'
        with open(self.settings, "wb") as fh:
            fh.write(original)

        with open(self.settings, "rb") as old_settings:
            old_inode = os.fstat(old_settings.fileno()).st_ino
            out = self.run_install("--wire")
            old_settings.seek(0)
            self.assertEqual(old_settings.read(), original, out)

        self.assertNotEqual(os.stat(self.settings).st_ino, old_inode)
        with open(self.settings) as fh:
            self.assertIsInstance(json.load(fh), dict)
        leftovers = [name for name in os.listdir(os.path.dirname(self.settings))
                     if name.startswith(".settings.json.") and name.endswith(".tmp")]
        self.assertEqual(leftovers, [], out)

    def test_interrupted_wire_preserves_live_settings_and_next_run_reaps_temp(self):
        org_script = os.path.join(HERE, os.pardir, os.pardir,
                                  "org-rule-guard", "install.sh")
        specs = (
            ("agent-secrets", self.script, self.env),
            ("org-rule-guard", org_script, dict(self.env)),
        )
        for utility, script, base_env in specs:
            with self.subTest(utility=utility):
                settings = os.path.join(self.root, utility, "settings.json")
                os.makedirs(os.path.dirname(settings))
                original = json.dumps(
                    {"model": "opus", "padding": "x" * (64 * 1024 * 1024)},
                    indent=2,
                ).encode() + b"\n"
                with open(settings, "wb") as fh:
                    fh.write(original)
                env = dict(base_env, CLAUDE_SETTINGS=settings)
                process = subprocess.Popen(
                    ["bash", script, "--wire"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    start_new_session=True,
                )
                interrupted = False
                try:
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        if self.settings_temp_files(settings, utility):
                            interrupted = True
                            os.killpg(process.pid, signal.SIGKILL)
                            break
                        if process.poll() is not None:
                            break
                        time.sleep(0.001)
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                    stdout, stderr = process.communicate(timeout=10)
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                self.assertTrue(interrupted, stdout.decode() + stderr.decode())
                with open(settings, "rb") as fh:
                    self.assertEqual(fh.read(), original)
                self.assertTrue(self.settings_temp_files(settings, utility))

                result = subprocess.run(
                    ["bash", script, "--wire"],
                    capture_output=True,
                    env=env,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                with open(settings) as fh:
                    completed = json.load(fh)
                self.assertEqual(completed["model"], "opus")
                self.assertEqual(len(completed["padding"]), 64 * 1024 * 1024)
                self.assertEqual(self.settings_temp_files(settings, utility), [])

    def test_wire_preserves_live_settings_permissions_at_mode_0600(self):
        with open(self.settings, "w") as fh:
            json.dump({"model": "opus"}, fh)
        os.chmod(self.settings, 0o600)

        self.run_install("--wire")

        self.assertEqual(stat.S_IMODE(os.stat(self.settings).st_mode), 0o600)

    def test_wire_preserves_live_settings_permissions_at_mode_0644_with_custom_path(self):
        settings = os.path.join(self.root, "custom", "settings.json")
        os.makedirs(os.path.dirname(settings))
        with open(settings, "w") as fh:
            json.dump({"model": "opus"}, fh)
        os.chmod(settings, 0o644)

        env = dict(self.env, CLAUDE_SETTINGS=settings)
        result = self.run_install_raw("--wire", env=env)

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(stat.S_IMODE(os.stat(settings).st_mode), 0o644)

    def test_concurrent_wires_preserve_both_installers_and_settings(self):
        with open(self.settings, "w") as fh:
            json.dump({"model": "opus", "padding": "x" * (4 * 1024 * 1024)}, fh)
        org_script = os.path.join(HERE, os.pardir, os.pardir,
                                  "org-rule-guard", "install.sh")
        self.run_concurrent_wires(org_script, dict(self.env))

        with open(self.settings) as fh:
            settings = json.load(fh)
        commands = [entry["hooks"][0]["command"]
                    for entry in settings["hooks"]["PreToolUse"]]
        self.assertEqual(set(commands), {
            "python3 %s" % self.hook_dst(),
            "python3 %s" % os.path.join(self.hooks_dir, "org-rule-guard.py"),
        })
        self.assertEqual(settings["model"], "opus")
        self.assertEqual(len(settings["padding"]), 4 * 1024 * 1024)

    def assert_malformed_settings_is_untouched(self, original):
        with open(self.settings, "wb") as fh:
            fh.write(original)

        proc = self.run_install_expect_failure("--wire")

        message = proc.stderr.decode()
        self.assertIn("refusing to wire", message)
        self.assertIn("settings file was not modified", message)
        with open(self.settings, "rb") as fh:
            self.assertEqual(fh.read(), original)
        with open(self.settings + ".bak", "rb") as fh:
            self.assertEqual(fh.read(), original)

    def test_wire_refuses_a_truncated_settings_file(self):
        self.assert_malformed_settings_is_untouched(
            b'{"model": "opus", "hooks": '
        )

    def test_wire_refuses_settings_with_a_trailing_comma(self):
        self.assert_malformed_settings_is_untouched(b'{"model": "opus",}\n')

    def test_wire_refuses_a_non_object_settings_root(self):
        self.assert_malformed_settings_is_untouched(b"[]\n")

    def test_wire_preserves_an_existing_settings_backup_on_reruns(self):
        original = b'{"model": "opus"}\n'
        sentinel = b"operator-selected baseline\n"
        with open(self.settings, "wb") as fh:
            fh.write(original)
        with open(self.settings + ".bak", "wb") as fh:
            fh.write(sentinel)

        self.run_install("--wire")
        self.run_install("--wire")

        with open(self.settings + ".bak", "rb") as fh:
            self.assertEqual(fh.read(), sentinel)

    def test_wire_and_uninstall_never_change_an_existing_settings_backup(self):
        original = b'{"model": "opus"}\n'
        sentinel = b"operator-selected baseline\n"
        with open(self.settings, "wb") as fh:
            fh.write(original)
        with open(self.settings + ".bak", "wb") as fh:
            fh.write(sentinel)
        os.chmod(self.settings + ".bak", 0o600)

        self.run_install("--wire")
        self.run_install("--wire")
        self.run_install("--uninstall")

        with open(self.settings + ".bak", "rb") as fh:
            self.assertEqual(fh.read(), sentinel)
        self.assertEqual(stat.S_IMODE(os.stat(self.settings + ".bak").st_mode),
                         0o600)

    def test_wire_replaces_an_existing_hook_copy(self):
        self.run_install()
        with open(self.hook_dst(), "a") as fh:
            fh.write("\n# local edit\n")
        self.run_install("--wire")
        self.assertNotIn("# local edit", self.read(self.hook_dst()))

    def test_wire_is_idempotent(self):
        self.run_install("--wire")
        self.run_install("--wire")
        with open(self.settings) as fh:
            entries = json.load(fh)["hooks"]["PreToolUse"]
        self.assertEqual(len(entries), 1)

    def test_wire_preserves_unrelated_settings(self):
        with open(self.settings, "w") as fh:
            json.dump({"model": "opus", "hooks": {"Stop": [{"hooks": [
                {"type": "command", "command": "/bin/true"}]}]}}, fh)
        self.run_install("--wire")
        with open(self.settings) as fh:
            s = json.load(fh)
        self.assertEqual(s["model"], "opus")
        self.assertEqual(len(s["hooks"]["PreToolUse"]), 1)
        self.assertEqual(len(s["hooks"]["Stop"]), 1)

    def test_wire_keeps_a_preexisting_pretooluse_entry(self):
        """Merging means appending to PreToolUse, not replacing it: another
        hook already wired there must survive the --wire."""
        with open(self.settings, "w") as fh:
            json.dump({"hooks": {"PreToolUse": [{"matcher": "WebFetch", "hooks": [
                {"type": "command", "command": "/bin/true"}]}]}}, fh)
        self.run_install("--wire")
        with open(self.settings) as fh:
            entries = json.load(fh)["hooks"]["PreToolUse"]
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["matcher"], "WebFetch")
        self.assertEqual(entries[1]["matcher"], "Write|Edit|MultiEdit|NotebookEdit|Bash")

    def test_uninstall_removes_the_copies_and_leaves_settings_and_config(self):
        """Uninstall removes install metadata but retains the audit state.

        settings.json keeps its wiring and the config directory keeps the
        operator's instance table: an uninstaller that removed credential
        material would destroy live AppRole secrets. The denial state is also
        retained because its bounded history remains useful after uninstall.
        """
        state_home = os.path.join(self.root, "state")
        state_dir = os.path.join(state_home, "credential-guard")
        os.makedirs(state_dir)
        state_files = {
            "denials.jsonl": b'{"rule_id": "keep-me"}\n',
            "denials.jsonl.1": b'{"rule_id": "older"}\n',
            "denials.jsonl.lock": b"",
        }
        for name, contents in state_files.items():
            with open(os.path.join(state_dir, name), "wb") as handle:
                handle.write(contents)
        self.env.pop("CREDENTIAL_GUARD_STATE_DIR", None)
        self.env["XDG_STATE_HOME"] = state_home

        self.run_install("--wire")
        self.assertTrue(os.path.exists(self.settings + ".lock"))
        provenance = os.path.join(self.hooks_dir, "agent-secrets", "provenance.json")
        self.assertTrue(os.path.exists(provenance))
        out = self.run_install("--uninstall")
        self.assertFalse(os.path.exists(self.hook_dst()), out)
        self.assertFalse(os.path.exists(self.bin_dst()), out)
        self.assertFalse(os.path.exists(provenance), out)
        self.assertFalse(os.path.exists(os.path.dirname(provenance)), out)
        self.assertTrue(os.path.exists(self.settings), out)
        self.assertTrue(os.path.exists(self.conf()), out)
        self.assertFalse(os.path.exists(self.settings + ".lock"), out)
        self.assertTrue(os.path.isdir(state_dir), out)
        for name, contents in state_files.items():
            with open(os.path.join(state_dir, name), "rb") as handle:
                self.assertEqual(handle.read(), contents, name)

    def test_uninstall_refuses_a_file_this_copy_did_not_install(self):
        """A hand-edited copy at a destination is live enforcement this
        folder never wrote -- removing it on sight would take the guard down.
        The refusal is all-or-nothing: a foreign copy anywhere blocks removal
        of every copy, so no half-uninstalled machine is left. --force
        overrides."""
        for target in (self.hook_dst(), self.bin_dst()):
            self.run_install()
            with open(target, "a") as fh:
                fh.write("\n# local edit\n")
            proc = subprocess.run(["bash", self.script, "--uninstall"],
                                  capture_output=True, env=self.env, timeout=30)
            self.assertNotEqual(proc.returncode, 0, proc.stdout.decode())
            self.assertTrue(os.path.exists(self.hook_dst()), proc.stdout.decode())
            self.assertTrue(os.path.exists(self.bin_dst()), proc.stdout.decode())
            self.assertIn("refusing", proc.stderr.decode())
            out = self.run_install("--uninstall", "--force")
            self.assertFalse(os.path.exists(self.hook_dst()), out)
            self.assertFalse(os.path.exists(self.bin_dst()), out)

    def test_installed_hook_passes_the_rule_fixtures(self):
        """What the installer put down is the thing this file tests. Only
        FindCredential and HookProcess run: neither installs anything, so
        re-entering the suite from here cannot recurse (Install would
        re-install, and re-run this test, forever)."""
        self.run_install()
        env = dict(os.environ)
        env["CREDENTIAL_GUARD_UNDER_TEST"] = self.hook_dst()
        env["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="agent-secrets-test-")
        _CLEANUP.append(env["XDG_CONFIG_HOME"])
        proc = subprocess.run(
            [sys.executable, "-m", "unittest",
             "test_credential_guard.FindCredential",
             "test_credential_guard.HookProcess", "-v"],
            capture_output=True, env=env, cwd=HERE, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode() + proc.stdout.decode())


if __name__ == "__main__":
    unittest.main()
