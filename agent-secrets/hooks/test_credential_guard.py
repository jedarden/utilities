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
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.environ.get("CREDENTIAL_GUARD_UNDER_TEST") or os.path.join(HERE, "credential-guard.py")

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
        proc = subprocess.run(["bash", self.script, *args], capture_output=True,
                              env=self.env, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        return proc.stdout.decode()

    def hook_dst(self):
        return os.path.join(self.hooks_dir, "credential-guard.py")

    def bin_dst(self):
        return os.path.join(self.bin_dir, "bao-as")

    def conf(self):
        return os.path.join(self.conf_dir, "instances.conf")

    def read(self, path):
        with open(path) as fh:
            return fh.read()

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
        self.assertEqual(entries[0]["matcher"], "Write|Edit|MultiEdit|Bash")
        self.assertEqual(entries[0]["hooks"][0]["command"],
                         "python3 %s" % self.hook_dst())

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
        self.assertEqual(entries[1]["matcher"], "Write|Edit|MultiEdit|Bash")

    def test_uninstall_removes_the_copies_and_leaves_settings_and_config(self):
        """settings.json keeps its wiring and the config directory keeps the
        operator's instance table: an uninstaller that removed credential
        material would destroy live AppRole secrets."""
        self.run_install("--wire")
        out = self.run_install("--uninstall")
        self.assertFalse(os.path.exists(self.hook_dst()), out)
        self.assertFalse(os.path.exists(self.bin_dst()), out)
        self.assertTrue(os.path.exists(self.settings), out)
        self.assertTrue(os.path.exists(self.conf()), out)

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

