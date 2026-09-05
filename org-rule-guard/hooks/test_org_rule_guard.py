#!/usr/bin/env python3
"""Tests for org-rule-guard.py.

The suite runs against whichever hook file ORG_RULE_GUARD_UNDER_TEST names,
defaulting to the ported copy beside this file -- so the same fixtures are
what proves the port matches the live hook:

    python3 -m unittest discover -s org-rule-guard/hooks -v
    ORG_RULE_GUARD_UNDER_TEST=~/.claude/hooks/org-rule-guard.py \
      python3 -m unittest discover -s org-rule-guard/hooks -v

Every rule-triggering fixture is BUILT at runtime from fragments, so no deny
literal appears in this file -- which matters, because the guard under test
is usually installed on the machine editing it and would (correctly) refuse
to write one. The deny-vs-allow pairing is deliberate: each allow is a
near miss for its deny, so a fix that widens a pattern to catch the deny
cannot quietly catch the allow too.

Each subprocess runs with XDG_STATE_HOME pointed at a throwaway directory.
That isolates the denial log for the ported copy and would isolate it for
the live hook too, so running this suite never appends synthetic denials to
a real log.
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
HOOK = os.environ.get("ORG_RULE_GUARD_UNDER_TEST") or os.path.join(HERE, "org-rule-guard.py")

spec = importlib.util.spec_from_file_location("org_rule_guard_under_test", HOOK)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

# The ported hook logs denials; the live hook it was ported from does not
# yet. Log-behaviour assertions are meaningful only against the former.
LOGS = hasattr(guard, "log_denial")

_CLEANUP = []


def tearDownModule():
    for d in _CLEANUP:
        shutil.rmtree(d, ignore_errors=True)


# --- fixtures, assembled so no rule-triggering literal sits in this file -----

def alnum(n, seed=0):
    """A deterministic, non-repeating alphanumeric body of length n."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(alphabet[(i * 7 + seed) % len(alphabet)] for i in range(n))


def token(prefix, n=40, seed=0):
    return prefix + alnum(n, seed)


# Rule 1 matches the path anywhere in the input, so the deny fixture is
# assembled from pieces too.
WORKFLOWS_PATH = "svc/" + ".github" + "/" + "workflows" + "/ci.yml"

JOB_MANIFEST = "\n".join([
    "apiVersion: batch/v1",
    "kind" + ": " + "Job",
    "metadata:",
    "  name: batch-index",
])

JOB_COMMENT_MANIFEST = "\n".join([
    "# A " + "kind" + ": " + "Job here would be rejected by the fleet guard.",
    "apiVersion: apps/v1",
    "kind: Deployment",
])

LATEST_MANIFEST = "\n".join([
    "apiVersion: apps/v1",
    "kind: Deployment",
    "spec:",
    "  template:",
    "    spec:",
    "      containers:",
    "        - image: ronaldraygun/spaxel:" + "lat" + "est",
])

PINNED_MANIFEST = "\n".join([
    "apiVersion: apps/v1",
    "kind: Deployment",
    "spec:",
    "  template:",
    "    spec:",
    "      containers:",
    "        - image: ronaldraygun/spaxel:1.4.2",
])

KUBECTL_DELETE = "kubectl" + " delete pod worker-0 -n default"
KUBECTL_READ = "kubectl get pods -n argo-workflows"

COMMIT_ALL = "git" + " commit --all -m 'sweep the index'"
COMMIT_NO_PATHSPEC = "git" + " commit -m 'sweep the index'"
COMMIT_SCOPED = "git" + " commit src/app.py -m 'sweep the index'"

CREDENTIAL_BODY = "# credentials: " + token("ghp_", 36, seed=3)
CREDENTIAL_PROSE = "Rotate the ghp_ prefix token stored in OpenBao, never by value."


def write(path, content, session="sess-1", cwd="/repo"):
    return {"tool_name": "Write", "tool_input": {"file_path": path, "content": content},
            "session_id": session, "cwd": cwd}


def bash(command, session="sess-1", cwd="/repo"):
    return {"tool_name": "Bash", "tool_input": {"command": command},
            "session_id": session, "cwd": cwd}


# One allow and one deny per rule, in the order the rules are numbered in the
# hook's docstring. (expected rule_id, allow payload, deny payload)
CASES = [
    ("github-actions-workflow",
     write("docs/ci.md", "CI runs on Argo Workflows, not Actions."),
     write(WORKFLOWS_PATH, "name: build\non: push\n")),
    ("k8s-job-cronjob",
     write("k8s/deploy.yaml", JOB_COMMENT_MANIFEST),
     write("k8s/batch.yaml", JOB_MANIFEST)),
    ("latest-image-tag",
     write("k8s/pinned.yaml", PINNED_MANIFEST),
     write("k8s/loose.yaml", LATEST_MANIFEST)),
    ("mutating-kubectl",
     bash(KUBECTL_READ),
     bash(KUBECTL_DELETE)),
    ("credential-value",
     write("docs/secrets.md", CREDENTIAL_PROSE),
     write("docs/secrets.md", CREDENTIAL_BODY)),
    ("git-commit-all",
     bash(COMMIT_SCOPED),
     bash(COMMIT_ALL)),
    ("git-commit-no-pathspec",
     bash(COMMIT_SCOPED),
     bash(COMMIT_NO_PATHSPEC)),
]


def invoke(payload, state_home=None):
    """Run the hook as Claude Code would: JSON on stdin, decision on stdout.

    Returns (decision_or_None, log_path). The log path is where this run's
    denial log WOULD be, whether or not the hook under test writes one.
    """
    sh = state_home or tempfile.mkdtemp(prefix="org-rule-guard-test-")
    if sh not in _CLEANUP:
        _CLEANUP.append(sh)
    env = dict(os.environ)
    env["XDG_STATE_HOME"] = sh
    env.pop("ORG_RULE_GUARD_STATE_DIR", None)
    proc = subprocess.run([sys.executable, HOOK], input=json.dumps(payload).encode(),
                          capture_output=True, env=env, timeout=20)
    assert proc.returncode == 0, "%s exited %s: %s" % (HOOK, proc.returncode, proc.stderr.decode())
    out = proc.stdout.decode().strip()
    decision = json.loads(out) if out else None
    return decision, os.path.join(sh, "org-rule-guard", "denials.jsonl")


def denied(decision):
    return bool(decision) and decision["hookSpecificOutput"]["permissionDecision"] == "deny"


def log_records(log_path):
    if not os.path.exists(log_path):
        return []
    with open(log_path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def isolated_env(**extra):
    """Environment for a subprocess run whose denial log goes nowhere real."""
    env = dict(os.environ)
    env["XDG_STATE_HOME"] = tempfile.mkdtemp(prefix="org-rule-guard-test-")
    _CLEANUP.append(env["XDG_STATE_HOME"])
    env.pop("ORG_RULE_GUARD_STATE_DIR", None)
    env.update(extra)
    return env


class Decisions(unittest.TestCase):
    """Rule behaviour. Runs against the live hook and the ported copy alike."""

    def test_every_rule_denies_its_fixture(self):
        for rule_id, _allow, deny_payload in CASES:
            with self.subTest(rule_id=rule_id):
                decision, _ = invoke(deny_payload)
                self.assertTrue(denied(decision), "expected deny for %s" % rule_id)

    def test_every_rule_allows_its_near_miss(self):
        for rule_id, allow_payload, _deny in CASES:
            with self.subTest(rule_id=rule_id):
                decision, _ = invoke(allow_payload)
                self.assertFalse(denied(decision), "expected allow for %s" % rule_id)

    def test_garbage_input_fails_open(self):
        for payload in ("not json", "[1, 2]", "{}", {"tool_name": "Bash"},
                        {"tool_name": "Write", "tool_input": {}}):
            with self.subTest(payload=payload):
                raw = json.dumps(payload) if not isinstance(payload, str) else payload
                proc = subprocess.run(
                    [sys.executable, HOOK], input=raw.encode(),
                    capture_output=True, timeout=20, env=isolated_env(),
                )
                self.assertEqual(proc.returncode, 0)
                # Failing open must stay silent: no deny JSON, nothing to parse.
                self.assertEqual(proc.stdout.decode().strip(), "")

    def test_internal_error_fails_open(self):
        """A body that explodes the checker still allows, exit 0."""
        decision, _ = invoke({"tool_name": "Bash", "tool_input": {"command": None}})
        self.assertFalse(denied(decision))

    def test_argo_workflow_create_is_allowed(self):
        decision, _ = invoke(bash("kubectl" + " create -f workflow.yml -n argo-workflows"))
        self.assertFalse(denied(decision))

    def test_rollout_status_is_allowed(self):
        decision, _ = invoke(bash("kubectl" + " rollout status deploy/web"))
        self.assertFalse(denied(decision))

    def test_git_commit_amend_without_all_is_allowed(self):
        decision, _ = invoke(bash("git" + " commit --amend -m 'typo'"))
        self.assertFalse(denied(decision))

    def test_piped_grep_mentioning_a_banned_verb_is_allowed(self):
        decision, _ = invoke(bash("cat rules.md | grep " + "'kubectl delete'"))
        self.assertFalse(denied(decision))


@unittest.skipUnless(LOGS, "hook under test has no denial log")
class DenialLog(unittest.TestCase):
    """The learning signal. Only the ported copy has it."""

    def test_deny_writes_exactly_one_line(self):
        _decision, log_path = invoke(CASES[0][2])
        records = log_records(log_path)
        self.assertEqual(len(records), 1)

    def test_allow_writes_nothing(self):
        for rule_id, allow_payload, _deny in CASES:
            with self.subTest(rule_id=rule_id):
                _decision, log_path = invoke(allow_payload)
                self.assertEqual(log_records(log_path), [])

    def test_record_has_exactly_the_documented_fields(self):
        _decision, log_path = invoke(CASES[0][2])
        (record,) = log_records(log_path)
        self.assertEqual(sorted(record),
                         sorted(["ts", "rule_id", "tool", "cwd", "session_id", "fragment"]))

    def test_record_fields_are_populated_from_the_hook_input(self):
        payload = bash(KUBECTL_DELETE, session="sess-abc", cwd="/home/coding/NEEDLE")
        _decision, log_path = invoke(payload)
        (record,) = log_records(log_path)
        self.assertEqual(record["rule_id"], "mutating-kubectl")
        self.assertEqual(record["tool"], "Bash")
        self.assertEqual(record["cwd"], "/home/coding/NEEDLE")
        self.assertEqual(record["session_id"], "sess-abc")
        self.assertRegex(record["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_every_logged_rule_id_is_a_declared_slug(self):
        for rule_id, _allow, deny_payload in CASES:
            with self.subTest(rule_id=rule_id):
                _decision, log_path = invoke(deny_payload)
                (record,) = log_records(log_path)
                self.assertEqual(record["rule_id"], rule_id)
                self.assertIn(record["rule_id"], guard.RULE_IDS)

    def test_denials_accumulate_across_calls(self):
        sh = tempfile.mkdtemp(prefix="org-rule-guard-test-")
        for rule_id, _allow, deny_payload in CASES:
            invoke(deny_payload, state_home=sh)
        records = log_records(os.path.join(sh, "org-rule-guard", "denials.jsonl"))
        self.assertEqual(len(records), len(CASES))

    def test_credential_rule_logs_the_pattern_name_only(self):
        _decision, log_path = invoke(CASES[4][2])
        (record,) = log_records(log_path)
        self.assertEqual(record["fragment"], "GitHub token")
        # Belt and braces: no fragment of the blocked value anywhere in the line.
        with open(log_path) as fh:
            raw = fh.read()
        body = token("ghp_", 36, seed=3)[len("ghp_"):]
        self.assertNotIn(token("ghp_", 36, seed=3), raw)
        self.assertNotIn(body[:12], raw)

    def test_credential_check_wins_the_deny_on_a_mixed_command(self):
        """Ordering is what keeps a value off the log for Bash: the credential
        rule denies before any other rule can take a fragment from the same
        command, so what gets logged is the pattern name."""
        command = " && ".join([KUBECTL_DELETE, "echo " + token("ghp_", 36, seed=5)])
        _decision, log_path = invoke(bash(command))
        (record,) = log_records(log_path)
        self.assertEqual(record["rule_id"], "credential-value")
        self.assertEqual(record["fragment"], "GitHub token")

    def test_redact_strips_a_credential_from_any_fragment(self):
        """The belt to that brace: should a future rule ever take a fragment
        from text still holding a value, the scrubber removes it first."""
        self.assertEqual(guard._redact("delete pod " + token("ghp_", 36, seed=5)),
                         "delete pod [redacted]")
        self.assertEqual(guard._redact("line one\nline two\r\nthree"),
                         "line one line two three")

    def test_fragment_is_truncated_to_80_chars(self):
        long_path = "d/" * 60 + ".github" + "/" + "workflows" + "/ci.yml"
        _decision, log_path = invoke(write(long_path, "on: push\n"))
        (record,) = log_records(log_path)
        self.assertEqual(len(record["fragment"]), 80)

    def test_state_directory_is_mode_700_and_file_600(self):
        _decision, log_path = invoke(CASES[0][2])
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(log_path)).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(log_path).st_mode), 0o600)

    def test_missing_session_and_cwd_fall_back(self):
        """A caller that omits them still gets a usable record, and a vanished
        working directory does not stop the write."""
        payload = {"tool_name": "Write",
                   "tool_input": {"file_path": WORKFLOWS_PATH, "content": "on: push\n"}}
        _decision, log_path = invoke(payload)
        (record,) = log_records(log_path)
        self.assertEqual(record["session_id"], "")
        self.assertTrue(record["cwd"])

    def test_logging_failure_does_not_change_the_decision(self):
        """A log that cannot be written must deny anyway, never allow."""
        sh = tempfile.mkdtemp(prefix="org-rule-guard-test-")
        blocker = os.path.join(sh, "not-a-directory")
        with open(blocker, "w") as fh:
            fh.write("a file where the log directory would go\n")
        env = dict(os.environ)
        env["ORG_RULE_GUARD_STATE_DIR"] = os.path.join(blocker, "org-rule-guard")
        proc = subprocess.run([sys.executable, HOOK], input=json.dumps(CASES[0][2]).encode(),
                              capture_output=True, env=env, timeout=20)
        self.assertEqual(proc.returncode, 0)
        decision = json.loads(proc.stdout.decode().strip())
        self.assertTrue(denied(decision))
        self.assertFalse(os.path.exists(os.path.join(blocker, "org-rule-guard")))

    def test_state_dir_override_is_honoured(self):
        sh = tempfile.mkdtemp(prefix="org-rule-guard-test-")
        env = dict(os.environ)
        env["ORG_RULE_GUARD_STATE_DIR"] = os.path.join(sh, "elsewhere")
        env.pop("XDG_STATE_HOME", None)
        proc = subprocess.run([sys.executable, HOOK], input=json.dumps(CASES[0][2]).encode(),
                              capture_output=True, env=env, timeout=20)
        self.assertTrue(denied(json.loads(proc.stdout.decode().strip())))
        self.assertTrue(os.path.exists(os.path.join(sh, "elsewhere", "denials.jsonl")))


class ModuleSurface(unittest.TestCase):
    """What a log reader depends on staying stable."""

    @unittest.skipUnless(LOGS, "hook under test has no denial log")
    def test_rule_ids_are_stable_slugs(self):
        for rule_id in guard.RULE_IDS:
            with self.subTest(rule_id=rule_id):
                self.assertRegex(rule_id, r"^[a-z][a-z0-9-]*$")

    def test_deny_exits_zero_with_a_deny_decision(self):
        """deny() is how a block is signalled: exit 0, JSON saying deny. A
        non-zero exit would be an error, which Claude Code treats differently."""
        payload = CASES[2][2]
        proc = subprocess.run([sys.executable, HOOK], input=json.dumps(payload).encode(),
                              capture_output=True, timeout=20, env=isolated_env())
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"],
                         "deny")


class Install(unittest.TestCase):
    """The installer's contract. Runs against a throwaway hooks dir and
    settings path, so the live hook and the live settings are never touched."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="org-rule-guard-install-")
        _CLEANUP.append(self.root)
        self.hooks_dir = os.path.join(self.root, "hooks")
        self.settings = os.path.join(self.root, "settings.json")
        self.script = os.path.join(HERE, os.pardir, "install.sh")
        self.env = dict(os.environ,
                        CLAUDE_HOOKS_DIR=self.hooks_dir,
                        CLAUDE_SETTINGS=self.settings)

    def run_install(self, *args):
        proc = subprocess.run(["bash", self.script, *args], capture_output=True,
                              env=self.env, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        return proc.stdout.decode()

    def dst(self):
        return os.path.join(self.hooks_dir, "org-rule-guard.py")

    def read(self, path):
        with open(path) as fh:
            return fh.read()

    def test_first_install_copies_the_hook_and_leaves_settings_alone(self):
        out = self.run_install()
        self.assertTrue(os.path.exists(self.dst()), out)
        self.assertFalse(os.path.exists(self.settings), out)

    def test_installed_hook_is_executable(self):
        self.run_install()
        self.assertTrue(os.stat(self.dst()).st_mode & stat.S_IXUSR)

    def test_installed_hook_passes_the_rule_fixtures(self):
        """What the installer put down is the thing this file tests. Only the
        Decisions class runs: it is entirely subprocess-based, so re-entering
        the suite from here cannot recurse (Install would re-install, and
        re-run this test, forever)."""
        self.run_install()
        env = dict(os.environ)
        env["ORG_RULE_GUARD_UNDER_TEST"] = self.dst()
        env["XDG_STATE_HOME"] = tempfile.mkdtemp(prefix="org-rule-guard-test-")
        _CLEANUP.append(env["XDG_STATE_HOME"])
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "test_org_rule_guard.Decisions", "-v"],
            capture_output=True, env=env, cwd=HERE, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode() + proc.stdout.decode())

    def test_install_does_not_overwrite_an_existing_hook(self):
        self.run_install()
        with open(self.dst(), "a") as fh:
            fh.write("\n# local edit\n")
        before = self.read(self.dst())
        out = self.run_install()
        self.assertEqual(self.read(self.dst()), before, out)
        self.assertIn("not overwritten", out)
        self.assertFalse(os.path.exists(self.settings), out)

    def test_force_overwrites_but_still_leaves_settings_alone(self):
        self.run_install()
        with open(self.dst(), "a") as fh:
            fh.write("\n# local edit\n")
        out = self.run_install("--force")
        self.assertNotIn("# local edit", self.read(self.dst()), out)
        self.assertFalse(os.path.exists(self.settings), out)

    def test_wire_installs_and_writes_the_settings_entry(self):
        out = self.run_install("--wire")
        self.assertIn("wired", out)
        with open(self.settings) as fh:
            s = json.load(fh)
        entries = s["hooks"]["PreToolUse"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["matcher"], "Write|Edit|Bash")
        self.assertEqual(entries[0]["hooks"][0]["command"],
                         "python3 %s" % self.dst())

    def test_wire_replaces_an_existing_hook_copy(self):
        self.run_install()
        with open(self.dst(), "a") as fh:
            fh.write("\n# local edit\n")
        self.run_install("--wire")
        self.assertNotIn("# local edit", self.read(self.dst()))

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

    def test_uninstall_removes_the_hook_and_leaves_settings(self):
        self.run_install("--wire")
        self.run_install("--uninstall")
        self.assertFalse(os.path.exists(self.dst()))
        self.assertTrue(os.path.exists(self.settings))

    def test_uninstall_refuses_a_hook_this_copy_did_not_install(self):
        """On a machine still running the pre-port hook, the file at the
        destination is live enforcement that this folder never wrote -- removing
        it on sight would take the guard down fleet-wide. --force overrides."""
        os.makedirs(self.hooks_dir, exist_ok=True)
        with open(self.dst(), "w") as fh:
            fh.write("#!/usr/bin/env python3\n# the operator's own pre-port hook\n")
        proc = subprocess.run(["bash", self.script, "--uninstall"],
                              capture_output=True, env=self.env, timeout=30)
        self.assertNotEqual(proc.returncode, 0, proc.stdout.decode())
        self.assertTrue(os.path.exists(self.dst()), proc.stdout.decode())
        self.assertIn("refusing", proc.stderr.decode())
        out = self.run_install("--uninstall", "--force")
        self.assertFalse(os.path.exists(self.dst()), out)


if __name__ == "__main__":
    unittest.main()
