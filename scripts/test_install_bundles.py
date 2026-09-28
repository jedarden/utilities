#!/usr/bin/env python3
"""End-to-end tests for declared install-time utility bundles.

The tests stage the two utilities an installer is allowed to see into a
temporary checkout.  After installation that checkout is removed before the
installed hooks are executed, so a passing run cannot be explained by a
runtime lookup into the repository.

    python3 -m unittest discover -s scripts -p 'test_install_bundles.py' -v
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
ORG_RULE_GUARD = ROOT / "org-rule-guard"
MANIFEST = ORG_RULE_GUARD / "bundled-dependencies.json"
SETTINGS_PRESERVATION_FIXTURE = (
    ROOT / "scripts" / "fixtures" / "settings-preservation.json"
)


def alnum(length, seed=0):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(alphabet[(index * 7 + seed) % len(alphabet)] for index in range(length))


def token(prefix, length=40, seed=0):
    return prefix + alnum(length, seed)


class SelectiveInstallTests(unittest.TestCase):
    """Exercise each utility from a namespaced release-shaped checkout."""

    def temp_dir(self, prefix):
        path = Path(tempfile.mkdtemp(prefix=prefix))
        self.addCleanup(shutil.rmtree, path, ignore_errors=True)
        return path

    def stage_release(self, *utilities):
        """Stage only the utility directories present in one release checkout."""

        checkout = self.temp_dir("selective-install-release-")
        for utility in utilities:
            shutil.copytree(ROOT / utility, checkout / utility)
        return checkout

    def stage_checkout(self):
        """Stage the source and declared install-time bundle for org-rule-guard."""

        return self.stage_release("agent-secrets", "org-rule-guard")

    def bundle_declaration(self):
        with MANIFEST.open(encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(set(data), {"bundles"})
        self.assertEqual(len(data["bundles"]), 1)
        declaration = data["bundles"][0]
        self.assertEqual(
            set(declaration), {"utility", "version", "source", "destination"}
        )
        return declaration

    def clean_environment(self, home):
        env = dict(os.environ)
        env["HOME"] = str(home)
        for name in (
            "CLAUDE_HOOKS_DIR",
            "CLAUDE_SETTINGS",
            "CREDENTIAL_GUARD_STATE_DIR",
            "ORG_RULE_GUARD_STATE_DIR",
            "BAO_AS_CONFIG_DIR",
            "BAO_AS_BIN",
            "BAO_TOKEN",
            "VAULT_TOKEN",
            "BAO_ADDR",
            "VAULT_ADDR",
            "XDG_CONFIG_HOME",
            "XDG_STATE_HOME",
            "PYTHONPATH",
        ):
            env.pop(name, None)
        return env

    def run_install(
        self, checkout, utility, home, runtime, mode=None, settings=None,
        env_overrides=None,
    ):
        script = checkout / utility / "install.sh"
        command = ["/bin/sh", str(script)]
        if mode is not None:
            command.append(mode)
        environment = self.clean_environment(home)
        if settings is not None:
            environment["CLAUDE_SETTINGS"] = str(settings)
        if env_overrides is not None:
            environment.update(env_overrides)
        return subprocess.run(
            command,
            cwd=runtime,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def run_install_with_umask(
        self, checkout, utility, home, runtime, mode, umask, settings=None
    ):
        script = checkout / utility / "install.sh"
        environment = self.clean_environment(home)
        if settings is not None:
            environment["CLAUDE_SETTINGS"] = str(settings)
        return subprocess.run(
            ["/bin/sh", str(script), mode],
            cwd=runtime,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            preexec_fn=lambda: os.umask(umask),
        )

    def read_provenance(self, home, utility):
        path = self.provenance_path(home, utility)
        return path, json.loads(path.read_text(encoding="utf-8"))

    def provenance_path(self, home, utility):
        if utility == "agent-secrets":
            return home / ".claude" / "hooks" / "agent-secrets" / "provenance.json"
        return (
            home
            / ".claude"
            / "hooks"
            / "org-rule-guard"
            / "provenance.json"
        )

    def installed_file_snapshot(self, home):
        """Capture installed file contents and modes for read-only assertions."""

        return {
            path.relative_to(home): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
            for path in home.rglob("*")
            if path.is_file()
        }

    def status_path(self, prefix):
        path = self.temp_dir(prefix)
        (path / "dirname").symlink_to(shutil.which("dirname"))
        (path / "cat").symlink_to(shutil.which("cat"))
        return path

    def test_status_requires_existing_provenance_record(self):
        cases = (
            ("agent-secrets", self.stage_release("agent-secrets")),
            ("org-rule-guard", self.stage_checkout()),
        )
        for utility, release in cases:
            with self.subTest(utility=utility):
                home = self.temp_dir("status-before-install-home-")
                runtime = self.temp_dir("status-before-install-runtime-")
                provenance_path = self.provenance_path(home, utility)
                self.assertFalse(provenance_path.exists())

                result = self.run_install(
                    release,
                    utility,
                    home,
                    runtime,
                    "--status",
                    env_overrides={
                        "PATH": str(self.status_path("status-before-install-bin-"))
                    },
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("no installed provenance", result.stderr)
                self.assertFalse(provenance_path.exists())
                self.assertFalse((home / ".claude").exists())

    def test_status_reports_a_stale_bundled_copy_without_changing_it(self):
        first = self.stage_checkout()
        current = self.stage_checkout()
        home = self.temp_dir("status-stale-bundle-home-")
        runtime = self.temp_dir("status-stale-bundle-runtime-")

        installed = self.run_install(first, "org-rule-guard", home, runtime)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        bundle_source = current / "agent-secrets" / "hooks" / "credential-guard.py"
        bundle_source.write_text(
            bundle_source.read_text(encoding="utf-8")
            + "\n# newer bundle source\n",
            encoding="utf-8",
        )
        (current / "agent-secrets" / "VERSION").write_text(
            "0.2.0\n", encoding="utf-8"
        )
        before = self.installed_file_snapshot(home)

        status = self.run_install(
            current,
            "org-rule-guard",
            home,
            runtime,
            "--status",
            env_overrides={"PATH": str(self.status_path("status-stale-bundle-bin-"))},
        )

        self.assertNotEqual(status.returncode, 0)
        self.assertIn("stale bundle pin", status.stderr)
        self.assertIn("modified or stale bundled", status.stderr)
        self.assertIn("reinstall to repair", status.stderr)
        self.assertEqual(self.installed_file_snapshot(home), before)

    def test_status_reports_post_install_edits_without_changing_the_install(self):
        cases = (
            ("agent-secrets", self.stage_release("agent-secrets")),
            ("org-rule-guard", self.stage_checkout()),
        )
        for utility, release in cases:
            with self.subTest(utility=utility):
                home = self.temp_dir("status-edited-home-")
                runtime = self.temp_dir("status-edited-runtime-")
                installed = self.run_install(release, utility, home, runtime)
                self.assertEqual(installed.returncode, 0, installed.stderr)
                if utility == "agent-secrets":
                    hook = home / ".claude" / "hooks" / "credential-guard.py"
                else:
                    hook = home / ".claude" / "hooks" / "org-rule-guard.py"
                hook.write_text(
                    hook.read_text(encoding="utf-8") + "\n# local edit\n",
                    encoding="utf-8",
                )
                before = self.installed_file_snapshot(home)

                status = self.run_install(
                    release,
                    utility,
                    home,
                    runtime,
                    "--status",
                    env_overrides={"PATH": str(self.status_path("status-edited-bin-"))},
                )

                self.assertNotEqual(status.returncode, 0)
                self.assertIn("modified or stale", status.stderr)
                self.assertIn("reinstall to repair", status.stderr)
                self.assertEqual(self.installed_file_snapshot(home), before)

    def test_provenance_survives_unrelated_settings_wire(self):
        cases = (
            ("agent-secrets", self.stage_release("agent-secrets")),
            ("org-rule-guard", self.stage_checkout()),
        )
        for utility, release in cases:
            with self.subTest(utility=utility):
                home = self.temp_dir("settings-provenance-home-")
                runtime = self.temp_dir("settings-provenance-runtime-")
                settings = runtime / "settings.json"
                settings.write_text(
                    json.dumps(
                        {"model": "opus", "permissions": {"allow": ["Read"]}},
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )

                initial = self.run_install(release, utility, home, runtime)
                self.assertEqual(initial.returncode, 0, initial.stderr)
                provenance_path, provenance = self.read_provenance(home, utility)
                installed_record = provenance_path.read_bytes()

                changed_settings = json.loads(settings.read_text(encoding="utf-8"))
                changed_settings["model"] = "sonnet"
                changed_settings["permissions"]["deny"] = ["Bash"]
                settings.write_text(
                    json.dumps(changed_settings, indent=2) + "\n", encoding="utf-8"
                )
                wired = self.run_install(
                    release, utility, home, runtime, "--wire", settings=settings
                )

                self.assertEqual(wired.returncode, 0, wired.stderr)
                self.assertEqual(provenance_path.read_bytes(), installed_record)
                self.assertEqual(
                    json.loads(provenance_path.read_text(encoding="utf-8")),
                    provenance,
                )
                final_settings = json.loads(settings.read_text(encoding="utf-8"))
                self.assertEqual(final_settings["model"], changed_settings["model"])
                self.assertEqual(
                    final_settings["permissions"], changed_settings["permissions"]
                )

    def hold_settings_lock(self, lock_path):
        code = """import fcntl
import os
import sys

fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
print("ready", flush=True)
sys.stdin.read()
"""
        process = subprocess.Popen(
            [sys.executable, "-c", code, str(lock_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        ready = process.stdout.readline().strip()
        if ready != "ready":
            process.kill()
            process.wait()
            raise AssertionError(
                "settings lock holder did not become ready: "
                + process.stderr.read()
            )
        return process

    def release_settings_lock(self, process):
        if process.poll() is None:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()

    def run_concurrent_wire(self, checkout, home, runtime, settings):
        processes = []
        for utility in ("org-rule-guard", "agent-secrets"):
            environment = self.clean_environment(home)
            environment["CLAUDE_SETTINGS"] = str(settings)
            processes.append(
                subprocess.Popen(
                    ["/bin/sh", str(checkout / utility / "install.sh"), "--wire"],
                    cwd=runtime,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        return processes

    def preservation_fixture(self, utility, case, command):
        with SETTINGS_PRESERVATION_FIXTURE.open(encoding="utf-8") as handle:
            settings = json.load(handle)

        own_entry = settings["hooks"]["PreToolUse"][-1]
        own_entry["hooks"][0]["command"] = command
        desired_matcher = "Write|Edit|MultiEdit|NotebookEdit|Bash"
        if case == "append":
            settings["hooks"]["PreToolUse"].pop()
        elif case == "current":
            own_entry["matcher"] = desired_matcher
            own_entry["hooks"][0]["timeout"] = 10
        elif case == "legacy":
            self.assertEqual(utility, "org-rule-guard")
            own_entry["matcher"] = "Write|Edit|Bash"
            own_entry["hooks"][0]["timeout"] = 10
        else:
            self.fail("unknown settings preservation case: %s" % case)
        return settings

    def without_owned_entry(self, settings, command):
        preserved = json.loads(json.dumps(settings))
        entries = preserved["hooks"]["PreToolUse"]
        matching = [
            entry for entry in entries
            if any(
                isinstance(handler, dict)
                and handler.get("command") == command
                for handler in entry.get("hooks", [])
            )
        ]
        self.assertEqual(len(matching), 1)
        entries.remove(matching[0])
        return json.dumps(preserved, indent=2).encode("utf-8") + b"\n"

    def run_installed_hook(self, hook, home, runtime, payload, state):
        env = self.clean_environment(home)
        env["XDG_CONFIG_HOME"] = str(state / "config")
        env["XDG_STATE_HOME"] = str(state / "state")
        return subprocess.run(
            [sys.executable, str(hook)],
            cwd=runtime,
            env=env,
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=30,
        )

    def assert_installed_runtime_has_no_source_paths(self, installed, *sources):
        for path in installed:
            contents = path.read_bytes()
            for source in sources:
                self.assertNotIn(
                    os.fsencode(source),
                    contents,
                    "%s embeds source path %s" % (path, source),
                )

    def test_agent_secrets_selective_install_runs_without_release_checkout(self):
        release = self.stage_release("agent-secrets")
        home = self.temp_dir("agent-secrets-install-home-")
        runtime = self.temp_dir("agent-secrets-install-runtime-")
        state = self.temp_dir("agent-secrets-install-state-")
        self.assertFalse(self.provenance_path(home, "agent-secrets").exists())

        result = self.run_install(release, "agent-secrets", home, runtime)

        self.assertEqual(result.returncode, 0, result.stderr)
        hook_dst = home / ".claude" / "hooks" / "credential-guard.py"
        bao_as_dst = home / ".local" / "bin" / "bao-as"
        self.assertTrue(hook_dst.is_file(), result.stdout)
        self.assertTrue(bao_as_dst.is_file(), result.stdout)
        self.assertTrue(os.access(bao_as_dst, os.X_OK))
        _, provenance = self.read_provenance(home, "agent-secrets")
        version = (
            (release / "agent-secrets" / "VERSION")
            .read_text(encoding="utf-8")
            .splitlines()[0]
            .strip()
        )
        self.assertEqual(
            provenance,
            {
                "utility": "agent-secrets",
                "version": version,
                "runtime": {"python3": ">=3.9"},
                "bundles": [],
            },
        )
        installed_before_status = self.installed_file_snapshot(home)
        status = self.run_install(
            release, "agent-secrets", home, runtime, "--status",
            env_overrides={"PATH": str(self.status_path("agent-secrets-status-bin-"))},
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout), provenance)
        self.assertEqual(self.installed_file_snapshot(home), installed_before_status)
        self.assertFalse((release / "org-rule-guard").exists())
        self.assertEqual(
            hook_dst.read_bytes(),
            (release / "agent-secrets" / "hooks" / "credential-guard.py").read_bytes(),
        )
        self.assertEqual(
            bao_as_dst.read_bytes(),
            (release / "agent-secrets" / "bin" / "bao-as").read_bytes(),
        )
        self.assert_installed_runtime_has_no_source_paths(
            (hook_dst, bao_as_dst), ROOT, release
        )

        shutil.rmtree(release)
        self.assertFalse(release.exists())

        hook_payload = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": str(runtime / "notes.md"),
                "content": "credential = " + token("ghp_", 36, seed=7),
            },
        }
        hook_result = self.run_installed_hook(
            hook_dst, home, runtime, hook_payload, state
        )
        self.assertEqual(hook_result.returncode, 0, hook_result.stderr)
        hook_decision = json.loads(hook_result.stdout)
        self.assertEqual(
            hook_decision["hookSpecificOutput"]["permissionDecision"], "deny"
        )

        config = home / ".config" / "bao-as"
        instance_dir = config / "prod"
        instance_dir.mkdir()
        (config / "instances.conf").write_text(
            "prod https://bao-fixture.invalid:8200\n", encoding="utf-8"
        )
        role_id = instance_dir / "role_id"
        secret_id = instance_dir / "secret_id"
        role_id.write_text("role-id-fixture\n", encoding="utf-8")
        secret_id.write_text("secret-id-fixture\n", encoding="utf-8")
        role_id.chmod(0o600)
        secret_id.chmod(0o600)

        stub_dir = self.temp_dir("agent-secrets-install-cli-")
        stub_bao = stub_dir / "bao"
        stub_bao.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" > \"$BAO_STUB_LOG\"\n"
            "if [ \"$1\" = write ] && [ \"$3\" = auth/approle/login ]; then\n"
            "  printf 'fixture-token\\n'\n"
            "  exit 0\n"
            "fi\n"
            "exit 2\n",
            encoding="utf-8",
        )
        stub_bao.chmod(0o700)
        stub_log = stub_dir / "bao.log"
        bao_env = self.clean_environment(home)
        bao_env["PATH"] = str(stub_dir) + os.pathsep + bao_env["PATH"]
        bao_env["BAO_STUB_LOG"] = str(stub_log)
        bao_result = subprocess.run(
            [
                str(bao_as_dst),
                "prod",
                "/bin/sh",
                "-c",
                "test -n \"$BAO_TOKEN\" && test \"$BAO_ADDR\" = https://bao-fixture.invalid:8200",
            ],
            cwd=runtime,
            env=bao_env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(bao_result.returncode, 0, bao_result.stderr)
        stub_args = stub_log.read_text(encoding="utf-8")
        self.assertIn("role_id=@" + str(role_id), stub_args)
        self.assertIn("secret_id=@" + str(secret_id), stub_args)

    def test_org_rule_guard_selective_install_runs_without_release_checkout(self):
        declaration = self.bundle_declaration()
        release = self.stage_release("agent-secrets", "org-rule-guard")
        home = self.temp_dir("org-rule-guard-install-home-")
        runtime = self.temp_dir("org-rule-guard-install-runtime-")
        state = self.temp_dir("org-rule-guard-install-state-")
        self.assertFalse(self.provenance_path(home, "org-rule-guard").exists())

        source = release / declaration["utility"] / PurePosixPath(declaration["source"])
        source_bytes = source.read_bytes()
        result = self.run_install(release, "org-rule-guard", home, runtime)

        self.assertEqual(result.returncode, 0, result.stderr)
        hook_dst = home / ".claude" / "hooks" / "org-rule-guard.py"
        bundle_root = hook_dst.with_suffix("")
        bundle_dst = bundle_root / PurePosixPath(declaration["destination"])
        self.assertTrue(hook_dst.is_file(), result.stdout)
        self.assertTrue(bundle_dst.is_file(), result.stdout)
        _, provenance = self.read_provenance(home, "org-rule-guard")
        self.assertEqual(
            provenance,
            {
                "utility": "org-rule-guard",
                "version": (
                    (release / "org-rule-guard" / "VERSION")
                    .read_text(encoding="utf-8")
                    .splitlines()[0]
                    .strip()
                ),
                "runtime": {"python3": ">=3.9"},
                "bundles": [declaration],
            },
        )
        installed_before_status = self.installed_file_snapshot(home)
        status = self.run_install(
            release, "org-rule-guard", home, runtime, "--status",
            env_overrides={"PATH": str(self.status_path("org-rule-guard-status-bin-"))},
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout), provenance)
        self.assertEqual(self.installed_file_snapshot(home), installed_before_status)
        self.assertEqual(bundle_dst.read_bytes(), source_bytes)
        self.assertEqual(stat.S_IMODE(bundle_dst.stat().st_mode), 0o755)
        self.assertEqual(bundle_dst.parent, bundle_root)
        self.assertFalse((home / "agent-secrets").exists())
        self.assert_installed_runtime_has_no_source_paths(
            (hook_dst, bundle_dst), ROOT, release
        )

        shutil.rmtree(release)
        self.assertFalse(release.exists())

        org_payload = {
            "tool_name": "Bash",
            "tool_input": {
                "command": "kubectl" + " delete pod worker-0 -n default",
            },
        }
        org_result = self.run_installed_hook(
            hook_dst, home, runtime, org_payload, state
        )
        self.assertEqual(org_result.returncode, 0, org_result.stderr)
        org_decision = json.loads(org_result.stdout)
        self.assertEqual(
            org_decision["hookSpecificOutput"]["permissionDecision"], "deny"
        )

        credential_payload = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": str(runtime / "notes.md"),
                "content": "token = " + token("ghp_", 36, seed=3),
            },
        }
        credential_result = self.run_installed_hook(
            bundle_dst, home, runtime, credential_payload, state
        )
        self.assertEqual(credential_result.returncode, 0, credential_result.stderr)
        credential_decision = json.loads(credential_result.stdout)
        self.assertEqual(
            credential_decision["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertIn("GitHub token", credential_decision["hookSpecificOutput"][
            "permissionDecisionReason"
        ])

    def test_org_rule_guard_keeps_credential_rule_when_bundle_is_unavailable(self):
        """The org hook remains safe if its optional copied companion is gone."""
        declaration = self.bundle_declaration()
        release = self.stage_release("agent-secrets", "org-rule-guard")
        home = self.temp_dir("org-rule-guard-fallback-home-")
        runtime = self.temp_dir("org-rule-guard-fallback-runtime-")
        state = self.temp_dir("org-rule-guard-fallback-state-")

        source = release / declaration["utility"] / PurePosixPath(declaration["source"])
        result = self.run_install(release, "org-rule-guard", home, runtime)

        self.assertEqual(result.returncode, 0, result.stderr)
        hook_dst = home / ".claude" / "hooks" / "org-rule-guard.py"
        bundle_dst = (
            hook_dst.with_suffix("") / PurePosixPath(declaration["destination"])
        )
        self.assertTrue(bundle_dst.is_file(), result.stdout)
        self.assertEqual(bundle_dst.read_bytes(), source.read_bytes())

        # The copied companion is an install-time enhancement, not a runtime
        # dependency of org-rule-guard.  Removing it models an unavailable
        # bundle without giving the hook access to the source checkout.
        bundle_dst.unlink()
        shutil.rmtree(release)
        self.assertFalse(bundle_dst.exists())
        self.assertFalse(release.exists())

        credential_payload = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": str(runtime / "notes.md"),
                "content": "token = " + token("ghp_", 36, seed=11),
            },
        }
        credential_result = self.run_installed_hook(
            hook_dst, home, runtime, credential_payload, state
        )
        self.assertEqual(credential_result.returncode, 0, credential_result.stderr)
        credential_decision = json.loads(credential_result.stdout)
        self.assertEqual(
            credential_decision["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertIn(
            "GitHub token",
            credential_decision["hookSpecificOutput"]["permissionDecisionReason"],
        )

    def test_combined_wire_merges_existing_settings_idempotently(self):
        """Both --wire runs preserve unrelated hooks and do not duplicate entries."""
        checkout = self.stage_checkout()
        home = self.temp_dir("combined-wire-home-")
        runtime = self.temp_dir("combined-wire-runtime-")
        settings = home / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        original = {
            "permissions": {"allow": ["Read"]},
            "hooks": {
                "SessionStart": [{
                    "hooks": [{
                        "type": "command",
                        "command": "printf session-start",
                    }],
                }],
                "PreToolUse": [{
                    "matcher": "Read",
                    "hooks": [{
                        "type": "command",
                        "command": "printf existing-pretooluse",
                    }],
                }],
                "PostToolUse": [{
                    "matcher": "Write",
                    "hooks": [{
                        "type": "command",
                        "command": "printf post-tooluse",
                    }],
                }],
            },
        }
        settings.write_text(json.dumps(original, indent=2) + "\n", encoding="utf-8")

        for utility in ("org-rule-guard", "agent-secrets"):
            result = self.run_install(
                checkout, utility, home, runtime, mode="--wire", settings=settings
            )
            self.assertEqual(result.returncode, 0, result.stderr)

        after_first_wire = settings.read_bytes()
        merged = json.loads(after_first_wire)
        self.assertEqual(merged["permissions"], original["permissions"])
        self.assertEqual(
            merged["hooks"]["SessionStart"], original["hooks"]["SessionStart"]
        )
        self.assertEqual(
            merged["hooks"]["PostToolUse"], original["hooks"]["PostToolUse"]
        )
        self.assertEqual(
            merged["hooks"]["PreToolUse"][:1], original["hooks"]["PreToolUse"]
        )
        self.assertEqual(
            [entry["hooks"][0]["command"]
             for entry in merged["hooks"]["PreToolUse"]],
            [
                "printf existing-pretooluse",
                f"python3 {home / '.claude/hooks/org-rule-guard.py'}",
                f"python3 {home / '.claude/hooks/credential-guard.py'}",
            ],
        )

        for utility in ("org-rule-guard", "agent-secrets"):
            result = self.run_install(
                checkout, utility, home, runtime, mode="--wire", settings=settings
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("already", result.stdout)
        self.assertEqual(settings.read_bytes(), after_first_wire)

    def test_fresh_wire_creates_mode_0600_settings_for_each_utility(self):
        """A fresh default settings path is private even with a permissive umask."""
        checkout = self.stage_checkout()
        for utility in ("org-rule-guard", "agent-secrets"):
            with self.subTest(utility=utility):
                home = self.temp_dir("fresh-wire-home-%s-" % utility)
                runtime = self.temp_dir("fresh-wire-runtime-%s-" % utility)
                settings = home / ".claude" / "settings.json"
                self.assertFalse(settings.exists())
                self.assertFalse(settings.parent.exists())

                result = self.run_install_with_umask(
                    checkout, utility, home, runtime, "--wire", 0o000
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(settings.is_file(), result.stdout)
                self.assertEqual(stat.S_IMODE(settings.stat().st_mode), 0o600)
                self.assertFalse(Path(str(settings) + ".bak").exists())

    def test_each_wire_preserves_fixture_content_on_every_merge_path(self):
        """Unrelated fixture bytes survive each installer's individual wire paths."""
        cases = (
            ("agent-secrets", "append"),
            ("agent-secrets", "current"),
            ("org-rule-guard", "append"),
            ("org-rule-guard", "current"),
            ("org-rule-guard", "legacy"),
        )
        for utility, case in cases:
            with self.subTest(utility=utility, case=case):
                checkout = self.stage_checkout()
                home = self.temp_dir(
                    "preservation-wire-home-%s-%s-" % (utility, case)
                )
                runtime = self.temp_dir(
                    "preservation-wire-runtime-%s-%s-" % (utility, case)
                )
                settings_path = home / ".claude" / "settings.json"
                settings_path.parent.mkdir(parents=True)
                hook_name = (
                    "credential-guard.py"
                    if utility == "agent-secrets"
                    else "org-rule-guard.py"
                )
                command = "python3 %s" % (home / ".claude/hooks" / hook_name)
                fixture = self.preservation_fixture(utility, case, command)
                settings_path.write_bytes(
                    json.dumps(fixture, indent=2).encode("utf-8") + b"\n"
                )
                before = settings_path.read_bytes()

                result = self.run_install(
                    checkout,
                    utility,
                    home,
                    runtime,
                    mode="--wire",
                    settings=settings_path,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                after = settings_path.read_bytes()
                merged = json.loads(after)
                pretooluse = merged["hooks"]["PreToolUse"]
                own_entries = [
                    entry for entry in pretooluse
                    if any(
                        handler.get("command") == command
                        for handler in entry.get("hooks", [])
                        if isinstance(handler, dict)
                    )
                ]
                self.assertEqual(len(own_entries), 1)
                if case == "append":
                    self.assertIn("wired", result.stdout)
                    self.assertEqual(
                        self.without_owned_entry(merged, command),
                        before,
                    )
                elif case == "current":
                    self.assertIn("already", result.stdout)
                    self.assertEqual(after, before)
                else:
                    self.assertIn("refreshed", result.stdout)
                    self.assertEqual(
                        self.without_owned_entry(merged, command),
                        self.without_owned_entry(json.loads(before), command),
                    )

    def test_wire_refreshes_org_rule_guard_legacy_entry_in_place(self):
        """The one documented org-rule-guard legacy shape is upgraded in place."""
        checkout = self.stage_checkout()
        home = self.temp_dir("legacy-wire-home-")
        runtime = self.temp_dir("legacy-wire-runtime-")
        settings = home / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        command = f"python3 {home / '.claude/hooks/org-rule-guard.py'}"
        settings.write_text(
            json.dumps(
                {
                    "model": "opus",
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": "Read",
                                "hooks": [{
                                    "type": "command",
                                    "command": "printf unrelated",
                                }],
                            },
                            {
                                "matcher": "Write|Edit|Bash",
                                "hooks": [{
                                    "type": "command",
                                    "command": command,
                                    "timeout": 10,
                                }],
                            },
                        ],
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        result = self.run_install(
            checkout, "org-rule-guard", home, runtime,
            mode="--wire", settings=settings,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("refreshed", result.stdout)
        self.assertEqual(result.stderr, "")
        merged = json.loads(settings.read_text(encoding="utf-8"))
        pretooluse = merged["hooks"]["PreToolUse"]
        self.assertEqual(len(pretooluse), 2)
        self.assertEqual(pretooluse[0]["matcher"], "Read")
        self.assertEqual(pretooluse[1], {
            "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash",
            "hooks": [{
                "type": "command",
                "command": command,
                "timeout": 10,
            }],
        })

    def test_wire_reports_customized_entry_and_exits_two_without_changes(self):
        """Customized exact-command wiring is reported on stderr as a conflict."""
        for utility in ("agent-secrets", "org-rule-guard"):
            with self.subTest(utility=utility):
                checkout = self.stage_checkout()
                home = self.temp_dir(f"custom-wire-home-{utility}-")
                runtime = self.temp_dir(f"custom-wire-runtime-{utility}-")
                settings = home / ".claude" / "settings.json"
                settings.parent.mkdir(parents=True)
                hook_name = (
                    "credential-guard.py"
                    if utility == "agent-secrets"
                    else "org-rule-guard.py"
                )
                command = f"python3 {home / '.claude/hooks' / hook_name}"
                original = {
                    "model": "opus",
                    "hooks": {
                        "PreToolUse": [{
                            "matcher": "Read",
                            "hooks": [{
                                "type": "command",
                                "command": command,
                                "timeout": 7,
                                "operator_note": "keep this",
                            }],
                            "operator_note": "keep this too",
                        }],
                    },
                }
                settings.write_text(
                    json.dumps(original, indent=2) + "\n", encoding="utf-8"
                )
                before = settings.read_bytes()

                result = self.run_install(
                    checkout, utility, home, runtime,
                    mode="--wire", settings=settings,
                )

                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertEqual(settings.read_bytes(), before)
                self.assertFalse(Path(str(settings) + ".bak").exists())
                self.assertEqual(result.stderr.count("preserved"), 1)
                self.assertIn("customized", result.stderr)
                self.assertIn("(exit 2)", result.stderr)
                self.assertIn("use --wire --force", result.stderr)
                self.assertNotIn("customized", result.stdout)

    def test_wire_force_replaces_customized_fields_and_preserves_other_fields(self):
        """--force changes only matcher/timeout on every exact-command match."""
        for utility in ("agent-secrets", "org-rule-guard"):
            with self.subTest(utility=utility):
                checkout = self.stage_checkout()
                home = self.temp_dir(f"force-wire-home-{utility}-")
                runtime = self.temp_dir(f"force-wire-runtime-{utility}-")
                settings = home / ".claude" / "settings.json"
                settings.parent.mkdir(parents=True)
                hook_name = (
                    "credential-guard.py"
                    if utility == "agent-secrets"
                    else "org-rule-guard.py"
                )
                command = f"python3 {home / '.claude/hooks' / hook_name}"
                original = {
                    "model": "opus",
                    "hooks": {
                        "PreToolUse": [{
                            "matcher": "Read",
                            "hooks": [{
                                "type": "command",
                                "command": command,
                                "timeout": 7,
                                "operator_note": "keep this",
                            }],
                            "operator_note": "keep this too",
                        }],
                    },
                }
                settings.write_text(
                    json.dumps(original, indent=2) + "\n", encoding="utf-8"
                )

                result = self.run_install(
                    checkout, utility, home, runtime,
                    mode="--wire --force", settings=settings,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("refreshed", result.stdout)
                self.assertEqual(result.stderr, "")
                merged = json.loads(settings.read_text(encoding="utf-8"))
                entry = merged["hooks"]["PreToolUse"][0]
                handler = entry["hooks"][0]
                self.assertEqual(entry["matcher"], "Write|Edit|MultiEdit|NotebookEdit|Bash")
                self.assertEqual(handler["command"], command)
                self.assertEqual(handler["type"], "command")
                self.assertEqual(handler["operator_note"], "keep this")
                self.assertEqual(entry["operator_note"], "keep this too")
                self.assertEqual(handler["timeout"], 10)
                self.assertEqual(merged["model"], "opus")

    def test_both_installers_conform_to_one_lock_and_merge_concurrently(self):
        """The independent installers serialize through the same effective lock."""
        checkout = self.stage_checkout()
        home = self.temp_dir("cross-utility-wire-home-")
        runtime = self.temp_dir("cross-utility-wire-runtime-")
        real_settings = home / "custom" / "settings.json"
        settings_alias = home / "settings-alias.json"
        real_settings.parent.mkdir(parents=True)
        real_settings.write_text(
            json.dumps(
                {
                    "model": "opus",
                    "permissions": {"allow": ["Read"]},
                    "hooks": {
                        "SessionStart": [{
                            "hooks": [{
                                "type": "command",
                                "command": "printf session-start",
                            }],
                        }],
                        "PreToolUse": [{
                            "matcher": "Read",
                            "hooks": [{
                                "type": "command",
                                "command": "printf existing-pretooluse",
                            }],
                        }],
                        "PostToolUse": [{
                            "matcher": "Write",
                            "hooks": [{
                                "type": "command",
                                "command": "printf post-tooluse",
                            }],
                        }],
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        settings_alias.symlink_to(real_settings)
        expected_lock = Path(str(real_settings.resolve()) + ".lock")
        original = real_settings.read_bytes()

        reported_lock_paths = []
        for utility in ("org-rule-guard", "agent-secrets"):
            holder = self.hold_settings_lock(expected_lock)
            try:
                environment = self.clean_environment(home)
                environment["CLAUDE_SETTINGS"] = str(settings_alias)
                environment["CLAUDE_SETTINGS_LOCK_TIMEOUT"] = "0.5"
                result = subprocess.run(
                    ["/bin/sh", str(checkout / utility / "install.sh"), "--wire"],
                    cwd=runtime,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            finally:
                self.release_settings_lock(holder)

            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("could not acquire settings lock", result.stderr)
            lock_message = result.stderr.split(
                "could not acquire settings lock ", 1
            )[1]
            reported_lock_paths.append(lock_message.split(" within", 1)[0])
            self.assertEqual(real_settings.read_bytes(), original)

        self.assertEqual(reported_lock_paths, [str(expected_lock)] * 2)

        holder = self.hold_settings_lock(expected_lock)
        processes = self.run_concurrent_wire(
            checkout, home, runtime, settings_alias
        )
        try:
            time.sleep(0.2)
            self.assertTrue(
                any(process.poll() is None for process in processes),
                "neither installer remained blocked on the shared settings lock",
            )
            self.release_settings_lock(holder)
            holder = None
            results = [process.communicate(timeout=30) for process in processes]
        finally:
            if holder is not None:
                self.release_settings_lock(holder)
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait()

        for process, result in zip(processes, results):
            self.assertEqual(process.returncode, 0, result[1] + result[0])

        merged = json.loads(real_settings.read_text(encoding="utf-8"))
        self.assertEqual(merged["model"], "opus")
        self.assertEqual(merged["permissions"], {"allow": ["Read"]})
        self.assertEqual(
            merged["hooks"]["SessionStart"],
            [{"hooks": [{"type": "command", "command": "printf session-start"}]}],
        )
        self.assertEqual(
            merged["hooks"]["PostToolUse"],
            [{
                "matcher": "Write",
                "hooks": [{"type": "command", "command": "printf post-tooluse"}],
            }],
        )
        pretooluse = merged["hooks"]["PreToolUse"]
        self.assertEqual(pretooluse[0]["hooks"][0]["command"], "printf existing-pretooluse")
        entries = {
            entry["hooks"][0]["command"]: entry
            for entry in pretooluse[1:]
        }
        self.assertEqual(
            set(entries),
            {
                f"python3 {home / '.claude/hooks/org-rule-guard.py'}",
                f"python3 {home / '.claude/hooks/credential-guard.py'}",
            },
        )
        self.assertEqual(
            entries[f"python3 {home / '.claude/hooks/org-rule-guard.py'}"],
            {
                "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash",
                "hooks": [{
                    "type": "command",
                    "command": f"python3 {home / '.claude/hooks/org-rule-guard.py'}",
                    "timeout": 10,
                }],
            },
        )
        self.assertEqual(
            entries[f"python3 {home / '.claude/hooks/credential-guard.py'}"],
            {
                "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash",
                "hooks": [{
                    "type": "command",
                    "command": f"python3 {home / '.claude/hooks/credential-guard.py'}",
                    "timeout": 10,
                }],
            },
        )
        self.assertTrue(settings_alias.is_symlink())
        self.assertEqual(
            [path.name for path in real_settings.parent.glob("*.lock")],
            [expected_lock.name],
        )
        self.assertEqual(list(settings_alias.parent.glob("*.lock")), [])

    def test_declared_bundle_installs_and_runs_without_checkout(self):
        declaration = self.bundle_declaration()
        checkout = self.stage_checkout()
        home = self.temp_dir("install-bundle-home-")
        runtime = self.temp_dir("install-bundle-runtime-")
        state = self.temp_dir("install-bundle-state-")

        source = checkout / declaration["utility"] / PurePosixPath(declaration["source"])
        source_bytes = source.read_bytes()
        source_version = (
            (checkout / declaration["utility"] / "VERSION")
            .read_text(encoding="utf-8")
            .splitlines()[0]
            .strip()
        )
        self.assertEqual(source_version, declaration["version"])

        result = self.run_install(checkout, "org-rule-guard", home, runtime)

        self.assertEqual(result.returncode, 0, result.stderr)
        hook_dst = home / ".claude" / "hooks" / "org-rule-guard.py"
        bundle_root = hook_dst.with_suffix("")
        bundle_dst = bundle_root / PurePosixPath(declaration["destination"])
        self.assertTrue(hook_dst.is_file(), result.stdout)
        self.assertTrue(bundle_dst.is_file(), result.stdout)
        self.assertEqual(bundle_dst.read_bytes(), source_bytes)
        self.assertEqual(stat.S_IMODE(bundle_dst.stat().st_mode), 0o755)
        self.assertEqual(bundle_dst.parent, bundle_root)
        self.assertFalse((home / "agent-secrets").exists())

        shutil.rmtree(checkout)
        self.assertFalse(checkout.exists())

        org_payload = {
            "tool_name": "Bash",
            "tool_input": {
                "command": "kubectl" + " delete pod worker-0 -n default",
            },
        }
        org_result = self.run_installed_hook(
            hook_dst, home, runtime, org_payload, state
        )
        self.assertEqual(org_result.returncode, 0, org_result.stderr)
        org_decision = json.loads(org_result.stdout)
        self.assertEqual(
            org_decision["hookSpecificOutput"]["permissionDecision"], "deny"
        )

        credential_payload = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": str(runtime / "notes.md"),
                "content": "token = " + token("ghp_", 36, seed=3),
            },
        }
        credential_result = self.run_installed_hook(
            bundle_dst, home, runtime, credential_payload, state
        )
        self.assertEqual(credential_result.returncode, 0, credential_result.stderr)
        credential_decision = json.loads(credential_result.stdout)
        self.assertEqual(
            credential_decision["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertIn("GitHub token", credential_decision["hookSpecificOutput"][
            "permissionDecisionReason"
        ])

    def test_install_rejects_stale_sibling_version_before_writing(self):
        declaration = self.bundle_declaration()
        checkout = self.stage_checkout()
        home = self.temp_dir("install-bundle-stale-home-")
        runtime = self.temp_dir("install-bundle-stale-runtime-")
        stale_version = "0.0.1"
        (checkout / declaration["utility"] / "VERSION").write_text(
            stale_version + "\n", encoding="utf-8"
        )

        result = self.run_install(checkout, "org-rule-guard", home, runtime)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "agent-secrets VERSION is %s, expected pinned %s"
            % (stale_version, declaration["version"]),
            result.stderr,
        )
        self.assertFalse((home / ".claude").exists())

    def test_install_requires_python39_before_writing(self):
        checkout = self.stage_checkout()
        missing_bin = self.temp_dir("missing-python3-bin-")
        (missing_bin / "dirname").symlink_to(shutil.which("dirname"))

        old_bin = self.temp_dir("old-python3-bin-")
        (old_bin / "dirname").symlink_to(shutil.which("dirname"))
        old_python = old_bin / "python3"
        old_python.write_text(
            "#!/bin/sh\nprintf '%s\\n' '3.8.18'\nexit 1\n",
            encoding="utf-8",
        )
        old_python.chmod(0o755)

        cases = (
            (
                "missing",
                missing_bin,
                "a working python3 interpreter is missing or could not start",
            ),
            ("too-old", old_bin, "found Python 3.8.18"),
        )
        for utility in ("agent-secrets", "org-rule-guard"):
            for name, path, detail in cases:
                with self.subTest(utility=utility, runtime=name):
                    home = self.temp_dir(
                        "python-prerequisite-home-%s-%s-" % (utility, name)
                    )
                    runtime = self.temp_dir(
                        "python-prerequisite-runtime-%s-%s-" % (utility, name)
                    )
                    result = self.run_install(
                        checkout, utility, home, runtime,
                        env_overrides={"PATH": str(path)},
                    )

                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("Python 3.9 or newer is required", result.stderr)
                    self.assertIn(detail, result.stderr)
                    self.assertIn("Installation aborted", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertFalse((home / ".claude").exists())

    def test_structure_check_rejects_manifest_pin_mismatched_with_sibling(self):
        checkout_parent = self.temp_dir("install-bundle-mismatch-")
        checkout = checkout_parent / "checkout"
        shutil.copytree(
            ROOT,
            checkout,
            ignore=shutil.ignore_patterns(".git", ".beads", "__pycache__"),
        )
        declaration_path = checkout / "org-rule-guard" / "bundled-dependencies.json"
        data = json.loads(declaration_path.read_text(encoding="utf-8"))
        declaration = data["bundles"][0]
        sibling_version = (
            (checkout / declaration["utility"] / "VERSION")
            .read_text(encoding="utf-8")
            .splitlines()[0]
            .strip()
        )
        mismatch = "9.9.9"
        self.assertNotEqual(mismatch, sibling_version)
        declaration["version"] = mismatch
        declaration_path.write_text(json.dumps(data), encoding="utf-8")

        result = subprocess.run(
            [sys.executable, "scripts/check-structure.py"],
            cwd=checkout,
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "pinned version '%s' does not match %s/VERSION ('%s')"
            % (mismatch, checkout / declaration["utility"], sibling_version),
            result.stderr,
        )

    def test_reinstall_reports_previous_provenance_before_replacing_agent_secrets(self):
        first = self.stage_release("agent-secrets")
        second = self.stage_release("agent-secrets")
        new_version = "0.2.0"
        (second / "agent-secrets" / "VERSION").write_text(
            new_version + "\n", encoding="utf-8"
        )
        home = self.temp_dir("agent-secrets-reinstall-home-")
        runtime = self.temp_dir("agent-secrets-reinstall-runtime-")

        initial = self.run_install(first, "agent-secrets", home, runtime)
        self.assertEqual(initial.returncode, 0, initial.stderr)
        replacement = self.run_install(
            second, "agent-secrets", home, runtime, "--force"
        )

        self.assertEqual(replacement.returncode, 0, replacement.stderr)
        self.assertIn("previously installed agent-secrets v0.1.0", replacement.stdout)
        _, provenance = self.read_provenance(home, "agent-secrets")
        self.assertEqual(provenance["version"], new_version)
        installed_before_status = self.installed_file_snapshot(home)
        status = self.run_install(
            second,
            "agent-secrets",
            home,
            runtime,
            "--status",
            env_overrides={"PATH": str(self.status_path("agent-secrets-upgrade-status-bin-"))},
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout), provenance)
        self.assertEqual(self.installed_file_snapshot(home), installed_before_status)

    def test_reinstall_reports_previous_bundle_provenance_before_replacing_org_guard(self):
        first = self.stage_checkout()
        second = self.stage_checkout()
        new_version = "0.2.0"
        (second / "agent-secrets" / "VERSION").write_text(
            new_version + "\n", encoding="utf-8"
        )
        (second / "org-rule-guard" / "VERSION").write_text(
            new_version + "\n", encoding="utf-8"
        )
        manifest_path = second / "org-rule-guard" / "bundled-dependencies.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["bundles"][0]["version"] = new_version
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        home = self.temp_dir("org-rule-guard-reinstall-home-")
        runtime = self.temp_dir("org-rule-guard-reinstall-runtime-")

        initial = self.run_install(first, "org-rule-guard", home, runtime)
        self.assertEqual(initial.returncode, 0, initial.stderr)
        replacement = self.run_install(
            second, "org-rule-guard", home, runtime, "--force"
        )

        self.assertEqual(replacement.returncode, 0, replacement.stderr)
        self.assertIn("previously installed org-rule-guard v0.1.0", replacement.stdout)
        self.assertIn("previously bundled agent-secrets v0.1.0", replacement.stdout)
        _, provenance = self.read_provenance(home, "org-rule-guard")
        self.assertEqual(provenance["version"], new_version)
        self.assertEqual(provenance["bundles"][0]["version"], new_version)
        installed_before_status = self.installed_file_snapshot(home)
        status = self.run_install(
            second,
            "org-rule-guard",
            home,
            runtime,
            "--status",
            env_overrides={"PATH": str(self.status_path("org-rule-guard-upgrade-status-bin-"))},
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout), provenance)
        self.assertEqual(self.installed_file_snapshot(home), installed_before_status)


if __name__ == "__main__":
    unittest.main(verbosity=2)
