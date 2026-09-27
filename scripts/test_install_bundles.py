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

    def run_install(self, checkout, utility, home, runtime, mode=None, settings=None):
        script = checkout / utility / "install.sh"
        command = ["/bin/sh", str(script)]
        if mode is not None:
            command.append(mode)
        environment = self.clean_environment(home)
        if settings is not None:
            environment["CLAUDE_SETTINGS"] = str(settings)
        return subprocess.run(
            command,
            cwd=runtime,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def read_provenance(self, home, utility):
        if utility == "agent-secrets":
            path = home / ".claude" / "hooks" / "agent-secrets" / "provenance.json"
        else:
            path = (
                home
                / ".claude"
                / "hooks"
                / "org-rule-guard"
                / "provenance.json"
            )
        return path, json.loads(path.read_text(encoding="utf-8"))

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
            {"utility": "agent-secrets", "version": version, "bundles": []},
        )
        status = self.run_install(release, "agent-secrets", home, runtime, "--status")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout), provenance)
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
                "bundles": [declaration],
            },
        )
        status = self.run_install(release, "org-rule-guard", home, runtime, "--status")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout), provenance)
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
                "matcher": "Write|Edit|MultiEdit|Bash",
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
                "matcher": "Write|Edit|MultiEdit|Bash",
                "hooks": [{
                    "type": "command",
                    "command": f"python3 {home / '.claude/hooks/credential-guard.py'}",
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
