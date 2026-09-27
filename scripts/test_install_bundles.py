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

    def run_install(self, checkout, utility, home, runtime):
        script = checkout / utility / "install.sh"
        return subprocess.run(
            ["/bin/sh", str(script)],
            cwd=runtime,
            env=self.clean_environment(home),
            capture_output=True,
            text=True,
            timeout=30,
        )

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
