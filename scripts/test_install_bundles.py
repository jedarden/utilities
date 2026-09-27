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


class InstallBundleTests(unittest.TestCase):
    """Exercise the actual org-rule-guard installer from isolated fixtures."""

    def temp_dir(self, prefix):
        path = Path(tempfile.mkdtemp(prefix=prefix))
        self.addCleanup(shutil.rmtree, path, ignore_errors=True)
        return path

    def stage_checkout(self):
        checkout = self.temp_dir("install-bundle-checkout-")
        for utility in ("agent-secrets", "org-rule-guard"):
            shutil.copytree(ROOT / utility, checkout / utility)
        return checkout

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
            "PYTHONPATH",
        ):
            env.pop(name, None)
        return env

    def run_install(self, checkout, home, runtime):
        script = checkout / "org-rule-guard" / "install.sh"
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

        result = self.run_install(checkout, home, runtime)

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

        result = self.run_install(checkout, home, runtime)

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
