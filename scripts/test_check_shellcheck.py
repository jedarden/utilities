#!/usr/bin/env python3
"""Regression tests for scripts/check-shellcheck.sh.

The tests use a disposable fake ShellCheck executable so they cover the
version gate without depending on the host's installed tool version.

    python3 -m unittest discover -s scripts -v
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
CHECKER = Path(
    os.environ.get("CHECK_SHELLCHECK_UNDER_TEST", HERE / "check-shellcheck.sh")
)


class ShellCheckVersionTests(unittest.TestCase):
    """Run the wrapper with controlled ShellCheck versions."""

    def setUp(self):
        self.fixture = Path(tempfile.mkdtemp(prefix="check-shellcheck-"))
        self.addCleanup(shutil.rmtree, self.fixture, ignore_errors=True)
        self.bin_dir = self.fixture / "bin"
        self.bin_dir.mkdir()
        self.invocations = self.fixture / "invocations"
        self.environment = os.environ.copy()
        self.environment["PATH"] = f"{self.bin_dir}{os.pathsep}{self.environment['PATH']}"

    def install_fake_shellcheck(self, version, version_exit=0, check_exit=0):
        script = self.bin_dir / "shellcheck"
        script.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = '--version' ]; then\n"
            f"  printf '%s\\n' 'ShellCheck - shell script analysis tool' 'version: {version}'\n"
            f"  exit {version_exit}\n"
            "fi\n"
            f"printf '%s\\n' \"$*\" > {self.invocations}\n"
            f"exit {check_exit}\n",
            encoding="utf-8",
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR)

    def run_checker(self, *args):
        return subprocess.run(
            [str(CHECKER), *args],
            cwd=self.fixture,
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_required_version_runs_shellcheck(self):
        self.install_fake_shellcheck("0.9.0")

        result = self.run_checker("example.sh")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ShellCheck 0.9.0 satisfies the minimum 0.9.0", result.stdout)
        self.assertEqual(self.invocations.read_text(encoding="utf-8"), "example.sh\n")

    def test_newer_version_runs_shellcheck(self):
        self.install_fake_shellcheck("1.0.0")

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.invocations.read_text(encoding="utf-8"),
            "agent-secrets/install.sh agent-secrets/bin/bao-as "
            "org-rule-guard/install.sh scripts/check-versions.sh "
            "scripts/check-shellcheck.sh\n",
        )

    def test_old_version_fails_before_shellcheck(self):
        self.install_fake_shellcheck("0.8.0")

        result = self.run_checker("example.sh")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "ShellCheck 0.8.0 is too old; this repository requires 0.9.0 or newer",
            result.stderr,
        )
        self.assertIn("install ShellCheck 0.9.0 or newer", result.stderr)
        self.assertFalse(self.invocations.exists())

    def test_malformed_version_fails_before_shellcheck(self):
        self.install_fake_shellcheck("development")

        result = self.run_checker("example.sh")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported version 'development'", result.stderr)
        self.assertFalse(self.invocations.exists())

    def test_missing_shellcheck_fails_with_install_guidance(self):
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)
        (self.bin_dir / "bash").symlink_to(bash)
        self.environment["PATH"] = str(self.bin_dir)

        result = self.run_checker("example.sh")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("was not found", result.stderr)
        self.assertIn("install ShellCheck 0.9.0 or newer", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
