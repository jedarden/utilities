#!/usr/bin/env python3
"""Regression tests for scripts/check-versions.sh.

The checker is exercised in disposable Git repositories so every test can
control both the VERSION files at HEAD and the commits named by tags.  The
fixtures include the structural checker because check-versions.sh invokes it
before checking the VERSION/tag contract.

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
CHECKER = Path(os.environ.get("CHECK_VERSIONS_UNDER_TEST", HERE / "check-versions.sh"))
STRUCTURE_CHECKER = HERE / "check-structure.py"


class VersionCheckerTests(unittest.TestCase):
    """Run the shell checker against runtime-built Git fixtures."""

    def setUp(self):
        self.fixture = Path(tempfile.mkdtemp(prefix="check-versions-"))
        self.addCleanup(shutil.rmtree, self.fixture, ignore_errors=True)
        self.utility_names = []

        self.git("init", "--quiet", "-b", "main")
        self.git("config", "user.email", "check-versions-test@example.invalid")
        self.git("config", "user.name", "check-versions test")
        scripts = self.fixture / "scripts"
        scripts.mkdir()
        shutil.copy2(STRUCTURE_CHECKER, scripts / "check-structure.py")

    def git(self, *args, check=True):
        return subprocess.run(
            ["git", "-C", str(self.fixture), *args],
            check=check,
            capture_output=True,
            text=True,
        )

    def write_utility(self, name, version):
        if name not in self.utility_names:
            self.utility_names.append(name)
        utility = self.fixture / name
        utility.mkdir(parents=True, exist_ok=True)
        (utility / "README.md").write_text(f"# {name}\n", encoding="utf-8")
        (utility / "VERSION").write_text(f"{version}\n", encoding="utf-8")
        (utility / "CHANGELOG.md").write_text(
            f"# Changelog\n\n## [{version}] - 2026-01-01\n\n- Initial release.\n",
            encoding="utf-8",
        )
        install = utility / "install.sh"
        install.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        install.chmod(install.stat().st_mode | stat.S_IXUSR)

    def write_readme(self):
        rows = "\n".join(
            f"| [`{name}/`]({name}/) | test utility |"
            for name in sorted(
                name for name in self.utility_names if (self.fixture / name).is_dir()
            )
        )
        (self.fixture / "README.md").write_text(
            "# test utilities\n\n"
            "| Folder | What it is |\n"
            "|---|---|\n"
            f"{rows}\n",
            encoding="utf-8",
        )

    def commit(self, message):
        self.write_readme()
        paths = ["scripts/check-structure.py"] + [
            name for name in self.utility_names if (self.fixture / name).exists()
        ]
        self.git("add", "README.md", *paths)
        self.git("add", "--update", "--", *self.utility_names)
        self.git("commit", "--quiet", "-m", message)

    def tag(self, name, revision="HEAD"):
        self.git("tag", name, revision)

    def run_checker(self):
        return subprocess.run(
            [str(CHECKER)],
            cwd=self.fixture,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_version_at_head_without_matching_tag_fails(self):
        self.write_utility("widget", "1.2.3")
        self.commit("add widget")

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no tag widget/v1.2.3", result.stderr)

    def test_tag_pointing_at_disagreeing_version_fails(self):
        self.write_utility("widget", "1.0.0")
        self.commit("add widget 1.0.0")
        old_revision = self.git("rev-parse", "HEAD").stdout.strip()

        (self.fixture / "widget" / "VERSION").write_text("1.1.0\n", encoding="utf-8")
        (self.fixture / "widget" / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [1.1.0] - 2026-01-02\n\n- Changed release.\n",
            encoding="utf-8",
        )
        self.commit("bump widget to 1.1.0")
        self.tag("widget/v1.1.0", old_revision)

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "tag widget/v1.1.0 points at a commit where widget/VERSION reads '1.0.0', not 1.1.0",
            result.stderr,
        )

    def test_fully_consistent_multi_utility_state_passes(self):
        self.write_utility("alpha", "1.0.0")
        self.write_utility("beta", "2.3.4")
        self.commit("add two utilities")
        self.tag("alpha/v1.0.0")
        self.tag("beta/v2.3.4")

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("2 utilities, VERSION files and tags agree", result.stdout)

    def test_readme_missing_utility_row_fails(self):
        self.write_utility("widget", "1.0.0")
        self.commit("add widget")
        self.tag("widget/v1.0.0")
        readme = self.fixture / "README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8").replace(
                "| [`widget/`](widget/) | test utility |\n", ""
            ),
            encoding="utf-8",
        )

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "utility folder 'widget' is missing from the Folder table",
            result.stderr,
        )

    def test_readme_row_for_missing_utility_fails(self):
        self.write_utility("widget", "1.0.0")
        self.commit("add widget")
        self.tag("widget/v1.0.0")
        readme = self.fixture / "README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8").replace(
                "| [`widget/`](widget/) | test utility |\n",
                "| [`widget/`](widget/) | test utility |\n"
                "| [`ghost/`](ghost/) | test utility |\n",
            ),
            encoding="utf-8",
        )

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Folder table names missing utility folder 'ghost'",
            result.stderr,
        )

    def test_tagged_commit_without_version_fails(self):
        self.git("commit", "--quiet", "--allow-empty", "-m", "empty initial commit")
        self.tag("ghost/v0.1.0")
        self.write_utility("ghost", "0.1.0")
        self.commit("add ghost after its tag")

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tag ghost/v0.1.0 points at a commit with no ghost/VERSION", result.stderr)

    def test_missing_version_files_at_head_with_old_tag_fails(self):
        self.write_utility("widget", "1.0.0")
        self.commit("add widget")
        self.tag("widget/v1.0.0")
        shutil.rmtree(self.fixture / "widget")
        self.commit("remove widget")

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no */VERSION files at HEAD but */v* tags exist", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
