#!/usr/bin/env python3
"""Regression tests for scripts/check-structure.py.

The checker is exercised in disposable repository-shaped directories so each
test can control the top-level utility layout independently.

    python3 -m unittest discover -s scripts -v
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
CHECKER = Path(os.environ.get("CHECK_STRUCTURE_UNDER_TEST", HERE / "check-structure.py"))


class StructureCheckerTests(unittest.TestCase):
    """Run the structure checker against runtime-built fixtures."""

    def setUp(self):
        self.fixture = Path(tempfile.mkdtemp(prefix="check-structure-"))
        self.addCleanup(shutil.rmtree, self.fixture, ignore_errors=True)

        scripts = self.fixture / "scripts"
        scripts.mkdir()
        shutil.copy2(CHECKER, scripts / "check-structure.py")

    def write_utility(self, name):
        utility = self.fixture / name
        utility.mkdir(parents=True, exist_ok=True)
        (utility / "README.md").write_text(f"# {name}\n", encoding="utf-8")
        (utility / "VERSION").write_text("1.0.0\n", encoding="utf-8")
        install = utility / "install.sh"
        install.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        install.chmod(install.stat().st_mode | stat.S_IXUSR)
        return utility

    def write_readme(self):
        utilities = sorted(
            path.name
            for path in self.fixture.iterdir()
            if path.is_dir() and path.name not in {"docs", "scripts"}
        )
        rows = "\n".join(
            f"| [`{name}/`]({name}/) | test utility |" for name in utilities
        )
        (self.fixture / "README.md").write_text(
            "# test utilities\n\n"
            "| Folder | What it is |\n"
            "|---|---|\n"
            f"{rows}\n",
            encoding="utf-8",
        )

    def write_wiring_utility(self, name, hook_name, timeout=None):
        utility = self.write_utility(name)
        timeout_field = ""
        if timeout is not None:
            timeout_field = f', "timeout": {timeout}'
        (utility / "install.sh").write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            'mkdir -p "$HOME/.claude/hooks"\n'
            'python3 - "$CLAUDE_SETTINGS" "$HOME/.claude/hooks/'
            f'{hook_name}" <<\'PY\'\n'
            "import json, os, sys\n"
            "path, hook = sys.argv[1:]\n"
            "settings = {}\n"
            "if os.path.exists(path):\n"
            "    with open(path) as handle:\n"
            "        settings = json.load(handle)\n"
            "settings.setdefault(\"hooks\", {}).setdefault(\"PreToolUse\", []).append({\n"
            "    \"matcher\": \"Write|Edit|MultiEdit|Bash\",\n"
            f'    "hooks": [{{"type": "command", "command": "python3 " + hook{timeout_field}}}]\n'
            "})\n"
            "with open(path, \"w\") as handle:\n"
            "    json.dump(settings, handle)\n"
            "PY\n",
            encoding="utf-8",
        )
        (utility / "install.sh").chmod(
            (utility / "install.sh").stat().st_mode | stat.S_IXUSR
        )

    def write_wiring_fixture(self):
        self.write_wiring_utility("agent-secrets", "credential-guard.py")
        self.write_wiring_utility("org-rule-guard", "org-rule-guard.py", timeout=10)
        docs = self.fixture / "docs" / "examples"
        docs.mkdir(parents=True)
        (docs / "settings-both.json").write_text(
            json.dumps({
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Write|Edit|MultiEdit|Bash",
                            "hooks": [{
                                "type": "command",
                                "command": "python3 ~/.claude/hooks/org-rule-guard.py",
                                "timeout": 10,
                            }],
                        },
                        {
                            "matcher": "Write|Edit|MultiEdit|Bash",
                            "hooks": [{
                                "type": "command",
                                "command": "python3 ~/.claude/hooks/credential-guard.py",
                            }],
                        },
                    ]
                }
            }),
            encoding="utf-8",
        )
        self.write_readme()

    def run_checker(self):
        return subprocess.run(
            [sys.executable, "scripts/check-structure.py"],
            cwd=self.fixture,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_valid_utility_passes(self):
        self.write_utility("alpha")
        self.write_readme()

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 utilities have README.md, VERSION, install.sh", result.stdout)

    def test_combined_settings_wiring_matches_both_installers(self):
        self.write_wiring_fixture()

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("combined hook settings agree", result.stdout)

    def test_combined_settings_timeout_drift_fails(self):
        self.write_wiring_fixture()
        settings_path = self.fixture / "docs" / "examples" / "settings-both.json"
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        settings["hooks"]["PreToolUse"][1]["hooks"][0]["timeout"] = 10
        settings_path.write_text(json.dumps(settings), encoding="utf-8")

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PreToolUse wiring does not match", result.stderr)

    def test_combined_settings_matcher_drift_fails(self):
        self.write_wiring_fixture()
        settings_path = self.fixture / "docs" / "examples" / "settings-both.json"
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        settings["hooks"]["PreToolUse"][0]["matcher"] = "Write|Edit|Bash"
        settings_path.write_text(json.dumps(settings), encoding="utf-8")

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PreToolUse wiring does not match", result.stderr)

    def test_combined_settings_invalid_json_fails(self):
        self.write_wiring_fixture()
        settings_path = self.fixture / "docs" / "examples" / "settings-both.json"
        settings_path.write_text("{\n", encoding="utf-8")

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("settings-both.json: invalid JSON", result.stderr)

    def test_non_posix_shell_shebang_fails(self):
        utility = self.write_utility("alpha")
        install = utility / "install.sh"
        install.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        self.write_readme()

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("shell script must use a POSIX sh shebang", result.stderr)

    def test_package_manager_install_fails(self):
        utility = self.write_utility("alpha")
        install = utility / "install.sh"
        install.write_text(
            "#!/bin/sh\n"
            "python3 -m pip install requests\n",
            encoding="utf-8",
        )
        self.write_readme()

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"{install}:2: package-manager command 'pip'",
            result.stderr,
        )

    def test_non_stdlib_python_import_fails(self):
        utility = self.write_utility("alpha")
        runtime_file = utility / "hooks" / "hook.py"
        runtime_file.parent.mkdir()
        runtime_file.write_text("import requests\n", encoding="utf-8")
        self.write_readme()

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"{runtime_file}:1: non-stdlib Python import 'requests'",
            result.stderr,
        )

    def test_import_from_same_utility_passes(self):
        utility = self.write_utility("alpha")
        (utility / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
        runtime_file = utility / "hooks" / "hook.py"
        runtime_file.parent.mkdir()
        runtime_file.write_text("from helper import VALUE\n", encoding="utf-8")
        self.write_readme()

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_required_file_fails_with_file_named(self):
        for missing in ("README.md", "VERSION", "install.sh"):
            with self.subTest(missing=missing):
                self.write_utility("alpha")
                (self.fixture / "alpha" / missing).unlink()
                self.write_readme()

                result = self.run_checker()

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f"alpha/{missing}: required file is missing",
                    result.stderr,
                )

                shutil.rmtree(self.fixture / "alpha")

    def test_symlinked_required_file_fails(self):
        utility = self.write_utility("alpha")
        owned_readme = utility / "README-owned.md"
        owned_readme.write_text("# alpha\n", encoding="utf-8")
        (utility / "README.md").unlink()
        (utility / "README.md").symlink_to(owned_readme)
        self.write_readme()

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"{utility / 'README.md'}: required file must be owned, not a symlink",
            result.stderr,
        )

    def test_symlinked_utility_directory_fails(self):
        self.write_utility("canonical")
        (self.fixture / "alias").symlink_to(self.fixture / "canonical", target_is_directory=True)
        self.write_readme()

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"{self.fixture / 'alias'}: utility directory must be owned, not a symlink",
            result.stderr,
        )

    def test_external_symlink_inside_utility_fails(self):
        utility = self.write_utility("alpha")
        outside = Path(tempfile.mkdtemp(prefix="check-structure-target-"))
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        target = outside / "shared.sh"
        target.write_text("#!/bin/sh\n", encoding="utf-8")
        link = utility / "shared.sh"
        link.symlink_to(target)
        self.write_readme()

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("shared.sh: symlink resolves outside alpha/", result.stderr)

    def test_runtime_reference_to_sibling_fails(self):
        alpha = self.write_utility("alpha")
        self.write_utility("beta")
        runtime_file = alpha / "bin" / "use-beta.py"
        runtime_file.parent.mkdir()
        runtime_file.write_text(
            "subprocess.run(['../beta/install.sh'], check=True)\n",
            encoding="utf-8",
        )
        self.write_readme()

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"{runtime_file}:1: runtime reference to sibling utility 'beta'",
            result.stderr,
        )

    def test_python_import_of_sibling_fails(self):
        alpha = self.write_utility("alpha")
        self.write_utility("beta")
        runtime_file = alpha / "bin" / "use-beta.py"
        runtime_file.parent.mkdir()
        runtime_file.write_text("from beta import helper\n", encoding="utf-8")
        self.write_readme()

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"{runtime_file}:1: runtime reference to sibling utility 'beta'",
            result.stderr,
        )

    def test_declared_pinned_bundle_copy_passes(self):
        alpha = self.write_utility("alpha")
        beta = self.write_utility("beta")
        source = beta / "hooks" / "credential.py"
        source.parent.mkdir()
        source.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        (alpha / "bundled-dependencies.json").write_text(
            json.dumps({
                "bundles": [{
                    "utility": "beta",
                    "version": "1.0.0",
                    "source": "hooks/credential.py",
                    "destination": "credential.py",
                }]
            }),
            encoding="utf-8",
        )
        install = alpha / "install.sh"
        install.write_text(
            "#!/bin/sh\n"
            'install -m 755 "$HERE/../beta/hooks/credential.py" "$DEST"\n',
            encoding="utf-8",
        )
        install.chmod(install.stat().st_mode | stat.S_IXUSR)
        self.write_readme()

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_undeclared_install_time_sibling_reference_fails(self):
        alpha = self.write_utility("alpha")
        self.write_utility("beta")
        install = alpha / "install.sh"
        install.write_text(
            "#!/bin/sh\n"
            'install -m 755 "$HERE/../beta/hooks/credential.py" "$DEST"\n',
            encoding="utf-8",
        )
        install.chmod(install.stat().st_mode | stat.S_IXUSR)
        self.write_readme()

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"{install}:2: install-time reference to sibling utility 'beta' "
            "is not a declared pinned bundle",
            result.stderr,
        )

    def test_pinned_bundle_does_not_allow_runtime_sibling_reference(self):
        alpha = self.write_utility("alpha")
        beta = self.write_utility("beta")
        source = beta / "hooks" / "credential.py"
        source.parent.mkdir()
        source.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        (alpha / "bundled-dependencies.json").write_text(
            json.dumps({
                "bundles": [{
                    "utility": "beta",
                    "version": "1.0.0",
                    "source": "hooks/credential.py",
                    "destination": "credential.py",
                }]
            }),
            encoding="utf-8",
        )
        install = alpha / "install.sh"
        install.write_text(
            "#!/bin/sh\n"
            'install -m 755 "$HERE/../beta/hooks/credential.py" "$DEST"\n',
            encoding="utf-8",
        )
        install.chmod(install.stat().st_mode | stat.S_IXUSR)
        runtime_file = alpha / "bin" / "use-beta.py"
        runtime_file.parent.mkdir()
        runtime_file.write_text(
            "subprocess.run(['../beta/hooks/credential.py'], check=True)\n",
            encoding="utf-8",
        )
        self.write_readme()

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"{runtime_file}:1: runtime reference to sibling utility 'beta'",
            result.stderr,
        )

    def test_bundle_version_must_match_sibling_version(self):
        alpha = self.write_utility("alpha")
        beta = self.write_utility("beta")
        source = beta / "hooks" / "credential.py"
        source.parent.mkdir()
        source.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        (alpha / "bundled-dependencies.json").write_text(
            json.dumps({
                "bundles": [{
                    "utility": "beta",
                    "version": "9.9.9",
                    "source": "hooks/credential.py",
                    "destination": "credential.py",
                }]
            }),
            encoding="utf-8",
        )
        install = alpha / "install.sh"
        install.write_text(
            "#!/bin/sh\n"
            'install -m 755 "$HERE/../beta/hooks/credential.py" "$DEST"\n',
            encoding="utf-8",
        )
        install.chmod(install.stat().st_mode | stat.S_IXUSR)
        self.write_readme()

        result = self.run_checker()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"pinned version '9.9.9' does not match {beta}/VERSION ('1.0.0')",
            result.stderr,
        )

    def test_non_utility_top_level_directories_are_exempt(self):
        self.write_utility("alpha")
        docs = self.fixture / "docs"
        docs.mkdir()
        (docs / "example.py").write_text(
            "from alpha import helper\n",
            encoding="utf-8",
        )
        (self.fixture / "scripts" / "repo-helper.py").write_text(
            "subprocess.run(['../alpha/install.sh'], check=True)\n",
            encoding="utf-8",
        )
        self.write_readme()

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
