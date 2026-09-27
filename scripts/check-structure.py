#!/usr/bin/env python3
"""Check the repository's self-contained utility layout.

Top-level directories other than the repository-tooling directories are
utilities.  Each utility owns the small amount of metadata needed to install
it, and its runtime files must use POSIX shell or Python's standard library
without installing packages or reaching into a sibling utility.  This check is
deliberately stdlib-only so it can run in the same minimal CI image as the
other repository checks.
"""

from __future__ import annotations

import ast
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from pathlib import PurePosixPath


REQUIRED_FILES = ("README.md", "VERSION", "install.sh")
BUNDLE_MANIFEST = "bundled-dependencies.json"
REPOSITORY_DIRECTORIES = {"docs", "scripts"}
TEXT_SUFFIXES = {
    ".bash",
    ".conf",
    ".fish",
    ".hcl",
    ".ini",
    ".json",
    ".js",
    ".py",
    ".rb",
    ".sh",
    ".toml",
    ".ts",
    ".yaml",
    ".yml",
    ".zsh",
}
SHELL_SUFFIXES = {".bash", ".dash", ".ksh", ".sh", ".zsh"}
PYTHON_SHEBANG = re.compile(
    r"^#!\s*(?:(?:/usr/bin/env\s+)?|/usr/bin/)?python(?:[0-9.]*)?(?:\s|$)"
)
POSIX_SHELL_SHEBANG = re.compile(
    r"^#!\s*(?:/usr/bin/env\s+)?(?:sh|/bin/sh|/usr/bin/sh)(?:\s|$)"
)
PACKAGE_INSTALL_PATTERNS = (
    ("pip", re.compile(r"\b(?:python(?:3(?:\.[0-9]+)?)?\s+-m\s+)?pip3?\s+install\b")),
    ("uv", re.compile(r"\buv\s+(?:pip\s+)?install\b")),
    ("pipx", re.compile(r"\bpipx\s+install\b")),
    ("poetry", re.compile(r"\bpoetry\s+(?:add|install)\b")),
    ("npm", re.compile(r"\bnpm\s+(?:i|install|ci)\b")),
    ("yarn", re.compile(r"\byarn\s+(?:add|install)\b")),
    ("pnpm", re.compile(r"\bpnpm\s+(?:add|install|i)\b")),
    ("apt", re.compile(r"\bapt(?:-get)?\s+(?:[^;&|\n]*\s+)?(?:install|upgrade)\b")),
    ("apk", re.compile(r"\bapk\s+(?:add|upgrade)\b")),
    ("dnf/yum", re.compile(r"\b(?:dnf|yum)\s+(?:[^;&|\n]*\s+)?(?:install|upgrade)\b")),
    ("Homebrew", re.compile(r"\bbrew\s+install\b")),
    ("pacman", re.compile(r"\bpacman\s+(?:[^;&|\n]*\s+)?-S(?:\s|$)")),
    ("zypper", re.compile(r"\bzypper\s+install\b")),
    ("gem", re.compile(r"\bgem\s+install\b")),
    ("cargo", re.compile(r"\bcargo\s+install\b")),
    ("go", re.compile(r"\bgo\s+install\b")),
)
STDLIB_MODULES = (
    set(getattr(sys, "stdlib_module_names", ()))
    | set(sys.builtin_module_names)
    | {"__future__"}
)
README_TABLE_HEADER = re.compile(r"^\s*\|\s*Folder\s*\|")
README_TABLE_SEPARATOR = re.compile(r"^\s*:?-{3,}:?\s*$")
README_FOLDER_LINK = re.compile(r"^\[([^]]+)\]\(([^)]+)\)$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
COMBINED_SETTINGS = PurePosixPath("docs/examples/settings-both.json")
WIRED_UTILITIES = ("agent-secrets", "org-rule-guard")
SHIPPED_SETTINGS_EXAMPLES = {
    "org-rule-guard": PurePosixPath("examples/settings.json"),
}


def is_utility_directory(path: Path) -> bool:
    """Return whether a direct child is a utility candidate."""

    return path.name not in REPOSITORY_DIRECTORIES and not path.name.startswith(".")


def required_file_errors(utility: Path) -> list[str]:
    errors = []
    for name in REQUIRED_FILES:
        path = utility / name
        if path.is_symlink():
            errors.append(f"{path}: required file must be owned, not a symlink")
        elif not path.is_file():
            errors.append(f"{path}: required file is missing")
    return errors


def symlink_errors(utility: Path) -> list[str]:
    """Reject links that make a utility depend on files outside itself."""

    errors = []
    utility_root = utility.resolve()
    for path in utility.rglob("*"):
        if not path.is_symlink():
            continue
        target = path.resolve(strict=False)
        try:
            target.relative_to(utility_root)
        except ValueError:
            errors.append(
                f"{path}: symlink resolves outside {utility.name}/ "
                f"({target})"
            )
    return errors


def runtime_files(utility: Path):
    """Yield source/config files whose contents can create a dependency."""

    for path in utility.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if path.name in REQUIRED_FILES or path.name == BUNDLE_MANIFEST:
            continue
        try:
            mode = path.stat().st_mode
        except OSError:
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or mode & stat.S_IXUSR:
            yield path


def utility_script_files(utility: Path):
    """Yield utility scripts, including the required install-time script."""

    install = utility / "install.sh"
    if install.is_file() and not install.is_symlink():
        yield install
    yield from runtime_files(utility)


def _read_first_line(path: Path) -> str:
    try:
        with path.open(encoding="utf-8") as handle:
            return handle.readline().rstrip("\n")
    except (OSError, UnicodeDecodeError):
        return ""


def is_shell_file(path: Path) -> bool:
    """Return whether a utility file is a shell script."""

    return path.suffix.lower() in SHELL_SUFFIXES or bool(
        re.match(r"^#!.*(?:/|\s)(?:ba|z|k|d)?sh(?:\s|$)", _read_first_line(path))
    )


def is_python_file(path: Path) -> bool:
    """Return whether a utility file is a Python source file."""

    return path.suffix.lower() == ".py" or bool(PYTHON_SHEBANG.match(_read_first_line(path)))


def shell_constraint_errors(utility: Path) -> list[str]:
    """Require utility shell scripts to declare the portable POSIX shell."""

    errors = []
    for path in utility_script_files(utility):
        if not is_shell_file(path):
            continue
        shebang = _read_first_line(path)
        if not POSIX_SHELL_SHEBANG.match(shebang):
            errors.append(
                f"{path}: shell script must use a POSIX sh shebang, not {shebang!r}"
            )
    return errors


def package_install_errors(utility: Path) -> list[str]:
    """Reject package-manager installation commands in utility runtime files."""

    errors = []
    for path in utility_script_files(utility):
        if not is_shell_file(path):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for line_number, line in enumerate(lines, 1):
            if line.lstrip().startswith("#"):
                continue
            for manager, pattern in PACKAGE_INSTALL_PATTERNS:
                if pattern.search(line):
                    errors.append(
                        f"{path}:{line_number}: package-manager command {manager!r} "
                        "must not install runtime dependencies"
                    )
    return errors


def _local_python_modules(utility: Path) -> set[str]:
    names = set()
    for path in runtime_files(utility):
        if not is_python_file(path):
            continue
        if path.name == "__init__.py":
            names.add(path.parent.name)
        else:
            names.add(path.stem)
    return names


def python_dependency_errors(utility: Path) -> list[str]:
    """Reject absolute Python imports outside the stdlib or this utility."""

    errors = []
    local_modules = _local_python_modules(utility)
    for path in runtime_files(utility):
        if not is_python_file(path):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError):
            continue
        except SyntaxError as error:
            errors.append(f"{path}:{error.lineno}: invalid Python syntax ({error.msg})")
            continue

        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend((alias.name, node.lineno) for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imports.append((node.module, node.lineno))

        for module, line_number in imports:
            root = module.split(".", 1)[0]
            if root in STDLIB_MODULES or root in local_modules:
                continue
            errors.append(
                f"{path}:{line_number}: non-stdlib Python import {root!r}"
            )
    return errors


def dependency_patterns(other: str) -> tuple[re.Pattern[str], ...]:
    escaped = re.escape(other)
    patterns = [
        # Any path component named after a sibling utility, such as
        # ../other/bin/tool or /checkout/other/hooks/hook.py.
        re.compile(rf"(?<![A-Za-z0-9_.-]){escaped}(?=[/\\])"),
        # Shell/Python/JS-style imports of a sibling package.  Hyphenated
        # utility names are also checked in their Python-normalized form.
        re.compile(rf"^\s*(?:from|import)\s+{escaped}(?:\b|\.)"),
        re.compile(rf"\b(?:require|import)\s*\(\s*['\"]{escaped}(?:[/\\]|['\"])")
    ]
    normalized = other.replace("-", "_")
    if normalized != other and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", normalized):
        patterns.append(
            re.compile(rf"^\s*(?:from|import)\s+{re.escape(normalized)}(?:\b|\.)")
        )
    return tuple(patterns)


def _safe_relative_path(value: object) -> bool:
    """Return whether a manifest path stays inside its declared layout."""

    if not isinstance(value, str) or not value or value.startswith(("/", "\\")):
        return False
    if "\\" in value:
        return False
    parts = PurePosixPath(value).parts
    return bool(parts) and all(part not in {".", ".."} for part in parts)


def bundled_dependency_declarations(
    utility: Path, siblings: list[Path]
) -> tuple[dict[tuple[str, str], str], list[str]]:
    """Read the only sanctioned install-time sibling dependency declaration.

    A bundle is source material copied by install.sh into the installing
    utility's own layout.  The installed files therefore remain a leaf at
    runtime.  The manifest is deliberately strict: one sibling name, the
    exact VERSION it was copied from, a source path inside that sibling, and a
    relative destination inside the installed bundle layout.
    """

    manifest = utility / BUNDLE_MANIFEST
    if not manifest.exists():
        return {}, []
    if manifest.is_symlink() or not manifest.is_file():
        return {}, [f"{manifest}: bundle manifest must be an owned file"]

    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return {}, [f"{manifest}: invalid bundle manifest ({error})"]

    if not isinstance(data, dict) or set(data) != {"bundles"}:
        return {}, [f"{manifest}: expected an object containing only 'bundles'"]
    bundles = data["bundles"]
    if not isinstance(bundles, list):
        return {}, [f"{manifest}: 'bundles' must be a list"]

    sibling_by_name = {sibling.name: sibling for sibling in siblings}
    declarations = {}
    errors = []
    for index, bundle in enumerate(bundles, 1):
        label = f"{manifest}: bundles[{index}]"
        if not isinstance(bundle, dict) or set(bundle) != {
            "utility", "version", "source", "destination"
        }:
            errors.append(
                f"{label}: expected utility, version, source, and destination"
            )
            continue

        sibling_name = bundle["utility"]
        version = bundle["version"]
        source = bundle["source"]
        destination = bundle["destination"]
        sibling = sibling_by_name.get(sibling_name)
        if sibling is None or sibling_name == utility.name:
            errors.append(f"{label}: utility {sibling_name!r} is not a sibling")
            continue
        if not isinstance(version, str) or not SEMVER.fullmatch(version):
            errors.append(f"{label}: version {version!r} is not semver")
            continue
        if not _safe_relative_path(source):
            errors.append(f"{label}: source must be a safe relative path")
            continue
        if not _safe_relative_path(destination):
            errors.append(f"{label}: destination must be a safe relative path")
            continue

        version_file = sibling / "VERSION"
        try:
            actual_version = version_file.read_text(encoding="utf-8").splitlines()[0].strip()
        except (OSError, UnicodeDecodeError, IndexError):
            actual_version = ""
        if actual_version != version:
            errors.append(
                f"{label}: pinned version {version!r} does not match "
                f"{sibling}/VERSION ({actual_version!r})"
            )

        source_path = sibling / PurePosixPath(source)
        if source_path.is_symlink() or not source_path.is_file():
            errors.append(f"{label}: source file {source_path} is missing or a symlink")

        key = (sibling_name, source)
        if key in declarations:
            errors.append(f"{label}: duplicate bundle source {sibling_name!r}/{source}")
        else:
            declarations[key] = destination

    return declarations, errors


def dependency_errors(utility: Path, siblings: list[Path]) -> list[str]:
    errors = []
    patterns = {
        sibling.name: dependency_patterns(sibling.name)
        for sibling in siblings
        if sibling.name != utility.name
    }
    for path in runtime_files(utility):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "//", "/*", "*")):
                continue
            for sibling, sibling_patterns in patterns.items():
                if any(pattern.search(line) for pattern in sibling_patterns):
                    errors.append(
                        f"{path}:{line_number}: runtime reference to sibling "
                        f"utility {sibling!r}"
                    )
    return errors


def install_time_dependency_errors(
    utility: Path,
    siblings: list[Path],
    declarations: dict[tuple[str, str], str],
) -> list[str]:
    """Allow only declared source-copy lines in an install script.

    install.sh is not runtime code, but silently ignoring it would make an
    accidental sibling dependency invisible.  A declared source (and its
    sibling VERSION file when the installer checks the pin) must appear in the
    script, and the source must be used by an install/cp command.  This keeps
    the exception narrowly scoped to copying pinned material into the
    utility's own layout.
    """

    install = utility / "install.sh"
    try:
        lines = install.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []

    patterns = {
        sibling.name: dependency_patterns(sibling.name)
        for sibling in siblings
        if sibling.name != utility.name
    }
    copied = set()
    seen = set()
    errors = []
    for line_number, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        normalized = line.replace("\\", "/")
        for sibling, sibling_patterns in patterns.items():
            if not any(pattern.search(line) for pattern in sibling_patterns):
                continue
            matches = [
                (sibling_name, source)
                for sibling_name, source in declarations
                if sibling_name == sibling
                and f"../{sibling_name}/{source}" in normalized
            ]
            version_reference = f"../{sibling}/VERSION" in normalized
            if len(matches) == 1 or version_reference:
                if len(matches) == 1:
                    seen.add(matches[0])
                    if re.search(r"\b(?:install|cp)\b", line):
                        copied.add(matches[0])
                continue
            errors.append(
                f"{install}:{line_number}: install-time reference to sibling "
                f"utility {sibling!r} is not a declared pinned bundle"
            )

    for sibling, source in sorted(declarations):
        if (sibling, source) not in seen or (sibling, source) not in copied:
            errors.append(
                f"{install}: declared bundle {sibling!r}/{source} is not "
                "referenced and copied by an install/cp command"
            )
    return errors


def readme_table_errors(root: Path, utilities: list[Path]) -> list[str]:
    """Ensure README's Folder column names exactly the utility directories."""

    readme = root / "README.md"
    try:
        lines = readme.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        return [f"{readme}: cannot read utility table ({error})"]

    header_index = next(
        (index for index, line in enumerate(lines) if README_TABLE_HEADER.match(line)),
        None,
    )
    if header_index is None:
        return [f"{readme}: utility table with a Folder column is missing"]

    listed = []
    errors = []
    for index, line in enumerate(lines[header_index + 1 :], header_index + 2):
        if not line.lstrip().startswith("|"):
            break
        cells = line.split("|")
        if len(cells) < 3:
            errors.append(f"{readme}:{index}: malformed utility table row")
            continue
        folder_cell = cells[1].strip()
        if README_TABLE_SEPARATOR.fullmatch(folder_cell):
            continue

        link = README_FOLDER_LINK.fullmatch(folder_cell)
        if link is None:
            errors.append(
                f"{readme}:{index}: Folder column must be a link to one folder"
            )
            continue

        label, target = (part.strip() for part in link.groups())
        folder = target.rstrip("/")
        if (
            not folder
            or "\\" in folder
            or len(PurePosixPath(folder).parts) != 1
            or folder in {".", ".."}
        ):
            errors.append(
                f"{readme}:{index}: Folder link target {target!r} is not a top-level folder"
            )
            continue
        if label.strip("`").rstrip("/") != folder:
            errors.append(
                f"{readme}:{index}: Folder link label {label!r} does not match {folder!r}"
            )
            continue
        listed.append((folder, index))

    actual = {utility.name for utility in utilities}
    names = [name for name, _ in listed]
    listed_set = set(names)
    for name in sorted(actual - listed_set):
        errors.append(f"{readme}: utility folder {name!r} is missing from the Folder table")
    for name in sorted(listed_set - actual):
        errors.append(f"{readme}: Folder table names missing utility folder {name!r}")
    for name in sorted({name for name in names if names.count(name) > 1}):
        errors.append(f"{readme}: Folder table lists utility folder {name!r} more than once")
    return errors


def _settings_pretooluse(settings: object, path: Path) -> tuple[list[object] | None, list[str]]:
    """Return a settings file's PreToolUse entries with shape diagnostics."""

    if not isinstance(settings, dict):
        return None, [f"{path}: settings example must contain a JSON object"]
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return None, [f"{path}: settings example must contain a 'hooks' object"]
    entries = hooks.get("PreToolUse")
    if not isinstance(entries, list):
        return None, [f"{path}: settings example must contain a 'PreToolUse' list"]
    return entries, []


def _normalise_generated_commands(entries: list[object], home: Path) -> list[object]:
    """Rewrite temporary HOME paths to the documented ``~`` spelling."""

    prefix = f"python3 {home}/"
    normalised = json.loads(json.dumps(entries))
    for entry in normalised:
        if not isinstance(entry, dict):
            continue
        hooks = entry.get("hooks")
        if not isinstance(hooks, list):
            continue
        for hook in hooks:
            if not isinstance(hook, dict):
                continue
            command = hook.get("command")
            if isinstance(command, str) and command.startswith(prefix):
                hook["command"] = "python3 ~/" + command[len(prefix):]
    return normalised


def _sort_settings_entries(entries: list[object]) -> list[object]:
    """Make independent PreToolUse entries comparable regardless of order."""

    return sorted(entries, key=lambda entry: json.dumps(entry, sort_keys=True))


def _settings_environment(home: Path, generated_path: Path) -> dict[str, str]:
    """Build the isolated environment used to exercise an installer."""

    environment = os.environ.copy()
    environment["HOME"] = str(home)
    environment["CLAUDE_SETTINGS"] = str(generated_path)
    for variable in (
        "CLAUDE_HOOKS_DIR",
        "BIN_DIR",
        "BAO_AS_CONFIG_DIR",
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
    ):
        environment.pop(variable, None)
    return environment


def _run_wire_installer(
    root: Path, utility: str, environment: dict[str, str]
) -> str | None:
    """Run one installer's settings wiring and return an error, if any."""

    installer = root / utility / "install.sh"
    try:
        result = subprocess.run(
            ["sh", str(installer), "--wire"],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return f"{installer}: could not exercise --wire ({error})"
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        return (
            f"{installer}: --wire failed with exit {result.returncode}"
            + (f": {detail}" if detail else "")
        )
    return None


def shipped_settings_wiring_errors(root: Path) -> list[str]:
    """Verify each utility-owned settings example against its installer.

    The installer is the source of truth for the hook path, matcher, timeout,
    and JSON nesting.  A fresh settings file makes the generated object a
    complete contract for the shipped example, rather than checking only the
    fields that happen to be useful to the combined example check.
    """

    errors = []
    for utility, relative_path in SHIPPED_SETTINGS_EXAMPLES.items():
        utility_root = root / utility
        settings_path = utility_root / Path(*relative_path.parts)
        if not settings_path.is_file():
            if not utility_root.is_dir():
                continue
            errors.append(f"{settings_path}: settings example is missing")
            continue

        try:
            example = json.loads(settings_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            errors.append(f"{settings_path}: invalid JSON ({error})")
            continue
        _, shape_errors = _settings_pretooluse(example, settings_path)
        if shape_errors:
            errors.extend(shape_errors)
            continue

        with tempfile.TemporaryDirectory(prefix="check-settings-") as directory:
            temp_root = Path(directory)
            home = temp_root / "home"
            generated_path = temp_root / "settings.json"
            environment = _settings_environment(home, generated_path)
            error = _run_wire_installer(root, utility, environment)
            if error:
                errors.append(error)
                continue

            try:
                generated = json.loads(generated_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
                errors.append(
                    f"{generated_path}: installer generated invalid JSON ({error})"
                )
                continue
            generated_entries, shape_errors = _settings_pretooluse(
                generated, generated_path
            )
            if shape_errors:
                errors.extend(shape_errors)
                continue
            generated["hooks"]["PreToolUse"] = _normalise_generated_commands(
                generated_entries, home
            )
            if generated != example:
                errors.append(
                    f"{settings_path}: settings wiring does not match the entry "
                    f"generated by {utility}/install.sh --wire\n"
                    f"  example:  {json.dumps(example, sort_keys=True)}\n"
                    f"  generated: {json.dumps(generated, sort_keys=True)}"
                )
    return errors


def combined_settings_wiring_errors(root: Path) -> list[str]:
    """Verify the combined settings example against both live installers.

    The installers are the source of truth for destinations, matchers, and
    hook options.  Running them in a disposable HOME exercises the same
    ``--wire`` code CI ships, while normalising only the temporary HOME path
    back to the spelling used by the checked-in example.
    """

    settings_path = root / Path(*COMBINED_SETTINGS.parts)
    if not settings_path.is_file():
        if not all((root / utility).is_dir() for utility in WIRED_UTILITIES):
            return []
        return [f"{settings_path}: combined settings example is missing"]

    try:
        example = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return [f"{settings_path}: invalid JSON ({error})"]
    expected, errors = _settings_pretooluse(example, settings_path)
    if errors:
        return errors
    if not all((root / utility).is_dir() for utility in WIRED_UTILITIES):
        return []

    with tempfile.TemporaryDirectory(prefix="check-settings-") as directory:
        temp_root = Path(directory)
        home = temp_root / "home"
        generated_path = temp_root / "settings.json"
        environment = _settings_environment(home, generated_path)

        for utility in WIRED_UTILITIES:
            error = _run_wire_installer(root, utility, environment)
            if error:
                return [error]

        try:
            generated = json.loads(generated_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            return [f"{generated_path}: installer generated invalid JSON ({error})"]
        actual, errors = _settings_pretooluse(generated, generated_path)
        if errors:
            return errors
        actual = _normalise_generated_commands(actual, home)
        if _sort_settings_entries(actual) != _sort_settings_entries(expected):
            return [
                f"{settings_path}: PreToolUse wiring does not match the entries "
                f"generated by {WIRED_UTILITIES[0]}/install.sh and "
                f"{WIRED_UTILITIES[1]}/install.sh\n"
                f"  example:  {json.dumps(expected, sort_keys=True)}\n"
                f"  generated: {json.dumps(actual, sort_keys=True)}"
            ]
    return []


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    candidates = sorted(
        path
        for path in root.iterdir()
        if path.is_dir() and is_utility_directory(path)
    )
    errors = []
    bundle_declarations = {}

    for utility in candidates:
        if utility.is_symlink():
            errors.append(f"{utility}: utility directory must be owned, not a symlink")
            continue
        errors.extend(required_file_errors(utility))
        errors.extend(symlink_errors(utility))
        declarations, declaration_errors = bundled_dependency_declarations(
            utility, candidates
        )
        bundle_declarations[utility.name] = declarations
        errors.extend(declaration_errors)

    for utility in candidates:
        if utility.is_symlink():
            continue
        errors.extend(shell_constraint_errors(utility))
        errors.extend(package_install_errors(utility))
        errors.extend(python_dependency_errors(utility))
        errors.extend(dependency_errors(utility, candidates))
        errors.extend(
            install_time_dependency_errors(
                utility,
                candidates,
                bundle_declarations.get(utility.name, {}),
            )
        )

    errors.extend(readme_table_errors(root, candidates))
    errors.extend(shipped_settings_wiring_errors(root))
    errors.extend(combined_settings_wiring_errors(root))

    if errors:
        for error in errors:
            print(f"check-structure: {error}", file=sys.stderr)
        print(f"check-structure: {len(errors)} violation(s)", file=sys.stderr)
        return 1

    print(
        "check-structure: "
        f"{len(candidates)} utilities have README.md, VERSION, install.sh "
        "and pass the POSIX-shell, Python-stdlib, package-install, and "
        "cross-utility checks; README Folder table, shipped hook settings "
        "examples, and combined hook settings agree"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
