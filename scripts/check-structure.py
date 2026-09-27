#!/usr/bin/env python3
"""Check the repository's self-contained utility layout.

Top-level directories other than the repository-tooling directories are
utilities.  Each utility owns the small amount of metadata needed to install
it, and its runtime files must not reach into a sibling utility.  This check
is deliberately stdlib-only so it can run in the same minimal CI image as the
other repository checks.
"""

from __future__ import annotations

import re
import stat
import sys
from pathlib import Path


REQUIRED_FILES = ("README.md", "VERSION", "install.sh")
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
        if path.name in REQUIRED_FILES:
            continue
        try:
            mode = path.stat().st_mode
        except OSError:
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or mode & stat.S_IXUSR:
            yield path


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


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    candidates = sorted(
        path
        for path in root.iterdir()
        if path.is_dir() and is_utility_directory(path)
    )
    errors = []

    for utility in candidates:
        if utility.is_symlink():
            errors.append(f"{utility}: utility directory must be owned, not a symlink")
            continue
        errors.extend(required_file_errors(utility))
        errors.extend(symlink_errors(utility))

    for utility in candidates:
        if utility.is_symlink():
            continue
        errors.extend(dependency_errors(utility, candidates))

    if errors:
        for error in errors:
            print(f"check-structure: {error}", file=sys.stderr)
        print(f"check-structure: {len(errors)} violation(s)", file=sys.stderr)
        return 1

    print(
        "check-structure: "
        f"{len(candidates)} utilities have README.md, VERSION, install.sh "
        "and no cross-utility runtime dependencies"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
