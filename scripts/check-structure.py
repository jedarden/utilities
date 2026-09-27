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
from pathlib import PurePosixPath


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
README_TABLE_HEADER = re.compile(r"^\s*\|\s*Folder\s*\|")
README_TABLE_SEPARATOR = re.compile(r"^\s*:?-{3,}:?\s*$")
README_FOLDER_LINK = re.compile(r"^\[([^]]+)\]\(([^)]+)\)$")


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

    errors.extend(readme_table_errors(root, candidates))

    if errors:
        for error in errors:
            print(f"check-structure: {error}", file=sys.stderr)
        print(f"check-structure: {len(errors)} violation(s)", file=sys.stderr)
        return 1

    print(
        "check-structure: "
        f"{len(candidates)} utilities have README.md, VERSION, install.sh "
        "and no cross-utility runtime dependencies; README Folder table agrees"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
