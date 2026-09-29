# Structure-gate reference

This document is the human-readable companion to
[`scripts/check-structure.py`](../scripts/check-structure.py). The checker is
the executable source of truth. The inventories below are intentionally code-
valued, and the documentation-sync tests compare them with their executable
sources; update the source, this document, and the relevant fixtures in one
change.

The gate runs as part of `scripts/check-versions.sh` in `utilities-ci`. Run it
directly from the repository root while developing:

```bash
python3 scripts/check-structure.py
```

## Enforcement contract

Each direct child of the repository is a utility unless its name starts with
`.` or it is one of the repository-tooling directories `docs` and `scripts`.
The repository root must own these files:

| Inventory | Entries |
|---|---|
| Required repository files | `LICENSE` |

Each utility must own these files:

| Inventory | Entries |
|---|---|
| Required utility files | `README.md`, `VERSION`, `CHANGELOG.md`, `install.sh` |
| Required release note | `CHANGELOG.md` contains `## [VERSION] - YYYY-MM-DD` |
| Required README license coverage | `licensed under the MIT License`, `does not change that coverage`, `does not copy a separate license file` |

The checker also rejects utility symlinks and links inside a utility that
resolve outside that utility. Shell files must use a POSIX `sh` shebang.
Python files must parse with Python 3.9 rules, may use only the standard
library or another module owned by the same utility, and may not use PEP 604
union annotations. `install.sh` is checked for install-time sibling use as
well as for shell and package-manager rules.

The root README must contain a `Folder` table. Its linked folder names must
match the utility directories exactly in both directions: missing, extra, and
duplicate rows are violations, as are malformed links or mismatched link
labels.

The pinned bundle exception is the only permitted checkout-time reuse. A
utility may declare a sibling, its exact `VERSION`, a source path, and a
destination in `bundled-dependencies.json`; `install.sh` must copy that exact
source into the installing utility's own layout. The installed copy is then a
runtime leaf. A bundle never permits a runtime reference to the sibling.

The gate verifies every utility-owned hook settings example against the output
of that utility's installer. The event name is part of the contract: the two
guard examples are `PreToolUse`, while friction-receipt's example is
`SessionEnd`. The combined example contains all three shipped entries, and
the gate runs all three installers before comparing both events. These checks
are contract checks rather than additional dependency allowlists, and they
catch missing examples, invalid JSON, event or matcher drift, and installer
output drift.

## Hook matcher inventory

The shipped `PreToolUse` settings entries for `org-rule-guard` and
`agent-secrets` must match the installer output and name exactly the complete
rule-relevant tool inventory handled by each hook:

```text
Write
Edit
MultiEdit
NotebookEdit
Bash
```

This matcher is a closed coverage boundary, not a claim that every
write-capable action is intercepted. `NotebookEdit` carries notebook cell text
in `new_source` and the notebook filename in `notebook_path`; omitting it from
a matcher bypasses the same file-content and credential rules that apply to
other write tools. Conversely, adding a tool to a matcher without adding it to
the hook's `SUPPORTED_TOOLS` inventory would invoke a hook that does not
inspect that tool.

MCP tool calls and any other write-capable tool whose name is not in this
five-tool matcher do not match either `PreToolUse` entry and therefore bypass
both guards silently, including credential writes. Neither guard has a
catch-all write hook or post-tool visibility; coverage must be extended
explicitly when a new write-capable tool is introduced.

`SessionEnd` is an event-scoped hook, not a tool-scoped hook. The
friction-receipt entry therefore has no `matcher` and contributes no name to
the `SUPPORTED_TOOLS` inventory. It is nevertheless part of the shipped
settings contract: the structure gate runs `friction-receipt/install.sh
--wire` and compares its `hooks.SessionEnd` output with
`friction-receipt/examples/settings.json`. A new event-scoped hook follows the
same settings-example verification path without being added to the tool
matcher inventory.

`scripts/test_hook_composition.py` loads each hook's `SUPPORTED_TOOLS` inventory
and asserts that the documented inventory equals their union, while each
combined shipped matcher equals its hook's inventory in both directions: no
supported tool may be missing and no extra matcher name may be present. When a
hook gains another write-capable tool, update its inventory, per-tool payload
extraction, installer matcher, settings examples, and this reference in one
change.

## Hook timeout contract

The shipped settings examples and combined composition must give every shipped
hook an explicit 10-second timeout. This is the expected worst-case latency
budget for `agent-secrets`'s `credential-guard.py`, `org-rule-guard`'s
`org-rule-guard.py`, and friction-receipt's `friction-receipt.py`; no hook is
allowed to inherit the harness default. `scripts/check-structure.py` checks
these timeout fields in the standalone examples, the combined `PreToolUse` and
`SessionEnd` examples, and the output produced by all three installers.

## Package-manager command inventory

The following regular expressions are searched line-by-line in shell files,
including `install.sh`. Comment lines are skipped. A match is reported as a
package-manager command and is rejected because runtime dependencies must be
self-contained. The expressions use Python `re` syntax and are copied from
`PACKAGE_INSTALL_PATTERNS` exactly:

```text
pip	\b(?:python(?:3(?:\.[0-9]+)?)?\s+-m\s+)?pip3?\s+install\b
uv	\buv\s+(?:pip\s+)?install\b
pipx	\bpipx\s+install\b
poetry	\bpoetry\s+(?:add|install)\b
npm	\bnpm\s+(?:i|install|ci)\b
yarn	\byarn\s+(?:add|install)\b
pnpm	\bpnpm\s+(?:add|install|i)\b
apt	\bapt(?:-get)?\s+(?:[^;&|\n]*\s+)?(?:install|upgrade)\b
apk	\bapk\s+(?:add|upgrade)\b
dnf/yum	\b(?:dnf|yum)\s+(?:[^;&|\n]*\s+)?(?:install|upgrade)\b
Homebrew	\bbrew\s+install\b
pacman	\bpacman\s+(?:[^;&|\n]*\s+)?-S(?:\s|$)
zypper	\bzypper\s+install\b
gem	\bgem\s+install\b
cargo	\bcargo\s+install\b
go	\bgo\s+install\b
```

The patterns deliberately cover dependency installation rather than every
package-manager operation: for example, `apt remove` is outside this
inventory, while `apt update` is not a way to make a utility self-contained
and is covered by the documented `upgrade`/`install` forms where applicable.

## Python import allowlist

For an absolute import, the checker takes the root before the first dot. The
root is allowed when it is in `STDLIB_MODULES` or in the set of Python module
names found inside the same utility. Relative imports are not rejected by this
check. The standard-library portion is the union of these two source sets,
listed in `STDLIB_ALLOWLIST_SOURCES` (each source name is paired with the set
it contributes):

| Allowlist source | Effective entries |
|---|---|
| `PYTHON39_STDLIB_MODULES` | The fixed Python 3.9 standard-library root inventory in the checker |
| `__future__` | The pseudo-module `__future__` |

In executable terms, the set is:

```python
PYTHON39_STDLIB_MODULES
| {"__future__"}
```

The pinned inventory includes platform-specific standard-library modules and
does not grow when CI runs the checker with a newer interpreter. In particular,
modules added after Python 3.9, such as `tomllib`, remain rejected as absolute
imports. To inspect the exact effective roots:

```bash
python3 -c 'import runpy; policy = runpy.run_path("scripts/check-structure.py"); print("\n".join(sorted(policy["STDLIB_MODULES"])))'
```

An import from a third-party package is not made valid by adding its name to
the documentation. When changing the Python floor, update the pinned
inventory, its tests, and this section together.

## Sibling-reference inventory

For every other top-level utility, the checker substitutes the sibling name
after `re.escape` for `{escaped}` in each rule below and scans non-comment
runtime lines. A sibling whose name contains hyphens also gets the final rule
with hyphens changed to underscores, when that normalized name is a valid
Python identifier.

```text
path component	(?<![A-Za-z0-9_.-]){escaped}(?=[/\\])
Python or shell import	^\s*(?:from|import)\s+{escaped}(?:\b|\.)
JavaScript require/import call	\b(?:require|import)\s*\(\s*['\"]{escaped}(?:[/\\]|['\"])
hyphen-normalized Python import	^\s*(?:from|import)\s+{escaped}(?:\b|\.)
```

The path rule catches a utility name used as a path component, such as
`../other/bin/tool` or `/checkout/other/hooks/hook.py`. The import rules catch
Python/shell-style leading imports and JavaScript-style `require(...)` or
`import(...)` calls. Leading comment lines (`#`, `//`, `/*`, and `*`) are
ignored. The same rules are used for install scripts, except that a matching
line is allowed only when it is the declared, pinned bundle source or that
sibling's `VERSION` file, and the declared source must be used by an
`install`/`cp` command.

## Violation reporting

Every violation is printed to stderr with the `check-structure:` prefix. When
the rule has a source location, the message includes `path:line`; examples
include:

```text
check-structure: alpha/install.sh:2: package-manager command 'pip' must not install runtime dependencies
check-structure: alpha/hooks/hook.py:1: non-stdlib Python import 'requests'
check-structure: alpha/bin/use-beta.py:1: runtime reference to sibling utility 'beta'
```

The process exits `1` and prints `check-structure: N violation(s)` when any
violation exists. A clean run exits `0` and prints the utility count plus the
checks that passed. The diagnostic is intentionally a rule and location, not
the contents of the offending line.

## Updating the gate

Make policy changes as one reviewable change:

1. Add or change the executable entry in `PACKAGE_INSTALL_PATTERNS`,
   `PYTHON39_STDLIB_MODULES`/its documented source expression,
   `README_LICENSE_COVERAGE_PHRASES`, or `SIBLING_REFERENCE_RULES` (and
   `SIBLING_NORMALIZED_IMPORT_RULE` when the normalized-import behavior
   changes).
2. Add a focused positive fixture and a nearby non-match or allowed-path
   fixture to `scripts/test_check_structure.py`. For a new package-manager or
   sibling rule, assert the diagnostic text as well as the exit status.
3. Update the matching code-valued inventory in this document in the same
   commit. The documentation-sync tests compare package labels and regexes,
   stdlib source names, and sibling rule templates with the checker source.
4. Run the structure suite and the checker itself. If the change affects a
   utility's user-facing behavior, add its changelog entry and follow the
   normal version/tag release process.

Do not add a third-party module to the stdlib allowlist to make a utility pass.
Keep runtime reuse inside the utility, or use the explicitly pinned
install-time bundle contract. `scripts/check-structure.py` remains stdlib-only
so the gate can run in the minimal CI image.
