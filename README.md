# utilities

Small, self-contained tools for running coding agents safely. Each top-level
folder is independent at runtime: it has its own README, its own `VERSION`,
and its own `install.sh`. A pinned install-time bundle is allowed only when it
is declared in `bundled-dependencies.json` and copied into that utility's own
installed layout.

| Folder | What it is |
|---|---|
| [`agent-secrets/`](agent-secrets/) | A credential guard hook for Claude Code, a login wrapper that keeps secret-store tokens out of argv, and prefix-scoped OpenBao/Vault policies — the pieces that let an agent read and write a secrets store without a value ever entering its transcript. |
| [`friction-receipt/`](friction-receipt/) | A fail-open `SessionEnd` hook that writes bounded, redacted TWILL friction receipts. |
| [`org-rule-guard/`](org-rule-guard/) | An org-wide `PreToolUse` guard for Claude Code with a JSONL denial log, an installer, and example settings wiring — the same six rules as the live hook, plus the record of every deny the live hook never kept. |

## Installing one utility

Forgejo is the canonical repository for this project. GitHub is a read-only
mirror, so clone from Forgejo to get the source of truth. For a reproducible
install, first list the utility's released tags from the canonical Forgejo
remote. Replace `agent-secrets` with the utility folder you want to install:

```bash
git ls-remote --tags https://git.ardenone.com/jedarden/utilities.git \
  'agent-secrets/v*'
```

Select one of the returned namespaced release tags; each utility README
documents its pin, upgrade, and removal lifecycle:

```bash
git clone --branch agent-secrets/v0.1.0 --depth 1 \
  https://git.ardenone.com/jedarden/utilities.git ~/utilities-agent-secrets
~/utilities-agent-secrets/agent-secrets/install.sh --wire

git clone --branch org-rule-guard/v0.1.0 --depth 1 \
  https://git.ardenone.com/jedarden/utilities.git ~/utilities-org-rule-guard
~/utilities-org-rule-guard/org-rule-guard/install.sh --wire
```

Replace `v0.1.0` with the released version you want. The utility-specific
README is the contract for upgrading and removing an installed copy.
Each installer also records the selected utility version and any install-time
bundle pins in its installed hook layout. The read-only `--status` query
re-derives the installed files from that provenance and reports modified or
stale files; rerun the installer from the intended release to repair drift.

### Composing both guards with an existing settings file

[`docs/examples/settings-both.json`](docs/examples/settings-both.json) shows
the resulting `PreToolUse` entries, but it is a reference snippet, not a
replacement for a user's settings file. To merge both guards into an existing
`settings.json`, run both installers with the same `CLAUDE_SETTINGS` path:

```bash
SETTINGS="$HOME/.claude/settings.json"
CLAUDE_SETTINGS="$SETTINGS" \
  ~/utilities-org-rule-guard/org-rule-guard/install.sh --wire
CLAUDE_SETTINGS="$SETTINGS" \
  ~/utilities-agent-secrets/agent-secrets/install.sh --wire
```

Each `--wire` run reads the current JSON and preserves every existing
top-level setting, `hooks` event, and unrelated hook entry. It identifies its
own `PreToolUse` entry by the exact command: a current matcher/timeout is left
alone, while a known legacy shipped entry is refreshed in place. A same-command
entry with any other matcher or timeout is treated as customized, left
untouched, and reported; the report is one `preserved` line on stderr and the
installer exits 2. The settings file is not rewritten and no backup is created
for that conflict. Use `--wire --force` when that customization should be
replaced deliberately: it exits 0 and changes only the matching entry's
matcher/timeout fields, preserving its command, handler type, other fields, and
all unrelated settings. If no matching command exists, the installer appends
its entry. Each utility README lists its exact known-legacy inventory; no other
same-command shape is eligible for in-place refresh. Before the first run that
changes an existing settings file,
the installer creates `$SETTINGS.bak` if it does not already exist. That backup
is the pre-wiring file: the second installer and later `--wire` runs leave it
untouched. If the
settings file does not exist yet, the installer creates it without a backup
because there is no prior file to preserve. Do not rerun a manual `cp` over
the backup, and do not copy `settings-both.json` over an existing file or
concatenate the two JSON objects; doing so can discard unrelated settings and
hooks. If a non-default settings path is used, pass that same path through
`CLAUDE_SETTINGS` on every run. For a symlinked `CLAUDE_SETTINGS`, the backup
is beside the resolved target rather than beside the symlink.

For both installers, an absolute `CLAUDE_SETTINGS` value is used as given and
a relative value is resolved from that run's current working directory. The
settings parent must already exist; a `--wire` settings step fails without
creating a missing parent, settings file, lock, or backup. Path symlinks are
resolved before reading and replacement, so a final-component symlink remains
in place while its target is updated; the target directory receives the lock
and backup. Distinct paths are independent: wiring one utility at A and the
other at B leaves one partial hook entry in each file and one separate
pre-wiring backup per existing file, with no cross-file rollback point. Use the
same effective path on every run when composing both utilities.

The merge is protected by an exclusive advisory lock at
`$SETTINGS.lock`, which the installers keep so every concurrent `--wire` run
uses the same lock. The lock covers reading, merging, backup creation, and
replacement. Each changed file is written to a uniquely named temporary file
in the settings file's directory, flushed, and atomically renamed into place;
an interruption before the rename therefore leaves the live file complete.
The temporary name includes the utility (`.settings.json.agent-secrets.*.tmp`
or `.settings.json.org-rule-guard.*.tmp`). Each installer removes its own
leftover temporary files while holding the lock before reading the settings;
the other utility's temporary files are left for that utility to reap. Normal
errors and HUP/INT/TERM interruptions remove the installer's current temporary
file too. A hard kill can still strand a file, but the next run removes it
before merging.
When rewriting an existing file, the replacement keeps the live file's
permission bits, including mode `0600`. If both installers are started at the
same time, one waits for the other and then rereads its result, so both hook
entries and unrelated settings are preserved. Manual editors or other writers
that do not honor the same advisory lock must not modify the file during a
wire; their edits are outside this serialization guarantee.

The lock file is created lazily with mode `0600` (and is corrected to that
mode if it already exists). The kernel lock belongs to the wiring process, not
to the pathname: normal exit, an exception, or a crash releases it, while the
empty `.lock` file may remain. A leftover lock file is stale metadata, not a
permanent block; a later `--wire` opens and acquires it normally. A wire that
cannot create the lock, or cannot acquire it within 30 seconds, prints a
refusal to stderr, exits nonzero, and does not modify the settings file. Set
`CLAUDE_SETTINGS_LOCK_TIMEOUT` to a different positive number when an
environment needs a different finite deadline; waiting is never indefinite.
`--uninstall` uses the same lock and deadline before removing the lock file,
then removes it if present. If the lock cannot be acquired or removed,
uninstall aborts before removing installed files.

The `.bak` is a permanent, one-time pre-wiring snapshot, not a rolling backup:
`--wire` and `--uninstall` never rewrite or remove an existing one. To inspect
what wiring changed, compare it with the live file:

```bash
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
diff -u "$SETTINGS.bak" "$SETTINGS"
```

For a wholesale rollback to the pre-wiring file, review the diff and then run:

```bash
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
cp -p "$SETTINGS.bak" "$SETTINGS"
```

If later settings changes should be kept, use the diff as the baseline and
merge only the wiring changes instead. The installer creates the backup with
the source settings file's permission bits, so a mode-`0600` `settings.json`
produces a mode-`0600` backup. Delete the `.bak` only after verifying the live
settings and deciding that this rollback point is no longer needed; a later
`--wire` change will create a new snapshot if the file is absent.

If an existing settings file is malformed JSON, or its top-level value is not
an object, either installer creates the pre-wiring `.bak` when it is owed,
prints a clear refusal to stderr, exits nonzero, and leaves the settings file
byte-for-byte unchanged. It never appends a hook entry to such a file.

## Structure

- `<utility>/` — one folder per tool, each self-contained
- `scripts/` — repo tooling, not a utility: `check-structure.py` verifies each
  utility owns its `README.md`, `VERSION`, `CHANGELOG.md`, and `install.sh`, requires POSIX
  `sh` shebangs, rejects package-manager install commands and non-stdlib
  Python imports, rejects undeclared cross-utility runtime references,
  validates the narrow pinned bundle exception, and keeps this table's Folder
  column in sync with the top-level utility folders; `check-versions.sh` runs
  that check, verifies each `<utility>/VERSION` has a matching
  `<utility>/vX.Y.Z` tag, and keeps every namespaced release pin in this
  README synchronized with the referenced utility's current `VERSION` (CI
  runs the combined gate on every push); the
  `check-shellcheck.sh` wrapper verifies ShellCheck's minimum version before
  invoking the repository's shell checks
- [`docs/structure-check.md`](docs/structure-check.md) — reference inventory
  for the structure gate's package-manager patterns, Python stdlib allowlist,
  sibling-reference rules, diagnostics, and update process; its inventories
  are checked against `check-structure.py` by the structure test suite
- `docs/notes/` — features, constraints, design decisions
- `docs/examples/` — shipped wiring examples, including the combined
  [`settings-both.json`](docs/examples/settings-both.json) configuration for
  running both PreToolUse guards
- `docs/research/` — external reference material and prior art
- `docs/plan/plan.md` — complete plan for the repo

## Development

### Prerequisites

Run the checks from the repository root with Python 3.9 or newer, a POSIX
`sh`, Bash for `scripts/check-versions.sh`, and ShellCheck 0.9.0 or newer.
The Python checks use only the standard library; no package install is needed.
Use `scripts/check-shellcheck.sh` for the shell checks: it fails before invoking
ShellCheck when the executable is missing, cannot report a numeric version, or
is older than 0.9.0.
`agent-secrets/bin/bao-as` defaults to the OpenBao `bao` CLI (OpenBao 2.x). A
Vault override is supported only under the exact login/KV compatibility
contract documented in [`agent-secrets/README.md`](agent-secrets/README.md#cli-compatibility-contract);
the test suite supplies stubs and does not contact a store.

### Local verification

Run unittest discovery for each utility directory so every `test_*.py` module
in the directory is included automatically:

```bash
python3 -m unittest discover -s agent-secrets/hooks -v
python3 -m unittest discover -s agent-secrets/bin -v
python3 -m unittest discover -s agent-secrets/policies -v
python3 -m unittest discover -s org-rule-guard/hooks -v
python3 -m unittest discover -s scripts -v
```

Check the shell entry points and enforce the ShellCheck version floor with:

```bash
scripts/check-shellcheck.sh
```

### Adding a utility

1. Create `<utility>/` with an owned `README.md`, semver `VERSION`, and
   executable POSIX `install.sh`; keep runtime code self-contained.
2. Add the new folder to the README `Folder` table and document its install
   and test commands.
3. Run the local verification commands above and
   `python3 scripts/check-structure.py`.
4. Add the release's `## [X.Y.Z] - YYYY-MM-DD` entry at the top of the
   utility's `CHANGELOG.md`, including concise user-facing notes. Commit the
   utility, its README row, `CHANGELOG.md`, and its initial/version-bumped
   `VERSION` together. Create `<utility>/vX.Y.Z` at that commit, then push the
   commit and tag together:

   ```bash
   git push origin main <utility>/vX.Y.Z
   ```

   The VERSION bump, matching changelog entry, and tag are one release unit;
   the structural gate rejects a VERSION without its release heading, and
   pushing only the commit leaves the version gate red.

## Releasing

To release a utility, add a concise user-facing entry to the top of
`<utility>/CHANGELOG.md` with the exact heading `## [X.Y.Z] - YYYY-MM-DD`,
update `<utility>/VERSION` to the same `X.Y.Z`, and commit both files together.
When releasing `agent-secrets`, also update
`org-rule-guard/bundled-dependencies.json` so its pinned `agent-secrets`
version equals the new `agent-secrets/VERSION` in the same push. If the pin
cannot land in that push, immediately follow it with a dependent
`org-rule-guard` release that updates the pin; otherwise the combined release
gate remains red.
Create a tag in the form `<utility>/vX.Y.Z` at that commit, then push the commit
and tag together:

```bash
git push origin main <utility>/vX.Y.Z
```

CI runs `scripts/check-versions.sh`, which first verifies every utility has a
current-version changelog heading, enforces each bundled-dependencies pin
against its sibling's current `VERSION`, and then checks the bidirectional
VERSION↔tag contract. A VERSION bump without its matching changelog entry or
tag, or a stale dependent bundle pin, therefore fails the release gate.

## Bead checkpoint workflow

After any bead mutation, flush the durable checkpoint and commit every
changed path under `.beads/checkpoint/`:

```bash
bead sync flush-only
git status --short -- .beads/checkpoint
git add .beads/checkpoint
git commit -m "chore(beads): publish checkpoint"
```

At the end of the bead-mutating session, run
`git status --short -- .beads/checkpoint` again and require no output. Do not
pull while that check is dirty; flush and commit the checkpoint first.

## Runtime constraints

The structural gate scans utility-owned runtime files. Shell scripts must
declare POSIX `sh` and may not install packages with pip, npm, apt, or another
package manager. Python files are parsed with the standard-library `ast`
module using Python 3.9 grammar, and PEP 604 union annotations are rejected;
absolute imports must resolve to Python's standard library or to code inside
the same utility. Runtime paths or imports into a sibling utility are also
rejected. Repository tooling under `scripts/` and documentation under `docs/`
are exempt; the declared pinned bundle remains install-time source copying,
not a runtime dependency.

## License

The utilities, repository tooling, and documentation in this repository are
licensed under the MIT License. Installers copy selected utility files to user
hosts; those installed copies remain under the MIT License. The installers do
not copy this root license file alongside them, so retain [LICENSE](LICENSE)
when redistributing installed files.
