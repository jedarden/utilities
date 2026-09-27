# utilities

Small, self-contained tools for running coding agents safely. Each top-level
folder is independent at runtime: it has its own README, its own `VERSION`,
and its own `install.sh`. A pinned install-time bundle is allowed only when it
is declared in `bundled-dependencies.json` and copied into that utility's own
installed layout.

| Folder | What it is |
|---|---|
| [`agent-secrets/`](agent-secrets/) | A credential guard hook for Claude Code, a login wrapper that keeps secret-store tokens out of argv, and prefix-scoped OpenBao/Vault policies — the pieces that let an agent read and write a secrets store without a value ever entering its transcript. |
| [`org-rule-guard/`](org-rule-guard/) | An org-wide `PreToolUse` guard for Claude Code with a JSONL denial log, an installer, and example settings wiring — the same six rules as the live hook, plus the record of every deny the live hook never kept. |

## Installing one utility

Forgejo is the canonical repository for this project. GitHub is a read-only
mirror, so clone from Forgejo to get the source of truth. For a reproducible
install, select the utility's namespaced release tag; each utility README
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

### Composing both guards with an existing settings file

[`docs/examples/settings-both.json`](docs/examples/settings-both.json) shows
the resulting `PreToolUse` entries, but it is a reference snippet, not a
replacement for a user's settings file. To merge both guards into an existing
`settings.json`, run both installers with the same `CLAUDE_SETTINGS` path:

```bash
SETTINGS="$HOME/.claude/settings.json"
cp "$SETTINGS" "$SETTINGS.bak"

CLAUDE_SETTINGS="$SETTINGS" \
  ~/utilities-org-rule-guard/org-rule-guard/install.sh --wire
CLAUDE_SETTINGS="$SETTINGS" \
  ~/utilities-agent-secrets/agent-secrets/install.sh --wire
```

Each `--wire` run reads the current JSON, preserves every existing top-level
setting, `hooks` event, and hook entry, then appends only its own
`PreToolUse` entry when that exact command is not already present. Running the
two commands again is safe: both installers report `already` and leave the
settings file unchanged. Do not copy `settings-both.json` over an existing
file or concatenate the two JSON objects; doing so can discard unrelated
settings and hooks. If a non-default settings path is used, pass that same
path through `CLAUDE_SETTINGS` on every run.

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

These commands are the individual unittest suites described by the plan:

```bash
python3 -m unittest discover -s agent-secrets/hooks -p 'test_credential_guard.py' -v
python3 -m unittest discover -s agent-secrets/bin -p 'test_bao_as.py' -v
python3 -m unittest discover -s agent-secrets/policies -p 'test_policies.py' -v
python3 -m unittest discover -s org-rule-guard/hooks -p 'test_org_rule_guard.py' -v
python3 -m unittest discover -s scripts -p 'test_check_structure.py' -v
python3 -m unittest discover -s scripts -p 'test_check_versions.py' -v
python3 -m unittest discover -s scripts -p 'test_hook_composition.py' -v
python3 -m unittest discover -s scripts -p 'test_install_bundles.py' -v
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
Create a tag in the form `<utility>/vX.Y.Z` at that commit, then push the commit
and tag together:

```bash
git push origin main <utility>/vX.Y.Z
```

CI runs `scripts/check-versions.sh`, which first verifies every utility has a
current-version changelog heading and then checks the bidirectional
VERSION↔tag contract. A VERSION bump without its matching changelog entry or
tag therefore fails the release gate.

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

MIT — see [LICENSE](LICENSE).
