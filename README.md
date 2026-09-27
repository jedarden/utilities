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
mirror, so clone from Forgejo to get the source of truth:

```bash
git clone https://git.ardenone.com/jedarden/utilities.git ~/utilities
~/utilities/agent-secrets/install.sh --help    # credential guard hook, bao-as, policies
~/utilities/org-rule-guard/install.sh --help   # PreToolUse guard, denial log, settings wiring
```

## Structure

- `<utility>/` — one folder per tool, each self-contained
- `scripts/` — repo tooling, not a utility: `check-structure.py` verifies each
  utility owns its `README.md`, `VERSION`, and `install.sh`, requires POSIX
  `sh` shebangs, rejects package-manager install commands and non-stdlib
  Python imports, rejects undeclared cross-utility runtime references,
  validates the narrow pinned bundle exception, and keeps this table's Folder
  column in sync with the top-level utility folders; `check-versions.sh` runs
  that check and verifies each `<utility>/VERSION` has a matching
  `<utility>/vX.Y.Z` tag (CI runs the combined gate on every push)
- `docs/notes/` — features, constraints, design decisions
- `docs/research/` — external reference material and prior art
- `docs/plan/plan.md` — complete plan for the repo

## Runtime constraints

The structural gate scans utility-owned runtime files. Shell scripts must
declare POSIX `sh` and may not install packages with pip, npm, apt, or another
package manager. Python files are parsed with the standard-library `ast`
module; absolute imports must resolve to Python's standard library or to code
inside the same utility. Runtime paths or imports into a sibling utility are
also rejected. Repository tooling under `scripts/` and documentation under
`docs/` are exempt; the declared pinned bundle remains install-time source
copying, not a runtime dependency.

## License

MIT — see [LICENSE](LICENSE).
