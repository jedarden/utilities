# utilities

Small, self-contained tools for running coding agents safely. Each top-level
folder is independent: it has its own README, its own `VERSION`, and its own
`install.sh`, and it depends on nothing else in this repo.

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
  utility owns its `README.md`, `VERSION`, and `install.sh` and has no
  cross-utility runtime dependency; `check-versions.sh` runs that check and
  verifies each `<utility>/VERSION` has a matching `<utility>/vX.Y.Z` tag (CI
  runs the combined gate on every push)
- `docs/notes/` — features, constraints, design decisions
- `docs/research/` — external reference material and prior art
- `docs/plan/plan.md` — complete plan for the repo

## License

MIT — see [LICENSE](LICENSE).
