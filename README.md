# utilities

Small, self-contained tools for running coding agents safely. Each top-level
folder is independent: it has its own README, its own `VERSION`, and its own
`install.sh`, and it depends on nothing else in this repo.

| Folder | What it is |
|---|---|
| [`agent-secrets/`](agent-secrets/) | A credential guard hook for Claude Code, a login wrapper that keeps secret-store tokens out of argv, and prefix-scoped OpenBao/Vault policies — the pieces that let an agent read and write a secrets store without a value ever entering its transcript. |

## Installing one utility

```bash
git clone https://github.com/jedarden/utilities ~/utilities
~/utilities/agent-secrets/install.sh --help
```

## Structure

- `<utility>/` — one folder per tool, each self-contained
- `docs/notes/` — features, constraints, design decisions
- `docs/research/` — external reference material and prior art
- `docs/plan/plan.md` — complete plan for the repo

## License

MIT — see [LICENSE](LICENSE).
