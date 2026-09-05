# utilities Plan

## Overview

Small, self-contained tools for running coding agents safely. One folder per
tool; nothing shared between folders except the license and this plan.

## Architecture

- Every utility is a leaf: `README.md`, `VERSION`, `install.sh`, and its files.
  No shared library directory — a shared `lib/` is how an "install one thing"
  repo turns into "install everything" (see jeds-curated-skills, whose
  installer had to inline `lib/common.sh` for exactly this reason).
- Scripts are POSIX shell or Python 3 stdlib. No package installs.
- Each `install.sh` is idempotent and copies into the conventional user
  locations (`~/.claude/hooks/`, `~/.local/bin/`); it never edits a file it
  did not create unless asked with an explicit flag.
- Versioning is per folder (`<utility>/VERSION`, semver). Git tags are
  `<utility>/vX.Y.Z`.

## Components

### agent-secrets (v0.1.0)

- `hooks/credential-guard.py` — Claude Code PreToolUse hook. Denies Write,
  Edit, MultiEdit and Bash calls whose body carries a high-signal credential
  value. Fails open. Placeholders and `gitleaks:allow` pass.
- `hooks/test_credential_guard.py` — unittest suite; fixtures are built at
  runtime so the test file itself never contains a token-shaped literal.
- `bin/bao-as` — `bao-as <instance> <command...>`: AppRole login to one
  named OpenBao/Vault instance with credentials passed as `@file`, then
  `exec` the command with the token only in its environment.
- `policies/*.hcl` — prefix-scoped policy templates: agent read/write on
  one prefix, writer on one prefix, reader on one prefix, and the superuser
  carve-outs (`sys/audit*`, `sys/seal`, `sys/step-down` denied).
- `examples/settings.json` — the hook wiring for `~/.claude/settings.json`.

### org-rule-guard (v0.1.0, Phase 3a)

- `hooks/org-rule-guard.py` — the org-wide PreToolUse guard, ported from
  `~/.claude/hooks/org-rule-guard.py`: no GitHub Actions workflows, no
  `kind: Job`/`CronJob`, no `:latest`, no mutating `kubectl`, no credential
  values, no blanket `git commit`. Same six rules, same deny messages, same
  fail-open contract as the live hook. Every denial additionally appends one
  JSON line (`ts`, `rule_id`, `tool`, `cwd`, `session_id`, redacted 80-char
  fragment) to `${XDG_STATE_HOME:-~/.local/state}/org-rule-guard/denials.jsonl`.
  The credential rule logs its pattern name, never a value, and every other
  fragment is scrubbed through the same patterns before it is written.
- `hooks/test_org_rule_guard.py` — unittest suite; fixtures are built at
  runtime so no rule-triggering literal sits in the test file.
  `ORG_RULE_GUARD_UNDER_TEST` points the whole suite at any hook copy, so one
  fixture set proves both that the port matches the live hook and that the
  log behaves (the log tests skip against a hook that predates the log).
- `install.sh` — idempotent copy into `~/.claude/hooks/`. Never overwrites a
  hook already at the destination and never touches `settings.json` without
  `--wire`; `--uninstall` refuses a file this folder did not install.
- `examples/settings.json` — the hook wiring for `~/.claude/settings.json`.

## Data Models

None. Configuration is files under `~/.config/bao-as/` (instance table and
per-instance `role_id` / `secret_id`, mode 0600) and an optional
`~/.config/credential-guard/patterns.json` for extra patterns. The one state
artifact is `org-rule-guard`'s denial log,
`${XDG_STATE_HOME:-~/.local/state}/org-rule-guard/denials.jsonl` — append-only
JSONL, one record per deny, never read back by the hook that writes it.

## Implementation Phases

- [x] Phase 1: `agent-secrets` — hook, wrapper, policies, tests, installer
- [ ] Phase 2: CI on Argo Workflows (unittest + shellcheck) — no GitHub Actions
- [ ] Phase 3: `org-rule-guard` — extract the working PreToolUse hook from
  `~/.claude/hooks/org-rule-guard.py` (332 lines, six hard-coded rules, one
  stdout deny path, no log). Two changes, in this order: (a) every denial
  appends one JSONL line (`ts`, `rule_id`, `tool`, `cwd`, `session_id`,
  matched fragment redacted) to `~/.local/state/org-rule-guard/denials.jsonl`,
  so the fleet finally has a record of which rules agents keep hitting and
  where the prose is failing; (b) the rules move out of Python into a YAML
  file with per-rule id, pattern, tool scope and message, so a promoted lesson
  can land as data rather than a code edit, and the credential rule delegates
  to `agent-secrets/credential-guard.py` instead of duplicating it. Same
  fail-open contract, same tests passing before and after.
  - [x] Phase 3(a): denial log — shipped 2026-09-05 as `org-rule-guard/`
    v0.1.0 (35 tests, green against both the ported copy and the live hook)
  - [ ] Phase 3(b): YAML rules + credential-rule delegation to
    `agent-secrets/credential-guard.py`
- [ ] Phase 4: further utilities as they are extracted from working setups

## Open Questions

- Whether `credential-guard.py` should grow an *output* check (a PostToolUse
  hook that redacts tool results). Today it only sees what the agent writes
  and runs, never what comes back; that gap is documented, not closed.
