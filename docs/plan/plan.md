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
  `<utility>/vX.Y.Z`. The contract is enforced by `scripts/check-versions.sh`
  (run by utilities-ci on every push): every VERSION at HEAD must have a tag
  at exactly its version, and every `<utility>/v*` tag must point at a commit
  whose VERSION agrees. Releasing means committing the bump and pushing
  commit and tag together — `git push origin main <utility>/v<X.Y.Z>` —
  since pushing the commit alone fails CI until the tag lands.

## Components

### agent-secrets (v0.1.0)

- `hooks/credential-guard.py` — Claude Code PreToolUse hook. Denies Write,
  Edit, MultiEdit and Bash calls whose body carries a high-signal credential
  value. Fails open. Placeholders and `gitleaks:allow` pass.
- `hooks/test_credential_guard.py` — unittest suite; fixtures are built at
  runtime so the test file itself never contains a token-shaped literal.
- `bin/bao-as` — `bao-as <instance> <command...>`: AppRole login to one
  named OpenBao/Vault instance with credentials passed as `@file`, then
  `exec` the command with the token only in its environment. Refuses to
  start when a credential file is missing or readable by group/other —
  mode 0600 is enforced, not advisory.
- `bin/test_bao_as.py` — unittest suite for the wrapper. Runs it against a
  stub `bao` placed first on `PATH` and a throwaway `BAO_AS_CONFIG_DIR`,
  then inspects what actually happened: the login argv carries
  `role_id=@`/`secret_id=@` and never the values, the issued token exists
  only in the child's environment (a stale inherited one does not survive)
  and is never printed, `exec` preserves the child's exit code and stdio,
  and missing or group/other-readable credential files fail closed before
  the CLI runs. `BAO_AS_UNDER_TEST` points the suite at another copy of the
  script. Fixtures are built at runtime so no credential-shaped literal
  sits in this file either.
- `policies/*.hcl` — prefix-scoped policy templates: agent read/write on
  one prefix, writer on one prefix, reader on one prefix, and the superuser
  carve-outs (`sys/audit*`, `sys/seal`, `sys/step-down` denied).
- `policies/test_policies.py` — stdlib tokenizer + recursive-descent parser
  for the policy grammar OpenBao's loader accepts (the `vault/policy.go`
  rule-key set), plus the broken-policy fixtures that prove it rejects.
  Every template must parse and must match its documented grant, so a
  syntax error fails CI instead of surfacing at `bao policy write` time.
- `install.sh` — idempotent copy to the conventional destinations: the hook
  to `~/.claude/hooks/credential-guard.py`, the wrapper to
  `~/.local/bin/bao-as`, and `~/.config/bao-as/instances.conf` seeded once
  at 0600 inside a 0700 directory. It never overwrites a hook or wrapper
  already at a destination without `--force` (or `--wire`, which replaces
  and wires in one step) — a live copy may carry local edits only its
  operator has seen — and never touches `settings.json` without `--wire`.
  `--uninstall` refuses a file this folder did not install, all-or-nothing
  so no half-uninstalled machine is left, and it never removes the bao-as
  config directory: the credential files there belong to the operator, and
  `bao-as` re-enforces the 0600 modes at runtime. `CLAUDE_HOOKS_DIR`,
  `BIN_DIR`, `CLAUDE_SETTINGS` and `BAO_AS_CONFIG_DIR` override the
  destinations; the `Install` class in `hooks/test_credential_guard.py`
  drives all of it in a throwaway HOME / hooks dir / settings path, and
  `CREDENTIAL_GUARD_UNDER_TEST` points the same fixtures at any installed
  copy.
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
  The `Install` class drives `install.sh` in a throwaway hooks dir / settings
  path (plus one temp `$HOME` for the default destinations), covering every
  contract clause above including the refusal paths: no overwrite without
  `--force`, no settings write without `--wire`, `--uninstall` refusing a
  file this folder did not install and leaving the denial log in place.
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
- [x] Phase 2: CI on Argo Workflows (unittest + shellcheck) — no GitHub
  Actions — shipped 2026-09-15 as `utilities-ci` (WorkflowTemplate + Forgejo
  push sensor; runs the unittest suites and shellcheck on every push to
  main, including the org-rule-guard installer contract). Grew the
  policy-template HCL validation suite on 2026-09-16. Since 2026-09-16
  it also runs `scripts/check-versions.sh` to enforce the VERSION↔tag
  contract (see Architecture).
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
