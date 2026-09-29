# utilities Plan

## Overview

Small, self-contained tools for running coding agents safely. One folder per
tool; nothing shared between folders except the root MIT License and this
plan.

## Architecture

- Every utility is a runtime leaf: `README.md`, `VERSION`, `install.sh`, and
  its files. No shared library directory — a shared `lib/` is how an "install
  one thing" repo turns into "install everything" (see jeds-curated-skills,
  whose installer had to inline `lib/common.sh` for exactly this reason).
  Optional companions may be composed by the host's settings, but an installed
  utility must not import, execute, or look up a sibling at runtime.
- The one sanctioned reuse path is an install-time bundle. A utility may add
  `bundled-dependencies.json` with a sibling name, exact sibling `VERSION`,
  source path, and destination path. Its `install.sh` may read that pinned
  source and copy it into the utility's own installed layout; the installed
  copy is then the only runtime input. `scripts/check-structure.py` verifies
  the manifest, the sibling version, the source file, and the copy reference,
  while rejecting every undeclared sibling reference. This is the mechanism
  Phase 3(b) must use if it reuses `agent-secrets`' credential guard; a direct
  import or subprocess delegation to the checkout is not sanctioned.
- Scripts are POSIX shell or Python 3 stdlib. No package installs. The
  stdlib-only `scripts/check-structure.py` gate enforces this for utility-owned
  runtime files: it requires POSIX `sh` shebangs, rejects package-manager
  install commands and absolute Python imports outside the stdlib or the same
  utility, and rejects undeclared sibling runtime references. `scripts/` and
  `docs/` remain repository tooling/documentation rather than utility runtime.
- Each `install.sh` is idempotent and copies into the conventional user
  locations (`~/.claude/hooks/`, `~/.local/bin/`); it never edits a file it
  did not create unless asked with an explicit flag.
- Versioning is per folder (`<utility>/VERSION`, semver), and every utility
  keeps a `CHANGELOG.md` beside it. Each release adds a concise entry headed
  `## [X.Y.Z] - YYYY-MM-DD` in the same commit as the VERSION bump. Git tags
  are `<utility>/vX.Y.Z`. The contract is enforced by
  `scripts/check-versions.sh` (run by utilities-ci on every push): every
  VERSION at HEAD must have its current-version changelog heading and a tag at
  exactly its version, and every `<utility>/v*` tag must point at a commit whose
  VERSION agrees. Releasing means committing the notes and bump, then pushing
  commit and tag together — `git push origin main <utility>/v<X.Y.Z>` — since
  pushing the commit alone fails CI until the tag lands.
- The leaf contract is enforced by `scripts/check-structure.py`, which is
  invoked by that same CI gate before the version/tag check. Every top-level
  utility must own `README.md`, `VERSION`, `CHANGELOG.md`, and `install.sh`;
  symlinks, non-
  POSIX shell shebangs, package-manager install commands, non-stdlib Python
  imports, and undeclared runtime references into a sibling utility are
  rejected. The README Folder table must match the top-level utility folders
  in both directions. The executable inventories and maintenance process for
  this gate live in [`docs/structure-check.md`](../structure-check.md), with
  documentation-drift tests in `scripts/test_check_structure.py`.

## Components

### agent-secrets (v0.1.0)

- `hooks/credential-guard.py` — Claude Code PreToolUse hook. Denies Write,
  Edit, MultiEdit, NotebookEdit and Bash calls whose body carries a high-signal credential
  value. Fails open. Placeholders and `gitleaks:allow` pass. Its built-in
  pattern inventory, high-signal definition, and update process live in
  [`agent-secrets/docs/credential-patterns.md`](../../agent-secrets/docs/credential-patterns.md)
  and must stay synchronized with the hook source. Every denial also appends
  one bounded JSONL record to `${XDG_STATE_HOME:-~/.local/state}/credential-guard/denials.jsonl`
  containing only timestamp, rule id, tool, invocation metadata, and a fixed
  payload-shape label; the matched payload and credential value never enter the
  log. The state directory is created mode 0700 and the log mode 0600,
  regardless of umask; existing log permissions are never loosened. Logging is
  best-effort and does not change the enforcement decision.
- `hooks/test_credential_guard.py` — unittest suite; fixtures are built at
  runtime so the test file itself never contains a token-shaped literal. It
  covers the built-in matcher, denied Write/Edit/MultiEdit/NotebookEdit/Bash calls,
  placeholder and `gitleaks:allow` pass paths for each tool shape, malformed
  and unexpected-input fail-open behavior, property-only denial records and
  logging failures, and the installer contract.
- `bin/bao-as` — `bao-as <instance> <command...>`: AppRole login to one
  named OpenBao/Vault instance with credentials passed as `@file`, then
  `exec` the command with the token only in its environment. Refuses to
  start when a credential file is missing or readable by group/other —
  mode 0600 is enforced, not advisory.
- `bin/test_bao_as.py` — unittest suite for the wrapper. Runs it against
  stubs placed first on `PATH` and a throwaway `BAO_AS_CONFIG_DIR`, then
  inspects what actually happened: the default `bao` selection, the
  `BAO_AS_BIN=vault` override, and missing/non-executable/unsupported
  selections fail closed; the login argv carries
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
  for the small HCL subset used by the templates, plus the broken-policy
  fixtures that prove the subset rejects common editing mistakes. The rule
  names follow the `vault/policy.go` set, but this is an approximation, not
  OpenBao's loader. It currently accepts same-line object members without
  commas, duplicate attributes, and boolean `required_parameters` items that
  OpenBao 2.5 rejects; it rejects unquoted block labels that OpenBao accepts.
  Every template must parse and must match its documented grant, but that
  structural check does not guarantee that arbitrary policy text will pass
  `bao policy write`. Run `bao policy fmt` on a disposable rendered copy and
  use the target `bao policy write` as the authoritative validation before
  applying a policy.
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
  values, no blanket `git commit`. Its file-content rules inspect Write, Edit,
  MultiEdit and NotebookEdit calls; its shell rules inspect Bash calls, and the shipped
  matcher covers all five tool classes. Same six rules, same deny messages,
  same fail-open contract as the live hook. Every denial additionally appends one
  JSON line (`ts`, `rule_id`, `tool`, `cwd`, `session_id`, redacted 80-char
  fragment) to `${XDG_STATE_HOME:-~/.local/state}/org-rule-guard/denials.jsonl`.
  Its state directory is created mode 0700 and the log mode 0600, regardless of
  umask; existing log permissions are never loosened.
  The credential rule logs its pattern name, never a value, and every other
  fragment is scrubbed through the same patterns before it is written.
  Its credential rule is bundled so this utility remains standalone;
  `agent-secrets/hooks/credential-guard.py` is an optional companion with a
  broader pattern set, not a runtime dependency.
- `hooks/test_org_rule_guard.py` — unittest suite; fixtures are built at
  runtime so no rule-triggering literal sits in the test file.
  `ORG_RULE_GUARD_UNDER_TEST` points the whole suite at any hook copy, so one
  fixture set proves both that the port matches the live hook and that the
  log behaves (the log tests skip against a hook that predates the log).
  The `Install` class drives `install.sh` in a throwaway hooks dir / settings
  path (plus one temp `$HOME` for the default destinations), covering every
  contract clause above including the refusal paths: no overwrite without
  `--force`, no settings write without `--wire`, `--uninstall` refusing a
  file this folder did not install, removing provenance, and retaining both
  denial state directories because their bounded audit history survives an
  uninstall.
- `install.sh` — idempotent copy into `~/.claude/hooks/`. Never overwrites a
  hook already at the destination and never touches `settings.json` without
  `--wire`; `--uninstall` refuses a file this folder did not install. It also
  copies the pinned `agent-secrets` credential guard into the installed
  `org-rule-guard/` sublayout; the source reference is install-time only and
  is declared in `bundled-dependencies.json`.
- `bundled-dependencies.json` — pins `agent-secrets` v0.1.0's credential guard
  source to the copy installed under `org-rule-guard/`. The current v0.1.0
  hook still owns its standalone credential fallback; the bundle is the
  approved seam for Phase 3(b)'s future rule-engine delegation.
- `examples/settings.json` — the hook wiring for `~/.claude/settings.json`.

### friction-receipt (v0.1.0)

- `hooks/friction-receipt.py` — a fail-open Claude Code `SessionEnd` hook. It
  writes one atomically replaced `twill-friction-receipt/v1` JSON object per
  session to `${XDG_STATE_HOME:-~/.local/state}/twill/friction-receipts/`.
  The record contains the canonical rule files and skills read from the
  transcript, matching org-rule-guard denials, bounded unresolved error
  signatures, and an `ended_mid_task` flag. Credential-shaped values are
  redacted before all fields are bounded; raw transcript records are never
  copied. The directory is mode 0700 and records are mode 0600. Each record is
  hard-limited to 64 KiB; there is no rotation or age-based expiry, so one
  record per session remains until an operator removes it. Uninstall leaves
  the receipt directory and its records in place.
- `hooks/test_friction_receipt.py` — fixture-driven round-trip and installer
  contract coverage for rule reads, denials, unresolved errors, mid-task
  sessions, malformed input, permissions, redaction, hard size bounding,
  idempotent wiring, legacy refresh, customization preservation, ownership
  refusal, uninstall unwiring, and receipt retention.
- `install.sh` — idempotent copy to `~/.claude/hooks/friction-receipt.py`;
  `--wire` merges one exact-command `SessionEnd` entry under the shared
  lock/backup/atomic-write protocol, refreshes only the documented no-timeout
  legacy entry, and reports customized entries with exit 2. `--uninstall`
  checks ownership, unwires recognized entries before removing the hook, and
  never removes receipts or rewrites the settings backup.
- `README.md` — the versioned receipt schema, location, redaction and failure
  contract, and install instructions.

## Data Models

None. Configuration is files under `~/.config/bao-as/` (instance table and
per-instance `role_id` / `secret_id`, mode 0600) and an optional
`~/.config/credential-guard/patterns.json` for extra patterns. The state
artifacts are the two independent denial-log directories,
`${XDG_STATE_HOME:-~/.local/state}/{org-rule-guard,credential-guard}/`, owned
by the user running each hook. Each contains a mode-600 active `denials.jsonl`,
one mode-600 `denials.jsonl.1` backup, and a mode-600 advisory lock. Each active
log is capped at 256 KiB and rotates to its single backup before an append
would cross that bound; each pair of retained JSONL files is therefore capped
at 512 KiB in total. Concurrent hook processes take the relevant lock across
rotation and their single `O_APPEND` record write. The hooks never read log
records as application data.

## Implementation Phases

- [x] Phase 1: `agent-secrets` — hook, wrapper, policies, tests, installer
- [x] Phase 2: CI on Argo Workflows (unittest + shellcheck) — no GitHub
  Actions — shipped 2026-09-15 as `utilities-ci` (WorkflowTemplate + Forgejo
  push sensor; runs the unittest suites and shellcheck on every push to
  main, including the org-rule-guard installer contract). Grew the
  policy-template HCL validation suite on 2026-09-16. Since 2026-09-16
  it also runs `scripts/check-versions.sh` to enforce the VERSION↔tag,
  current-version changelog, and self-contained leaf contracts (see
  Architecture). The repository's `scripts/check-shellcheck.sh` gate enforces
  ShellCheck 0.9.0 or newer before invoking the shell checks.
- [ ] Phase 3: `org-rule-guard` — extract the working PreToolUse hook from
  `~/.claude/hooks/org-rule-guard.py` (332 lines, six hard-coded rules, one
  stdout deny path, no log). Two changes, in this order: (a) every denial
  appends one JSONL line (`ts`, `rule_id`, `tool`, `cwd`, `session_id`,
  matched fragment redacted) to `~/.local/state/org-rule-guard/denials.jsonl`,
  so the fleet finally has a record of which rules agents keep hitting and
  where the prose is failing; (b) the rules move out of Python into a YAML
  file with per-rule id, pattern, tool scope and message, so a promoted lesson
  can land as data rather than a code edit. If its credential rule reuses
  `agent-secrets`, it must consume the pinned install-time bundle described in
  Architecture; it must never import or execute the sibling checkout. The
  standalone credential rule remains the fallback until that bundle is used.
  Same fail-open contract, same tests passing before and after.
  - [x] Phase 3(a): denial log — shipped 2026-09-05 as `org-rule-guard/`
    v0.1.0; its bounded two-file rotation and cross-process append lock are
    covered by regression tests (green against the ported copy and the live
    hook where supported)
  - [ ] Phase 3(b): YAML rules with the credential rule consuming the pinned
    install-time bundle while preserving the standalone fallback and documenting
    optional settings-level companion composition
- [ ] Phase 4: further utilities as they are extracted from working setups

## Open Questions

- Whether `credential-guard.py` should grow an *output* check (a PostToolUse
  hook that redacts tool results). Today it only sees what the agent writes
  and runs, never what comes back; that gap is documented, not closed.
