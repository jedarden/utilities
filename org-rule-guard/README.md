# org-rule-guard

The org-wide `PreToolUse` guard, extracted from `~/.claude/hooks/org-rule-guard.py`,
plus the thing the live hook never had: **a record of every denial.** Until now
the enforcement layer had exactly one output path — the deny JSON on stdout —
so nothing could say which rule agents keep hitting, in which repo, how often,
and the prose in `CLAUDE.md` could not be tuned against evidence.

Same six rules, same deny messages, same fail-open contract as the live hook.
One addition: every deny appends one JSON line to a log. The Python hook is the
authoritative rule configuration; each rule below links to its rule slug and
check in [`hooks/org-rule-guard.py`](hooks/org-rule-guard.py).

See [`CHANGELOG.md`](CHANGELOG.md) for release notes.

## Relationship with agent-secrets

`org-rule-guard` is a runtime leaf. Its `credential-value` rule is bundled and
continues to run when this folder is installed by itself; the installed hook
does not import, execute, or look up `agent-secrets`. The one sanctioned reuse
mechanism is the pinned install-time bundle declared in
[`bundled-dependencies.json`](bundled-dependencies.json): `install.sh` copies
`agent-secrets` v0.1.0's hook into the installed
`org-rule-guard/credential-guard.py` sublayout. That source checkout reference
exists only while installing and is checked by `scripts/check-structure.py`;
runtime delegation must use the copied file.

`agent-secrets`'s `credential-guard.py` is still an optional settings-level
companion, not a required runtime dependency. It has a broader built-in
pattern set and supports extra patterns, so wiring both gives defense in depth
and the union of their credential coverage. Installing only `org-rule-guard`
still enforces its credential rule. Installing only `agent-secrets` provides
credential coverage but not the org-specific Kubernetes, GitHub Actions, or
Git protections.

| Rule | Slug(s) | Scope | What it stops |
|---|---|---|---|
| [1](hooks/org-rule-guard.py#L434) | [`github-actions-workflow`](hooks/org-rule-guard.py#L57) | any Write/Edit/MultiEdit write to `.github/workflows/*` | GitHub Actions, disabled org-wide; CI runs on Argo Workflows in `iad-ci` |
| [2](hooks/org-rule-guard.py#L444) | [`k8s-job-cronjob`](hooks/org-rule-guard.py#L58) | Write/Edit/MultiEdit of `.yaml`/`.yml` only | `kind: Job` and `kind: CronJob`, which ArgoCD cannot prune |
| [3](hooks/org-rule-guard.py#L453) | [`latest-image-tag`](hooks/org-rule-guard.py#L59) | Write/Edit/MultiEdit of `.yaml`/`.yml` only | `image: …:latest`, which breaks rollback |
| [4](hooks/org-rule-guard.py#L325) | [`mutating-kubectl`](hooks/org-rule-guard.py#L60) | Bash | `kubectl apply/delete/patch/scale/…`; read-only verbs, `exec`, `cp`, `logs` and Argo Workflow submission stay allowed |
| [5](hooks/org-rule-guard.py#L405) | [`credential-value`](hooks/org-rule-guard.py#L61) | **every** Write/Edit/MultiEdit file type, and Bash | a credential *value*; secrets travel by reference |
| [6](hooks/org-rule-guard.py#L221) | [`git-add-all`](hooks/org-rule-guard.py#L62), [`git-commit-all`](hooks/org-rule-guard.py#L63), [`git-commit-no-pathspec`](hooks/org-rule-guard.py#L64) | Bash | blanket `git add -A`/`.`/`--all`, `git commit -a`, and bare `git commit -m`, which sweep in a sibling worker's staged files |

Rule 6 has three slugs because blanket staging and the two commit failure
modes have different fixes.
Rules 2–3 match real manifest lines only, never comments, so a document that
*describes* the prohibition is not itself blocked — this README passes.

## PreToolUse behavior

Claude Code invokes the hook for `Write`, `Edit`, `MultiEdit`, and `Bash` through the
`PreToolUse` matcher shown in the [settings example](examples/settings.json).
The hook reads one JSON payload from stdin and handles one tool call per
process. The first matching rule denies the call and writes one JSON object to
stdout with this shape:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "why this call is prohibited"
  }
}
```

Allowed calls are silent and exit 0. The fail-open input contract covers
malformed or unreadable stdin, non-object JSON, missing or empty `tool_input`,
and missing or unexpected `tool_name` values: each case allows the call,
writes nothing to stdout, and does not create or append a denial-log record.
An unparseable shell segment or other internal error has the same result. A
denial-log write failure does not change a matching deny: the hook still emits
the deny JSON and exits 0. The implementation of this protocol is
[`deny()`](hooks/org-rule-guard.py#L77) and [`main()`](hooks/org-rule-guard.py#L463).

## Settings wiring

Merge the standalone entry below into the operator's `~/.claude/settings.json`;
keep any unrelated settings already present. The complete checked-in example
is [`examples/settings.json`](examples/settings.json). To install the optional
companion too, use the combined example at
[`../docs/examples/settings-both.json`](../docs/examples/settings-both.json),
or run both utilities' `install.sh --wire` commands against the same settings
file. Each installer appends only its own entry and preserves unrelated
settings.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit|Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/org-rule-guard.py",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

`install.sh --wire` installs the hook, stages the pinned credential-guard
bundle, and merges this same entry. A bare `install.sh` prints it without
changing settings; it still stages the bundle when it installs.

The entry is identified by its exact command. A current entry uses the
`Write|Edit|MultiEdit|Bash` matcher and timeout `10`, so re-running `--wire`
is a no-op. The pre-MultiEdit shipped entry (`Write|Edit|Bash`, timeout `10`)
is recognized and refreshed in place during an upgrade. Any other same-command
matcher or timeout is treated as an operator customization, preserved, and
reported; use `--wire --force` as the explicit escape hatch to replace those
wiring fields. If the command is absent, `--wire` appends the entry.

The settings merge is protected by an exclusive advisory lock at
`$CLAUDE_SETTINGS.lock` (or `~/.claude/settings.json.lock`), which is kept so
concurrent `--wire` runs use the same lock. The lock covers reading, merging,
backup creation, and replacement. Each changed file is written to a uniquely
named temporary file in the settings file's directory, flushed, and
atomically renamed into place; an interruption before the rename leaves the
live file complete. Rewriting an existing file preserves its permission bits,
including mode `0600`. If the two utility installers run concurrently, the
second waits and rereads the first result, preserving both hook entries and
unrelated settings. Manual writers that do not honor the same advisory lock
must not edit the file during a wire; their races are outside this guarantee.

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

`CLAUDE_SETTINGS` defaults to `~/.claude/settings.json` and is used literally
for `--wire`. An absolute value is used as an absolute path. A relative value
is resolved against the installer's current working directory, not against the
utility checkout or `$HOME`; use the same working directory as well as the
same value on every run. The settings parent directory must already exist:
the settings step exits nonzero without creating a missing parent, settings
file, lock, or backup. The utility destinations may already have been copied
before that failed settings step, so retry after fixing the path.

Symlinks in the path are resolved before the settings file is read, locked,
backed up, or replaced. A final-component symlink is preserved and its target
is updated; the target's directory receives the `.lock`, temporary file, and
`.bak`. The target must be writable, and its parent must exist.

The two installers do not coordinate different settings files. If one run
uses path A and a later run uses distinct path B, each file receives only the
entry for the utility run against it, and each existing file gets its own
one-time pre-wiring `.bak`. Neither backup is a rollback point for the
combined installation. To compose both guards and retain one rollback point,
run both installers against the same effective settings target (the same path
or symlink-resolved target) every time.

When `--wire` changes an existing settings file, it creates
the effective settings target's `.bak` (normally
`$CLAUDE_SETTINGS.bak`, or `~/.claude/settings.json.bak`) immediately before
the first wiring change, but only if that backup does not already exist. For a
symlinked settings value, this is beside the resolved target, as described
above. The backup therefore remains the pre-wiring settings file when another
utility is wired later or this installer is run again. If the settings file
does not yet exist, no backup is created because there is no prior file to
preserve.

The `.bak` is a permanent, one-time pre-wiring snapshot rather than a rolling
backup. `--wire` and `--uninstall` never rewrite or remove an existing backup.
Inspect a suspected bad wire with:

```bash
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
diff -u "$SETTINGS.bak" "$SETTINGS"
```

After reviewing the diff, restore the whole pre-wiring file with
`cp -p "$SETTINGS.bak" "$SETTINGS"`, or merge only the wiring changes if
later settings edits must be kept. The installer gives the backup
the source file's permission bits, so a mode-`0600` settings file produces a
mode-`0600` backup. Delete the backup only after the live settings are verified
and this rollback point is no longer needed; the next wiring change creates a
new snapshot when no backup is present.

If an existing settings file is malformed JSON, or its top-level value is not
an object, `--wire` creates the pre-wiring `.bak` when it is owed, prints a
clear refusal to stderr, exits nonzero, and leaves the settings file
byte-for-byte unchanged. It never appends a hook entry to such a file.

### Composed execution

The combined configuration has two independent `PreToolUse` entries: the org
guard matches `Write|Edit|MultiEdit|Bash`, and the optional credential guard matches
`Write|Edit|MultiEdit|Bash`. Claude Code runs all matching hook handlers in
parallel, so the order of entries in `settings.json` is for readability only,
not an execution-order guarantee. Both handlers receive the same payload.
Their decisions are combined with `deny` taking precedence, so an allow from
one hook cannot override a deny from the other. See the
[Claude Code hooks reference](https://code.claude.com/docs/en/hooks#hook-handler-fields)
for the host semantics.

There is no runtime fallback lookup: if the optional companion is not
installed, leave its settings entry out and `org-rule-guard` continues to
provide its bundled credential rule. A stale settings entry pointing at a
missing command provides no credential coverage and should be removed; it does
not change the org guard's behavior.

If both hooks recognize the same credential, both processes may emit a deny,
but Claude Code blocks the tool call once. This is an expected duplicate at
the hook layer, not two tool executions or two permission prompts. Each hook
writes one record to its own log: `org-rule-guard` records its redacted
fragment, and the credential companion records only properties and a payload
shape. Do not wrap one hook inside the other or make either hook convert the
other hook's deny into an allow.

## Install

```bash
git clone --branch org-rule-guard/v0.1.0 --depth 1 \
  https://git.ardenone.com/jedarden/utilities.git ~/utilities-org-rule-guard
~/utilities-org-rule-guard/org-rule-guard/install.sh --wire
```

For a reproducible install, select an `org-rule-guard/vX.Y.Z` release tag before
running the installer. The tag is the version selector; `install.sh` has no
separate `--version` flag. Keep a checkout per utility so changing this tag
does not change the source revision used for another utility in the monorepo.

A hook already at `~/.claude/hooks/org-rule-guard.py` is live enforcement, so a
bare run never overwrites it: it prints the destination, says `not overwritten`,
and leaves the deployed copy alone. `--force` replaces it with this copy;
`--wire` replaces it and merges the settings entry in one step. `--wire` also
refreshes the pinned `agent-secrets` credential-guard bundle from the selected
release checkout and upgrades known legacy settings wiring. Python 3 and bash
are the only dependencies. Customized matcher/timeout fields are preserved by
default; use `--wire --force` when the selected release should replace them.

### Pin, upgrade, and remove

To upgrade an existing tagged install, fetch the new release, check it out,
and run that release's installer with `--wire`:

```bash
cd ~/utilities-org-rule-guard
git fetch --tags origin
git checkout --detach org-rule-guard/vX.Y.Z
./org-rule-guard/install.sh --wire
```

Review and commit any local changes in the source checkout before changing
tags; `git checkout` will refuse to overwrite uncommitted work. The upgrade
refreshes both the org hook and its bundled credential guard. It does not
remove either denial log at
`${XDG_STATE_HOME:-~/.local/state}/{org-rule-guard,credential-guard}/`.

To remove the installed files, run `--uninstall` from the exact release
checkout that supplied them (or from the currently installed release after an
upgrade):

```bash
./org-rule-guard/install.sh --uninstall
```

The uninstaller removes the org hook and its bundled credential guard only when
they still match this checkout, refusing a hand-edited or unknown copy unless
`--force` is supplied. It intentionally leaves `settings.json` and both denial
logs untouched. After uninstalling, remove this utility's `PreToolUse` command
from `settings.json` yourself; keep the entry if another installed copy still
uses that same destination. The source checkout can then be deleted if it is
no longer needed.

Promoting the copy that logs is what turns the learning signal on — the live
hook as of 2026-09 still predates the log and writes nothing.

## The denial log

```
${XDG_STATE_HOME:-~/.local/state}/org-rule-guard/denials.jsonl
```

One line per deny, appended with a single `O_APPEND` write so concurrent
workers on a shared box do not interleave. The hook also takes an advisory lock
for the rotation-and-append sequence, so concurrent sessions cannot rename the
active file underneath one another. The directory is owned by the user running
the hook and is created with mode `0700`; the active log, one rotated backup,
and the lock file are created with mode `0600`, regardless of the caller's
umask. On later writes, the hook may tighten an existing path to these private
modes, but it never loosens an existing log's permissions. Each JSONL record
contains exactly the six fields below; records are independent, so a malformed
or partial line must not be treated as a schema change.

The active `denials.jsonl` is capped at 256 KiB. When the next record would
cross that limit, the active file is atomically moved to
`denials.jsonl.1`, replacing the previous backup, and the new record starts a
fresh active file. The backup is trimmed to the same limit when necessary, so
the two retained log files occupy at most 512 KiB in total. The lock file is
`denials.jsonl.lock`; it is an implementation detail and is not JSONL data.
This is a bounded rolling window, not an archival log: older denials are
discarded at rotation. All hook processes using this utility take the same
lock, and each record is written with one `O_APPEND` write while holding it.
Manual writers that do not honor that lock are outside the atomicity contract.

```json
{"ts": "2026-09-05T12:41:07Z", "rule_id": "mutating-kubectl",
 "tool": "Bash", "cwd": "/home/coding/NEEDLE", "session_id": "a4f1…",
 "fragment": "kubectl delete pod worker-0 -n default"}
```

| Field | Meaning |
|---|---|
| `ts` | UTC ISO-8601 with a `Z` suffix, matching `jq`'s `todate`, so timestamps sort and compare as plain strings |
| `rule_id` | the slug from the table above |
| `tool` | `Write`, `Edit`, `MultiEdit`, `Bash`, … |
| `cwd` | the working directory from the hook input, falling back to the process's own |
| `session_id` | from the hook input when present, else empty |
| `fragment` | a redacted, whitespace-flattened, 80-character-truncated piece of what matched |

### Redaction

The credential rule logs its **pattern name** — `GitHub token`, `AWS access key
id` — and never the match. Independently of that, every fragment is scrubbed
through the same credential patterns before it is written, so a value reaching
the log through any *other* rule's fragment (a commit message, a `kubectl`
line) is stored as `[redacted]`. A blocked credential must not end up on disk
somewhere else; a denial log that leaks is worse than no log.

Ordering makes that hold in practice too: the credential rule runs first on a
Bash command, so a command that trips both it and another rule logs as
`credential-value` with the pattern name, not as the other rule with the value
in its fragment.

### Reading it

Denials by rule over the last 7 days:

```bash
LOG=${XDG_STATE_HOME:-$HOME/.local/state}/org-rule-guard/denials.jsonl
jq -r 'select(.ts >= $cutoff) | .rule_id' \
   --arg cutoff "$(date -u -d '7 days ago' +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v-7d +"%Y-%m-%dT%H:%M:%SZ")" \
   "$LOG" | sort | uniq -c | sort -rn
```

Same window, by repo — the "which checkout keeps hitting this" question:

```bash
CUTOFF="$(date -u -d '7 days ago' +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v-7d +"%Y-%m-%dT%H:%M:%SZ")"
jq -r 'select(.ts >= $cutoff) | [.rule_id, .cwd] | @tsv' --arg cutoff "$CUTOFF" "$LOG" \
  | sort | uniq -c | sort -rn
```

Filtering on `ts` with `jq` rather than hoping for a field selector is
deliberate: timestamp comparison needs a real inequality, and no `jq`
replacement here has one either.

## Failing open

Malformed or unreadable input, missing or empty `tool_input`, an unexpected
tool name, an unparseable shell segment, an internal error, anything
unexpected → allow, exit 0, no output, and no denial-log record. A NEEDLE fleet
must never be wedged by its own guard: a missed violation is recoverable, a
stuck fleet is not. The log inherits the same best-effort boundary for denied
calls — `deny()` attempts the write inside a bare `except` and emits its
decision regardless, so an unwritable log (a full disk, a vanished home, a
state path that is a regular file) still denies, never allows. A rule that
stops firing because logging broke would be a silent loss of enforcement; that
is why the log can change nothing.

## Tests

```bash
python3 -m unittest discover -s ~/utilities/org-rule-guard/hooks -v
```

Fixtures are built at runtime, so no rule-triggering literal sits in the test
file — which matters, because the guard under test is usually installed on the
machine editing it and would correctly refuse to write one. Each deny is
paired with a near-miss allow, so a fix that widens a pattern to catch the
deny cannot quietly catch the allow too.

The suite runs against *whichever* hook `ORG_RULE_GUARD_UNDER_TEST` names,
defaulting to this copy — the same fixtures prove the port matches the live
hook and that the log behaves:

```bash
# decisions + log + installer, against the ported copy   (50 tests)
python3 -m unittest discover -s ~/utilities/org-rule-guard/hooks

# same suite, against the live hook                      (log tests skipped if unsupported)
ORG_RULE_GUARD_UNDER_TEST=~/.claude/hooks/org-rule-guard.py \
  python3 -m unittest discover -s ~/utilities/org-rule-guard/hooks
```

The denial-log tests are skipped against the live hook because it predates the
log (`LOGS = hasattr(guard, "log_denial")`), not because they would fail. Every
run points `XDG_STATE_HOME` at a throwaway directory, so running the suite
never appends synthetic denials to a real log.

The explicit supported-tool boundary test is also skipped when the installed
live hook predates that utility-side guard (`SUPPORTED_TOOLS` is absent). The
ported copy always runs it, including a rule-shaped payload for an unexpected
tool name.

The cross-utility composition test runs from the repository root and invokes
both hook files against the same payloads, including both hook orders:

```bash
python3 -m unittest discover -s scripts -p 'test_hook_composition.py' -v
```

## Configuration boundary

The rules remain Python and this utility intentionally owns its credential
fallback. Phase 3(b) may reduce pattern duplication by consuming the copied
bundle, but it must preserve the no-runtime-sibling-dependency contract and
the pinned manifest. Until that phase lands, `agent-secrets` is an optional
companion selected at settings level rather than a delegated runtime
implementation dependency.
