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
| [1](hooks/org-rule-guard.py#L434) | [`github-actions-workflow`](hooks/org-rule-guard.py#L57) | any write to `.github/workflows/*` | GitHub Actions, disabled org-wide; CI runs on Argo Workflows in `iad-ci` |
| [2](hooks/org-rule-guard.py#L444) | [`k8s-job-cronjob`](hooks/org-rule-guard.py#L58) | `.yaml`/`.yml` only | `kind: Job` and `kind: CronJob`, which ArgoCD cannot prune |
| [3](hooks/org-rule-guard.py#L453) | [`latest-image-tag`](hooks/org-rule-guard.py#L59) | `.yaml`/`.yml` only | `image: …:latest`, which breaks rollback |
| [4](hooks/org-rule-guard.py#L325) | [`mutating-kubectl`](hooks/org-rule-guard.py#L60) | Bash | `kubectl apply/delete/patch/scale/…`; read-only verbs, `exec`, `cp`, `logs` and Argo Workflow submission stay allowed |
| [5](hooks/org-rule-guard.py#L405) | [`credential-value`](hooks/org-rule-guard.py#L61) | **every** file type, and Bash | a credential *value*; secrets travel by reference |
| [6](hooks/org-rule-guard.py#L221) | [`git-add-all`](hooks/org-rule-guard.py#L62), [`git-commit-all`](hooks/org-rule-guard.py#L63), [`git-commit-no-pathspec`](hooks/org-rule-guard.py#L64) | Bash | blanket `git add -A`/`.`/`--all`, `git commit -a`, and bare `git commit -m`, which sweep in a sibling worker's staged files |

Rule 6 has three slugs because blanket staging and the two commit failure
modes have different fixes.
Rules 2–3 match real manifest lines only, never comments, so a document that
*describes* the prohibition is not itself blocked — this README passes.

## PreToolUse behavior

Claude Code invokes the hook for `Write`, `Edit`, and `Bash` through the
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

Allowed calls are silent and exit 0. Malformed input, an unparseable shell
segment, or an internal error exits 0 without output; the hook fails open for
unexpected conditions. A denial-log write failure does not change a matching
deny: the hook still emits the deny JSON and exits 0. The implementation of
this protocol is [`deny()`](hooks/org-rule-guard.py#L77) and
[`main()`](hooks/org-rule-guard.py#L462).

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
        "matcher": "Write|Edit|Bash",
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

### Composed execution

The combined configuration has two independent `PreToolUse` entries: the org
guard matches `Write|Edit|Bash`, and the optional credential guard matches
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
the hook layer, not two tool executions or two permission prompts. Only
`org-rule-guard` writes the JSONL denial record, so one overlapping call still
produces one `credential-value` record from this utility. Do not wrap one hook
inside the other or make either hook convert the other hook's deny into an
allow.

## Install

```bash
~/utilities/org-rule-guard/install.sh            # copy if absent; print the settings snippet
~/utilities/org-rule-guard/install.sh --wire     # also add the PreToolUse entry to settings.json
~/utilities/org-rule-guard/install.sh --force    # replace the hook already at the destination
~/utilities/org-rule-guard/install.sh --uninstall
```

A hook already at `~/.claude/hooks/org-rule-guard.py` is live enforcement, so a
bare run never overwrites it: it prints the destination, says `not overwritten`,
and leaves the deployed copy alone. `--force` replaces it with this copy;
`--wire` installs and merges the settings entry in one step. `--uninstall` is
bound by the same rule in the direction that matters more: it refuses to remove
a file this folder did not install, since on a machine still running the
pre-port hook that file is enforcement for the whole fleet. `--force` overrides.
Neither `--wire` nor `--uninstall` touches `settings.json` beyond the one entry,
and the denial log is never removed by the installer. Python 3 and bash are the
only dependencies.

Promoting the copy that logs is what turns the learning signal on — the live
hook as of 2026-09 still predates the log and writes nothing.

## The denial log

```
${XDG_STATE_HOME:-~/.local/state}/org-rule-guard/denials.jsonl
```

One line per deny, appended with a single `O_APPEND` write so concurrent
workers on a shared box do not interleave. The directory is mode 700 and the
file 600. Each JSONL record contains exactly the six fields below; records are
independent, so a malformed or partial line must not be treated as a schema
change.

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

Malformed input, an unparseable shell segment, an internal error, anything
unexpected → allow, exit 0, no output. A NEEDLE fleet must never be wedged by
its own guard: a missed violation is recoverable, a stuck fleet is not. The
log inherits the same contract and is strictly best-effort — `deny()` attempts
the write inside a bare `except` and emits its decision regardless, so an
unwritable log (a full disk, a vanished home, a state path that is a regular
file) still denies, never allows. A rule that stops firing because logging
broke would be a silent loss of enforcement; that is why the log can change
nothing.

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
# decisions + log + installer, against the ported copy   (45 tests)
python3 -m unittest discover -s ~/utilities/org-rule-guard/hooks

# same suite, against the live hook                      (27 tests, 18 skipped)
ORG_RULE_GUARD_UNDER_TEST=~/.claude/hooks/org-rule-guard.py \
  python3 -m unittest discover -s ~/utilities/org-rule-guard/hooks
```

The 15 log tests are skipped against the live hook because it predates the log
(`LOGS = hasattr(guard, "log_denial")`), not because they would fail. Every run
points `XDG_STATE_HOME` at a throwaway directory, so running the suite never
appends synthetic denials to a real log.

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
