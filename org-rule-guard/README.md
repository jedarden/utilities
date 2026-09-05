# org-rule-guard

The org-wide `PreToolUse` guard, extracted from `~/.claude/hooks/org-rule-guard.py`,
plus the thing the live hook never had: **a record of every denial.** Until now
the enforcement layer had exactly one output path — the deny JSON on stdout —
so nothing could say which rule agents keep hitting, in which repo, how often,
and the prose in `CLAUDE.md` could not be tuned against evidence.

Same six rules, same deny messages, same fail-open contract as the live hook.
One addition: every deny appends one JSON line to a log.

| Rule | Slug(s) | Scope | What it stops |
|---|---|---|---|
| 1 | `github-actions-workflow` | any write to `.github/workflows/*` | GitHub Actions, disabled org-wide; CI runs on Argo Workflows in `iad-ci` |
| 2 | `k8s-job-cronjob` | `.yaml`/`.yml` only | `kind: Job` and `kind: CronJob`, which ArgoCD cannot prune |
| 3 | `latest-image-tag` | `.yaml`/`.yml` only | `image: …:latest`, which breaks rollback |
| 4 | `mutating-kubectl` | Bash | `kubectl apply/delete/patch/scale/…`; read-only verbs, `exec`, `cp`, `logs` and Argo Workflow submission stay allowed |
| 5 | `credential-value` | **every** file type, and Bash | a credential *value*; secrets travel by reference |
| 6 | `git-commit-all`, `git-commit-no-pathspec` | Bash | `git commit -a` and bare `git commit -m`, which sweep in a sibling worker's staged files |

Rule 6 has two slugs because it has two failure modes with different fixes.
Rules 2–3 match real manifest lines only, never comments, so a document that
*describes* the prohibition is not itself blocked — this README passes.

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
file 600.

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
# decisions + log, against the ported copy          (35 tests)
python3 -m unittest discover -s ~/utilities/org-rule-guard/hooks

# decisions only, against the live hook             (20 tests, 15 skipped)
ORG_RULE_GUARD_UNDER_TEST=~/.claude/hooks/org-rule-guard.py \
  python3 -m unittest discover -s ~/utilities/org-rule-guard/hooks
```

The 15 log tests are skipped against the live hook because it predates the log
(`LOGS = hasattr(guard, "log_denial")`), not because they would fail. Every run
points `XDG_STATE_HOME` at a throwaway directory, so running the suite never
appends synthetic denials to a real log.

## Not in here yet

The rules are still Python. The next phase moves them into a YAML file with
per-rule id, pattern, tool scope and message, so a promoted lesson can land as
data rather than a code edit, and the credential rule delegates to
`agent-secrets/credential-guard.py` instead of duplicating its pattern table —
see `docs/plan/plan.md`, Phase 3(b).
