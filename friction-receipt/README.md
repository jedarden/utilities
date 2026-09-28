# friction-receipt

`friction-receipt` is a fail-open Claude Code `SessionEnd` hook. It writes one
small, private JSON receipt per session for TWILL to read later. It never edits
rules, prompts, transcripts, or another repository.

The source files in this utility, and the files `install.sh` places on user
hosts, are licensed under the MIT License. Installation does not change that
coverage and does not copy a separate license file; retain the repository's
root `LICENSE` text when redistributing an installed copy.

## Receipt contract

Receipts are written to
`${XDG_STATE_HOME:-$HOME/.local/state}/twill/friction-receipts/<session_id>.json`
with mode `0600` in a mode `0700` directory. `TWILL_RECEIPTS_DIR` overrides the
directory for tests and explicitly managed installations. A receipt is replaced
atomically, so a killed hook leaves the previous complete record intact.

The top-level shape is versioned as `twill-friction-receipt/v1`:

```json
{
  "schema": "twill-friction-receipt/v1",
  "session_id": "session-id",
  "ended_at": "2026-09-28T20:00:00Z",
  "reason": "prompt_input_exit",
  "cwd": "/repo",
  "rules_consulted": ["AGENTS.md", "skills/testing"],
  "denials": [{"ts": "...", "rule_id": "latest-image-tag", "tool": "Write"}],
  "unresolved_errors": [{"kind": "tool_error", "signature": "bounded redacted text"}],
  "ended_mid_task": false
}
```

`rules_consulted` is derived from rule-file and skill reads in the transcript.
`denials` selects the matching session entries from the org-rule-guard JSONL
log, including its rotated file when present. Unresolved errors are bounded
signatures for failed tool results and Bash calls with no result. The hook
redacts credential-shaped values, normalizes whitespace, caps all text and list
sizes, and never stores a raw transcript record or tool payload.

Malformed hook input, missing or truncated transcripts, unreadable logs, and
state-directory failures are swallowed; the hook exits 0 in all cases.

## Install and wire

```bash
./install.sh --wire
```

The installer is idempotent. Without `--wire`, it copies
`~/.claude/hooks/friction-receipt.py` (or `CLAUDE_HOOKS_DIR` plus that
filename), leaves `settings.json` untouched, and prints the exact entry to
merge. It never overwrites an existing hook without `--force`; `--wire` is the
deliberate upgrade mode and replaces the installed hook before merging its
settings entry. A plain re-run leaves an existing local hook untouched.

The current `SessionEnd` entry is one command handler with timeout `10`:

```json
{
  "hooks": {
    "SessionEnd": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/friction-receipt.py",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

`--wire` identifies the entry by the exact command `python3 <installed-hook-path>`.
If the current timeout is already `10`, it reports `already` and leaves the
settings bytes unchanged. The complete known-legacy inventory is the exact
same command handler with no `timeout` field, which was the v0.1.0 shipped
shape; `--wire` refreshes that handler in place by adding timeout `10`. No
other timeout is a legacy entry.

If a same-command handler has another timeout, `--wire` preserves
`settings.json` byte-for-byte, prints exactly one `preserved` report on stderr,
and exits `2`. Use `--wire --force` to replace only the timeout with `10`;
the command, handler type, other fields, containing entry, and unrelated
settings remain intact. If the command is absent, the entry is appended. A
single settings file may contain unrelated SessionEnd handlers; they are
always preserved.

The settings merge uses the same exclusive advisory lock as the other utility
installers: the effective `CLAUDE_SETTINGS` path is realpath-resolved before
locking, so a symlinked settings file gets its lock beside its target. The
lock is created lazily at `$CLAUDE_SETTINGS.lock` with mode `0600`, corrected
to that mode when reused, and held across stale-temp cleanup, reading,
merging, backup creation, and atomic replacement. A wire waits at most 30
seconds; set `CLAUDE_SETTINGS_LOCK_TIMEOUT` to another positive finite number
to change that deadline. A lock refusal is nonzero and does not modify the
settings file. Each changed file is written to a friction-receipt-specific
temporary file in the settings directory, flushed, fsynced, and atomically
renamed; interruptions clean the active temporary file. A hard kill may leave
a temporary file for the next friction-receipt wire to reap.

When an existing settings file changes, the installer creates one
`<resolved-settings>.bak` snapshot if it does not already exist and preserves
the source mode. The backup is the pre-wiring file: later wires and uninstall
never rewrite, remove, or restore it. A newly created settings file is mode
`0600` and has no backup. The settings parent must already exist; the
installer does not create it.

`--uninstall` first applies the same ownership check to the installed hook. A
foreign or locally edited hook is not removed unless `--force` is supplied.
It then acquires the same settings lock and removes only recognized current or
known-legacy exact-command SessionEnd handlers. A customized handler is
preserved and exits `2` unless `--uninstall --force` is supplied. Invalid
settings, a lock failure, or any unwiring failure leaves the installed hook in
place. On success the settings entry is removed before the hook file, the lock
file is removed, the backup is left untouched, and all receipt state is left
in place. Removing the hook manually without unwiring leaves Claude invoking
a missing command, so use the installer lifecycle.

The receipt hook reads the org-rule-guard denial log if that guard is installed,
but does not require it. The two hooks may be installed independently.
