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

Without `--wire`, the installer copies the hook but leaves `settings.json`
untouched and prints the exact entry to merge. Re-running `--wire` is
idempotent. `--force` replaces an existing hook only when requested.

The receipt hook reads the org-rule-guard denial log if that guard is installed,
but does not require it. The two hooks may be installed independently.
