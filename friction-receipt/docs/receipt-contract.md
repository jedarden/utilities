# TWILL friction receipt contract

This document is the payload contract for the `friction-receipt` producer. It
is the companion to [`hooks/friction-receipt.py`](../hooks/friction-receipt.py)
and is normative for the bytes that hook emits. The hook's code-valued field,
nested-record, redaction-pattern, and redaction-step inventories are checked by
the hook unittest suite; update this document in the same change as an
intentional contract change.

The receipt is an optional, derived summary. It is not a transcript archive,
an audit log, or a guarantee that all private or sensitive context has been
removed. The storage directory's permissions, atomic-write behavior, and
retention lifecycle are described in the utility README; this document defines
the payload and its consumer compatibility.

## Producer and consumer

The producer is the Claude Code `SessionEnd` hook shipped in this utility. It
emits exactly the schema identifier `twill-friction-receipt/v1`.

The supported TWILL consumer is the v1 reader in TWILL's
`twill_receipts.py`: `read_receipt()` parses one file and `iter_receipts()`
enumerates valid `*.json` files. Compatibility is keyed by the literal schema
identifier, not by TWILL's corpus/database schema. The current TWILL checkout
does not publish an independent release/version constant for this reader, so
there is no TWILL release number to substitute for `twill-friction-receipt/v1`.
If the shape changes incompatibly, the producer and reader must move to a new
receipt schema identifier together.

The reader is deliberately strict: it requires the exact top-level field set,
rejects duplicate JSON keys, rejects unknown schemas and extra fields, checks
the nested object shapes and collection bounds, and skips malformed or
secret-bearing files when iterating. Its secret check is defense in depth; the
producer's redaction inventory below is the producer guarantee.

## Store locator

With no override, the producer writes one `<session_id>.json` under:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/twill/friction-receipts/
```

`TWILL_RECEIPTS_DIR` replaces that directory when it is set. This variable is
an explicit producer/test override, not a setting that the current TWILL reader
looks up. A consumer must therefore either resolve the default expression with
the same `HOME` and `XDG_STATE_HOME`, or pass the explicit override directory
to `iter_receipts(Path(...))`. `TWILL_STATE_DIR` and the TWILL SQLite state
directory are not receipt-directory overrides. A missing directory simply has
no live receipts.

## Top-level schema

Every emitted JSON object has exactly these fields. The final column is a
code-valued bound or fixed-value symbol from the hook; `none` means the field
has no length/list bound beyond its JSON type.

| Field | JSON type | Bound or fixed value |
|---|---|---|
| `schema` | `string` | `SCHEMA` |
| `session_id` | `string` | `MAX_SESSION_ID` |
| `ended_at` | `string` | `MAX_TIMESTAMP` |
| `reason` | `string` | `MAX_REASON` |
| `cwd` | `string` | `MAX_CWD` |
| `rules_consulted` | `array<string>` | `MAX_ITEMS` |
| `denials` | `array<object>` | `MAX_DENIALS` |
| `unresolved_errors` | `array<object>` | `MAX_ITEMS` |
| `ended_mid_task` | `boolean` | `none` |

The scalar bounds are maximum characters after the producer's normalization
step. Collection bounds are maximum entries before the serialized-byte bound
is applied. A receipt may contain fewer collection entries because the source
had fewer facts or because byte bounding removed entries; there is no separate
truncation marker.

### Field provenance and allowed facts

| Field | Producer input and meaning |
|---|---|
| `schema` | Fixed `SCHEMA`; currently `twill-friction-receipt/v1`. |
| `session_id` | `SessionEnd.session_id`, converted to safe identifier text. It is not hashed or treated as confidential. |
| `ended_at` | The hook's current UTC write time, formatted as `YYYY-MM-DDTHH:MM:SSZ`; it is not copied from the transcript. |
| `reason` | `SessionEnd.reason`, or `other` when absent, converted to safe identifier text. |
| `cwd` | `SessionEnd.cwd`, with credential redaction, whitespace normalization, and a character bound. It is not path-anonymized. |
| `rules_consulted` | Derived names only: `CLAUDE.md`, `AGENTS.md`, `MEMORY.md`, or `skills/<safe-name>` when a transcript tool input names a matching rule or skill path. The original path and tool input are not emitted. |
| `denials` | Matching records for the raw SessionEnd session id from `denials.jsonl` and `denials.jsonl.1` in the optional org-rule-guard state directory. Only `ts`, `rule_id`, and `tool` are copied; matched fragments, cwd, and other log fields are ignored. |
| `unresolved_errors` | A bounded, deduplicated signature for an errored transcript tool result (`kind: tool_error`) or a Bash tool use with no matching result at end of transcript (`kind: unresolved_run`). The signature is result content, or the Bash command when no result exists. |
| `ended_mid_task` | `true` exactly when at least one Bash tool use remains unmatched at end of the readable transcript; otherwise `false`. |

The hook reads transcript records only to derive the two rule/error summaries.
It never copies a raw record, user text block, tool input object, transcript
path, arbitrary file path, or successful tool command into a receipt. A path in
the SessionEnd `cwd` can survive because `cwd` is an explicit field. A Bash
command can survive only as the bounded `signature` of an unresolved or errored
run. A transcript `file_path` or `notebook_path` can contribute only the
allowlisted rule or skill name described above.

The nested records are also exact contracts:

| Collection | Object keys | Per-key bounds |
|---|---|---|
| `denials` | `ts`, `rule_id`, `tool` | `MAX_DENIAL_TIMESTAMP`, `MAX_DENIAL_FIELD`, `MAX_DENIAL_FIELD` |
| `unresolved_errors` | `kind`, `signature` | `none`, `MAX_ERROR_SIGNATURE` |

## Redaction and safe-text rules

Redaction is applied before normalization and truncation. The producer replaces
each match of these credential-shaped patterns with the literal `[redacted]`:

| Label | Python `re` pattern |
|---|---|
| GitHub token | `\bgh[pousr]_[A-Za-z0-9]{30,}` |
| GitHub fine-grained PAT | `\bgithub_pat_[A-Za-z0-9_]{40,}` |
| AWS access key id | `\bAKIA[0-9A-Z]{16}\b` |
| Slack token | `\bxox[baprs]-[A-Za-z0-9-]{20,}` |
| Anthropic API key | `\bsk-ant-[A-Za-z0-9_-]{30,}` |
| Bearer token | `(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}` |
| PEM private key | `-{5}BEGIN (?:[A-Z]+ )?PRIVATE KEY-{5}.*?-{5}END (?:[A-Z]+ )?PRIVATE KEY-{5}` |

The executable steps are:

| Step | Hook symbol | Effect |
|---|---|---|
| credential-shaped matches | `_SECRET_PATTERNS` | Replace matching spans with `[redacted]`; the PEM pattern may span lines. |
| whitespace normalization | `_redact` | Convert all whitespace runs to one space. |
| field length bound | `_redact` | Slice the normalized value at the requested field limit. |
| safe identifier filtering | `_safe` | After `_redact`, replace every character outside `[A-Za-z0-9_.:/-]` with `_`, strip leading/trailing `.` and `_`, and apply the identifier limit. |

This is a shape redactor, not a general privacy filter. It does not promise to
remove arbitrary secrets, source code, business data, paths, commands, or
identifiers that do not match one of the listed patterns. In particular,
`cwd` remains path-like text and error signatures remain diagnostic text. The
consumer's strict secret check may reject additional malformed records, but a
consumer rejection is not evidence that the producer's pattern inventory has
expanded.

## Bounding and compatibility rules

Normal construction applies the scalar and collection bounds above. Serialization
then keeps the complete top-level schema and removes entries from the largest
optional collection until the UTF-8 JSON object, including its trailing newline,
is at most `MAX_RECEIPT_BYTES` (`64 KiB` by default). If even the scalar shape
cannot fit, the hook writes a minimal valid v1 object with empty collections;
`ended_mid_task` is retained. Bounding never changes the schema identifier or
introduces an unrecognized field, and it never makes a partial JSON document.

The v1 TWILL reader expects the exact fields and nested keys above. It accepts
only `twill-friction-receipt/v1`; a future incompatible producer must publish a
new schema identifier rather than relying on a consumer to ignore added or
removed fields. A compatible v1 change must preserve the exact field set,
types, nested keys, and stated bounds.

## Maintenance rule

When changing the hook's output shape, source facts, bounds, redaction patterns,
or redaction order:

1. change the hook and this document together;
2. update the documentation-drift tests in
   `hooks/test_friction_receipt.py` and any behavioral fixtures;
3. update TWILL's `twill_receipts.py` and its fixture tests before changing the
   schema identifier or relying on a new field; and
4. run the friction-receipt hook suite and the repository definition-of-done
   checks.

The separate TWILL checkout owns its reader implementation. This utility owns
the producer bytes and must not import the TWILL checkout at runtime.
