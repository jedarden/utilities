#!/usr/bin/env python3
"""Write one redacted TWILL friction receipt when a Claude session ends.

This file is intentionally a runtime leaf. It reads the session transcript
and the optional org-rule-guard denial log, but never imports another utility.
Receipt generation is best effort and this hook always exits successfully.

Receipts use ``twill-friction-receipt/v1`` and live under
``${XDG_STATE_HOME:-$HOME/.local/state}/twill/friction-receipts``. Raw
transcript records are never copied into a receipt.
"""

import errno
import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone


SCHEMA = "twill-friction-receipt/v1"
RECEIPTS_DIR_ENV = "TWILL_RECEIPTS_DIR"
MAX_RECEIPT_BYTES = 64 * 1024
MAX_TEXT = 240
MAX_SAFE_TEXT = 128
MAX_SESSION_ID = 128
MAX_REASON = 128
MAX_TIMESTAMP = 32
MAX_CWD = 160
MAX_DENIAL_TIMESTAMP = 32
MAX_DENIAL_FIELD = 128
MAX_ERROR_SIGNATURE = 240
MAX_ITEMS = 64
MAX_DENIALS = 128
RECEIPT_LOCK_TIMEOUT = 5.0
RECEIPT_LOCK_POLL = 0.01
RECEIPT_FIELD_CONTRACT = (
    ("schema", "string", "SCHEMA"),
    ("session_id", "string", "MAX_SESSION_ID"),
    ("ended_at", "string", "MAX_TIMESTAMP"),
    ("reason", "string", "MAX_REASON"),
    ("cwd", "string", "MAX_CWD"),
    ("rules_consulted", "array<string>", "MAX_ITEMS"),
    ("denials", "array<object>", "MAX_DENIALS"),
    ("unresolved_errors", "array<object>", "MAX_ITEMS"),
    ("ended_mid_task", "boolean", "none"),
)
RECEIPT_NESTED_CONTRACT = (
    ("denials", ("ts", "rule_id", "tool"),
     ("MAX_DENIAL_TIMESTAMP", "MAX_DENIAL_FIELD", "MAX_DENIAL_FIELD")),
    ("unresolved_errors", ("kind", "signature"),
     ("none", "MAX_ERROR_SIGNATURE")),
)
_RECEIPT_KEYS = tuple(field for field, _kind, _bound in RECEIPT_FIELD_CONTRACT)

_REDACTION_PATTERNS = (
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    ("GitHub fine-grained PAT", r"\bgithub_pat_[A-Za-z0-9_]{40,}"),
    ("AWS access key id", r"\bAKIA[0-9A-Z]{16}\b"),
    ("Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{20,}"),
    ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{30,}"),
    ("Bearer token", r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    (
        "PEM private key",
        r"-{5}BEGIN (?:[A-Z]+ )?PRIVATE KEY-{5}.*?-{5}END "
        r"(?:[A-Z]+ )?PRIVATE KEY-{5}",
    ),
)
REDACTION_STEPS = (
    ("credential-shaped matches", "_SECRET_PATTERNS"),
    ("whitespace normalization", "_redact"),
    ("field length bound", "_redact"),
    ("safe identifier filtering", "_safe"),
)

_SECRET_PATTERNS = tuple(
    re.compile(pattern, re.S if "PRIVATE KEY" in pattern else 0)
    for _label, pattern in _REDACTION_PATTERNS
)
_RULE_FILE = re.compile(r"(?:^|/)(CLAUDE\.md|AGENTS\.md|MEMORY\.md)$", re.I)
_SKILL_FILE = re.compile(r"(?:^|/)(?:\.claude/)?skills/([^/]+)/", re.I)
_RULE_NAMES = {"claude.md": "CLAUDE.md", "agents.md": "AGENTS.md", "memory.md": "MEMORY.md"}


def _redact(value, limit=MAX_TEXT):
    text = "" if value is None else str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return " ".join(text.split())[:limit]


def _safe(value, limit=MAX_SAFE_TEXT):
    text = _redact(value, limit)
    return re.sub(r"[^A-Za-z0-9_.:/-]", "_", text).strip("._")[:limit]


def _utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _xdg_state_home():
    return os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state"
    )


def receipts_dir():
    return os.environ.get(RECEIPTS_DIR_ENV) or os.path.join(
        _xdg_state_home(), "twill", "friction-receipts"
    )


def _denials_dir():
    override = os.environ.get("ORG_RULE_GUARD_STATE_DIR")
    return override or os.path.join(_xdg_state_home(), "org-rule-guard")


def _receipt_path(directory, session_id, input_data):
    safe = re.sub(r"[^A-Za-z0-9_.:-]", "_", _safe(session_id, 96)).strip("._")
    if safe:
        return os.path.join(directory, safe + ".json")
    seed = "|".join(
        _redact(input_data.get(key), MAX_TEXT)
        for key in ("cwd", "transcript_path", "reason")
    )
    return os.path.join(
        directory, "unknown-" + hashlib.sha256(seed.encode()).hexdigest()[:16] + ".json"
    )


def _rule_consulted(path):
    if not isinstance(path, str):
        return None
    match = _RULE_FILE.search(path)
    if match:
        return _RULE_NAMES[match.group(1).lower()]
    match = _SKILL_FILE.search(path)
    if match:
        return "skills/" + _safe(match.group(1))
    return None


def _transcript_summary(path):
    consulted = set()
    unresolved = []
    pending = {}
    if not isinstance(path, str) or not path:
        return consulted, unresolved, False
    try:
        handle = open(path, "r", encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return consulted, unresolved, False
    try:
        for line in handle:
            if not line.endswith("\n"):
                break
            try:
                record = json.loads(line)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(record, dict):
                continue
            message = record.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            for block in content if isinstance(content, list) else []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use":
                    tool_input = block.get("input")
                    tool_input = tool_input if isinstance(tool_input, dict) else {}
                    rule = _rule_consulted(
                        tool_input.get("file_path") or tool_input.get("notebook_path")
                    )
                    if rule:
                        consulted.add(rule)
                    if block.get("name") == "Bash" and isinstance(block.get("id"), str):
                        pending[block["id"]] = _redact(
                            tool_input.get("command"), MAX_ERROR_SIGNATURE
                        )
                elif block.get("type") == "tool_result":
                    command = pending.pop(block.get("tool_use_id"), None)
                    if block.get("is_error") is True:
                        result = block.get("content")
                        if isinstance(result, list):
                            result = " ".join(
                                item.get("text", "")
                                for item in result
                                if isinstance(item, dict)
                            )
                        unresolved.append({
                            "signature": _redact(
                                result or command or "tool error", MAX_ERROR_SIGNATURE
                            ),
                            "kind": "tool_error",
                        })
    finally:
        handle.close()
    for command in pending.values():
        unresolved.append({
            "signature": _redact(command or "unresolved command", MAX_ERROR_SIGNATURE),
            "kind": "unresolved_run",
        })
    unique = []
    seen = set()
    for item in unresolved:
        key = (item["kind"], item["signature"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return consulted, unique[:MAX_ITEMS], bool(pending)


def _read_denials(session_id):
    records = []
    for name in ("denials.jsonl", "denials.jsonl.1"):
        path = os.path.join(_denials_dir(), name)
        try:
            handle = open(path, "r", encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            for line in handle:
                try:
                    record = json.loads(line)
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if not isinstance(record, dict) or record.get("session_id") != session_id:
                    continue
                records.append({
                    "ts": _redact(record.get("ts"), MAX_DENIAL_TIMESTAMP),
                    "rule_id": _safe(record.get("rule_id"), MAX_DENIAL_FIELD),
                    "tool": _safe(record.get("tool"), MAX_DENIAL_FIELD),
                })
        finally:
            handle.close()
    return records[-MAX_DENIALS:]


def build_receipt(input_data):
    session_id = _safe(input_data.get("session_id"), MAX_SESSION_ID)
    consulted, unresolved, pending = _transcript_summary(input_data.get("transcript_path"))
    return {
        "schema": SCHEMA,
        "session_id": session_id or "unknown",
        "ended_at": _utcnow(),
        "reason": _safe(input_data.get("reason") or "other", MAX_REASON) or "other",
        "cwd": _redact(input_data.get("cwd"), MAX_CWD),
        "rules_consulted": sorted(consulted)[:MAX_ITEMS],
        "denials": _read_denials(input_data.get("session_id")),
        "unresolved_errors": unresolved,
        "ended_mid_task": pending,
    }


def _dump_receipt(receipt):
    return (
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _minimal_receipt(receipt):
    """Return a valid, small receipt if an otherwise valid record is oversized."""
    return {
        "schema": SCHEMA,
        "session_id": _safe(receipt.get("session_id"), MAX_SESSION_ID) or "unknown",
        "ended_at": _redact(receipt.get("ended_at"), MAX_TIMESTAMP),
        "reason": _safe(receipt.get("reason"), MAX_REASON) or "other",
        "cwd": _redact(receipt.get("cwd"), MAX_CWD),
        "rules_consulted": [],
        "denials": [],
        "unresolved_errors": [],
        "ended_mid_task": bool(receipt.get("ended_mid_task")),
    }


def _serialize_receipt(receipt):
    """Serialize a receipt without ever emitting more than the byte limit."""
    payload = {key: receipt.get(key) for key in _RECEIPT_KEYS}
    for key in ("rules_consulted", "denials", "unresolved_errors"):
        if not isinstance(payload[key], list):
            payload[key] = []
    encoded = _dump_receipt(payload)
    if len(encoded) <= MAX_RECEIPT_BYTES:
        return encoded

    # Keep a complete prefix of each collection while it fits. The
    # normal build_receipt bounds fit comfortably, but this also protects the
    # storage boundary if this function is called with an oversized record.
    while len(encoded) > MAX_RECEIPT_BYTES:
        collections = [
            key for key in ("unresolved_errors", "denials", "rules_consulted")
            if payload[key]
        ]
        if not collections:
            break
        largest = max(collections, key=lambda key: len(payload[key]))
        payload[largest].pop()
        encoded = _dump_receipt(payload)

    if len(encoded) <= MAX_RECEIPT_BYTES:
        return encoded
    return _dump_receipt(_minimal_receipt(payload))


def _acquire_receipt_lock(directory):
    """Serialize complete receipt replacements within one store.

    The lock is advisory and process-scoped. A finite wait keeps a contended
    SessionEnd hook fail-open rather than allowing a store problem to hold up
    session exit indefinitely.
    """
    path = os.path.join(directory, ".receipts.lock")
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.fchmod(fd, 0o600)
        deadline = time.monotonic() + RECEIPT_LOCK_TIMEOUT
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except OSError as error:
                if error.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("receipt store lock timeout") from error
                time.sleep(min(RECEIPT_LOCK_POLL, remaining))
    except Exception:
        os.close(fd)
        raise


def write_receipt(receipt, input_data=None):
    directory = receipts_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    destination = _receipt_path(directory, receipt.get("session_id"), input_data or receipt)
    lock_fd = _acquire_receipt_lock(directory)
    fd = None
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".receipt.", suffix=".tmp", dir=directory)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(_serialize_receipt(receipt))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            if temporary is not None:
                os.unlink(temporary)
        except FileNotFoundError:
            pass
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def main():
    try:
        input_data = json.loads(sys.stdin.read())
        if isinstance(input_data, dict):
            write_receipt(build_receipt(input_data), input_data)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
