#!/usr/bin/env python3
"""Write one redacted TWILL friction receipt when a Claude session ends.

This file is intentionally a runtime leaf. It reads the session transcript
and the optional org-rule-guard denial log, but never imports another utility.
Receipt generation is best effort and this hook always exits successfully.

Receipts use ``twill-friction-receipt/v1`` and live under
``${XDG_STATE_HOME:-$HOME/.local/state}/twill/friction-receipts``. Raw
transcript records are never copied into a receipt.
"""

import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone


SCHEMA = "twill-friction-receipt/v1"
RECEIPTS_DIR_ENV = "TWILL_RECEIPTS_DIR"
MAX_TEXT = 240
MAX_ITEMS = 64
MAX_DENIALS = 128

_SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{30,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    re.compile(
        r"-{5}BEGIN (?:[A-Z]+ )?PRIVATE KEY-{5}.*?-{5}END "
        r"(?:[A-Z]+ )?PRIVATE KEY-{5}",
        re.S,
    ),
)
_RULE_FILE = re.compile(r"(?:^|/)(CLAUDE\.md|AGENTS\.md|MEMORY\.md)$", re.I)
_SKILL_FILE = re.compile(r"(?:^|/)(?:\.claude/)?skills/([^/]+)/", re.I)
_RULE_NAMES = {"claude.md": "CLAUDE.md", "agents.md": "AGENTS.md", "memory.md": "MEMORY.md"}


def _redact(value, limit=MAX_TEXT):
    text = "" if value is None else str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return " ".join(text.split())[:limit]


def _safe(value, limit=128):
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
        _redact(input_data.get(key), 240)
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
                        pending[block["id"]] = _redact(tool_input.get("command"))
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
                            "signature": _redact(result or command or "tool error"),
                            "kind": "tool_error",
                        })
    finally:
        handle.close()
    for command in pending.values():
        unresolved.append({
            "signature": _redact(command or "unresolved command"),
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
                    "ts": _redact(record.get("ts"), 32),
                    "rule_id": _safe(record.get("rule_id")),
                    "tool": _safe(record.get("tool")),
                })
        finally:
            handle.close()
    return records[-MAX_DENIALS:]


def build_receipt(input_data):
    session_id = _safe(input_data.get("session_id"))
    consulted, unresolved, pending = _transcript_summary(input_data.get("transcript_path"))
    return {
        "schema": SCHEMA,
        "session_id": session_id or "unknown",
        "ended_at": _utcnow(),
        "reason": _safe(input_data.get("reason") or "other") or "other",
        "cwd": _redact(input_data.get("cwd"), 160),
        "rules_consulted": sorted(consulted)[:MAX_ITEMS],
        "denials": _read_denials(input_data.get("session_id")),
        "unresolved_errors": unresolved,
        "ended_mid_task": pending,
    }


def write_receipt(receipt, input_data=None):
    directory = receipts_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    fd, temporary = tempfile.mkstemp(prefix=".receipt.", suffix=".tmp", dir=directory)
    destination = _receipt_path(directory, receipt.get("session_id"), input_data or receipt)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            json.dump(receipt, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


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
