#!/usr/bin/env python3
"""credential-guard: a Claude Code PreToolUse hook that refuses to let a
credential VALUE become text the agent produced.

Secrets travel by reference. An agent may hold a token in a file descriptor,
an environment variable, or a mode-0600 file; it must never put the value
into a file it writes, an edit it makes, or a command line it runs. Those all
land in the session transcript (and in shell history and `ps`), which is
logged, cached, and impossible to recall.

This hook inspects the *input* of Write, Edit, MultiEdit, NotebookEdit and Bash calls and
denies any that carry a high-signal credential shape. It does NOT see tool
*output* -- an agent that prints a secret with `cat` has still leaked it. The
defense for that side is a habit, not a hook: check presence (`wc -c`,
`md5sum`, `-field=... | wc -c`), never print.

FAILS OPEN by design. Any unexpected input, parse failure, or internal error
exits 0 (allow). A blocked agent gets worked around; a fleet wedged by its own
guard is worse than one missed write. The rule binds the agent regardless of
whether this hook catches the slip.

Denied calls also append a property-only record to a local JSONL log. The
record identifies the credential rule, tool, and matched payload shape, never
the payload or the credential value. Logging is best-effort and never changes
the deny decision.

What passes:
  * documentation stand-ins -- a token whose body is one repeated character
    (`ghp_xxxxxxxx...`), or that sits next to `example`, `REPLACE`, `your`,
    `dummy`, `placeholder`, `redact`, `changeme`, `todo`, `xxxx`, `...`
  * any line carrying a `gitleaks:allow` marker (deliberate test fixtures)
  * prose that names a token *type* without a value ("rotate the ghp_ token")

Extra patterns: drop a JSON file at ~/.config/credential-guard/patterns.json
of the form  [{"label": "Acme API key", "pattern": "\\bacme_[A-Za-z0-9]{32}"}]
Each entry is compiled and appended; a malformed file is ignored (fail open).

Wire it in ~/.claude/settings.json (see ../examples/settings.json):
  "PreToolUse": [{"matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash",
                  "hooks": [{"type": "command",
                             "command": "python3 ~/.claude/hooks/credential-guard.py"}]}]
"""
import fcntl
import json
import os
import re
import sys
from datetime import datetime, timezone

ALLOW = 0
RULE_CREDENTIAL = "credential-value"
STATE_DIR_ENV = "CREDENTIAL_GUARD_STATE_DIR"
LOG_NAME = "denials.jsonl"
ROTATED_LOG_NAME = "denials.jsonl.1"
LOCK_NAME = "denials.jsonl.lock"
MAX_LOG_BYTES = 256 * 1024
MAX_LOG_FIELD_CHARS = 512

# The hook handles one payload per process. Keeping it here avoids threading
# payload data through the deny API while ensuring the log contains metadata
# from the same invocation that produced the decision.
_PAYLOAD = {}

SUPPORTED_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit", "Bash")

# High-signal shapes only. Every pattern has a vendor prefix AND a length floor
# at the real token width, so naming a token type in prose never trips it. A
# false deny blocks real work and this guard already fails open, so the bias is
# toward narrow. (label, pattern, context_window): the window is how far PAST
# the match to look for a placeholder marker. Self-contained tokens use 0 --
# scanning ahead would let a nearby "example" excuse a real token. A PEM header
# is inherently multi-line: its placeholder body sits on the following line, so
# it gets a window, otherwise every committed secret *template* is blocked.
BUILTIN_PATTERNS = (
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{30,}", 0),
    ("GitHub fine-grained PAT", r"\bgithub_pat_[A-Za-z0-9_]{40,}", 0),
    ("GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}", 0),
    ("npm token", r"\bnpm_[A-Za-z0-9]{36,}", 0),
    ("AWS access key id", r"\bAKIA[0-9A-Z]{16}\b", 0),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b", 0),
    ("Slack token", r"\bxox[baprse]-[A-Za-z0-9-]{20,}", 0),
    ("Stripe live key", r"\b[sr]k_live_[0-9a-zA-Z]{24,}", 0),
    ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{30,}", 0),
    ("OpenAI API key", r"\bsk-proj-[A-Za-z0-9_-]{40,}", 0),
    ("Vault/OpenBao token", r"\bhv[sbr]\.[A-Za-z0-9_-]{24,}", 0),
    ("PEM private key header", r"-{5}BEGIN (?:[A-Z]+ )?PRIVATE KEY-{5}", 200),
)
PLACEHOLDER = re.compile(
    r"replace|example|your|dummy|placeholder|redact|changeme|todo|xxxx|\.\.\.",
    re.I,
)
GITLEAKS_ALLOW_MARKER = "gitleaks:allow"
EXTRA_PATTERNS_FILE = os.path.join(
    os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
    "credential-guard", "patterns.json",
)


def load_patterns(extra_file=EXTRA_PATTERNS_FILE):
    pats = [(label, re.compile(rx), win) for label, rx, win in BUILTIN_PATTERNS]
    try:
        with open(extra_file, encoding="utf-8") as fh:
            for entry in json.load(fh):
                pats.append((
                    str(entry["label"]),
                    re.compile(entry["pattern"]),
                    int(entry.get("window", 0)),
                ))
    except Exception:
        pass  # missing or malformed extras never break the guard
    return tuple(pats)


def deny(reason, tool="", payload_shape="unknown"):
    try:
        log_denial(tool, payload_shape)
    except Exception:
        pass  # logging is observability only; never change enforcement
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))
    sys.exit(0)


def state_dir():
    """Where the credential denial log lives.

    ``CREDENTIAL_GUARD_STATE_DIR`` is a test/operator override. In normal use
    the XDG state directory keeps this log separate from org-rule-guard's log,
    which lets operators distinguish the two independent hook decisions.
    """
    override = os.environ.get(STATE_DIR_ENV)
    if override:
        return override
    root = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state")
    return os.path.join(root, "credential-guard")


def _log_value(value):
    """Keep metadata bounded without ever serializing tool input fields."""
    if not value:
        return ""
    return str(value)[:MAX_LOG_FIELD_CHARS]


def _utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log_denial(tool, payload_shape):
    """Append one property-only JSONL record under a rotation lock.

    This function deliberately receives only the fixed shape label, not the
    matched body. The active file and one rotated backup are bounded so a
    repeated denial cannot grow the operator's state directory without limit.
    """
    payload = _PAYLOAD if isinstance(_PAYLOAD, dict) else {}
    cwd = payload.get("cwd")
    if not cwd:
        try:
            cwd = os.getcwd()
        except OSError:
            cwd = ""
    record = {
        "ts": _utcnow(),
        "rule_id": RULE_CREDENTIAL,
        "tool": _log_value(tool),
        "cwd": _log_value(cwd),
        "session_id": _log_value(payload.get("session_id")),
        "payload_shape": payload_shape,
    }
    directory = state_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    line = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
    lock_path = os.path.join(directory, LOCK_NAME)
    lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        log_path = os.path.join(directory, LOG_NAME)
        rotated_path = os.path.join(directory, ROTATED_LOG_NAME)
        try:
            current_size = os.stat(log_path).st_size
        except FileNotFoundError:
            current_size = 0
        if current_size and current_size + len(line) > MAX_LOG_BYTES:
            os.replace(log_path, rotated_path)
            os.chmod(rotated_path, 0o600)
            _trim_log(rotated_path)
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.chmod(log_path, 0o600)
            written = os.write(fd, line)
            if written != len(line):
                raise OSError("short denial-log write")
        finally:
            os.close(fd)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _trim_log(path):
    """Keep at most MAX_LOG_BYTES of the newest complete records."""
    if os.stat(path).st_size <= MAX_LOG_BYTES:
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.lseek(fd, -MAX_LOG_BYTES, os.SEEK_END)
        data = os.read(fd, MAX_LOG_BYTES)
    finally:
        os.close(fd)
    first_newline = data.find(b"\n")
    data = data[first_newline + 1:] if first_newline >= 0 else b""
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
    try:
        if data:
            written = os.write(fd, data)
            if written != len(data):
                raise OSError("short denial-log trim write")
    finally:
        os.close(fd)


def is_placeholder(value, context=""):
    """True for documentation stand-ins: a placeholder word in or near the
    match, or a token whose body (after the vendor prefix) is one repeated
    character -- `ghp_` followed by forty x's is the real-world case."""
    if PLACEHOLDER.search(value) or (context and PLACEHOLDER.search(context)):
        return True
    body = re.sub(r"^(?:[A-Za-z_]+[-_.])+", "", value)   # strip every prefix segment: sk-ant-, github_pat_, hvs.
    return len(set(body)) <= 1


def find_credential(body, patterns=None):
    """Return (label, match) for the first non-placeholder credential in
    `body`, or None. Pure -- no I/O, no exit -- so it is unit-testable."""
    for label, pat, window in (patterns or load_patterns()):
        for m in pat.finditer(body or ""):
            ctx = body[m.end():m.end() + window] if window else ""
            if is_placeholder(m.group(0), ctx):
                continue
            start = body.rfind("\n", 0, m.start()) + 1
            end = body.find("\n", m.end())
            line = body[start:end if end != -1 else len(body)]
            if GITLEAKS_ALLOW_MARKER in line:
                continue
            return label, m.group(0)
    return None


def reason_for(label, where):
    return (
        f"This {where} contains what looks like a real {label}. Secrets travel "
        "BY REFERENCE, never by value: write the path in the secret store "
        "(e.g. secret/<env>/<app>/<key>) or the command that fetches it "
        "(e.g. `gh auth token`), never the credential itself. To show a "
        "credential works, record the RESULT of the check, not the credential. "
        "To move a value, use a pipe, an @file, or a `key=-` stdin field so it "
        "never appears in argv. Deliberate test fixture? Add a gitleaks:allow "
        "comment to that line."
    )


def bodies_from(tool, tool_input):
    """Every text field a tool call could carry a value in."""
    if tool not in SUPPORTED_TOOLS:
        return []
    if tool == "Bash":
        return [("command", tool_input.get("command") or "")]
    path_key = "notebook_path" if tool == "NotebookEdit" else "file_path"
    path = tool_input.get(path_key) or "file"
    if tool == "NotebookEdit":
        source = tool_input.get("new_source")
        return [(f"new_source for {path}", source)] if isinstance(source, str) and source else []
    out = []
    for key in ("content", "new_string", "new_source"):
        if tool_input.get(key):
            out.append((f"{key} for {path}", tool_input[key]))
    for edit in tool_input.get("edits") or []:      # MultiEdit
        if isinstance(edit, dict) and edit.get("new_string"):
            out.append((f"edit of {tool_input.get('file_path') or 'file'}", edit["new_string"]))
    return out


def payload_shape(tool, where):
    """Turn an internal match location into a value-free schema label."""
    if tool == "Bash":
        return "Bash.command"
    if where.startswith("edit of "):
        return f"{tool}.edits[].new_string"
    field = where.split(" for ", 1)[0]
    return f"{tool}.{field}"


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return ALLOW
    if not isinstance(payload, dict):
        return ALLOW
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return ALLOW
    tool = payload.get("tool_name") or ""
    if tool not in SUPPORTED_TOOLS:
        return ALLOW
    global _PAYLOAD
    _PAYLOAD = payload
    try:
        patterns = load_patterns()
        for where, body in bodies_from(tool, tool_input):
            hit = find_credential(body, patterns)
            if hit:
                deny(reason_for(hit[0], where), tool, payload_shape(tool, where))
    except SystemExit:
        raise
    except Exception:
        return ALLOW
    return ALLOW


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        sys.exit(0)
