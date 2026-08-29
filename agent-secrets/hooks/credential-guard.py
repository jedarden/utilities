#!/usr/bin/env python3
"""credential-guard: a Claude Code PreToolUse hook that refuses to let a
credential VALUE become text the agent produced.

Secrets travel by reference. An agent may hold a token in a file descriptor,
an environment variable, or a mode-0600 file; it must never put the value
into a file it writes, an edit it makes, or a command line it runs. Those all
land in the session transcript (and in shell history and `ps`), which is
logged, cached, and impossible to recall.

This hook inspects the *input* of Write, Edit, MultiEdit and Bash calls and
denies any that carry a high-signal credential shape. It does NOT see tool
*output* -- an agent that prints a secret with `cat` has still leaked it. The
defense for that side is a habit, not a hook: check presence (`wc -c`,
`md5sum`, `-field=... | wc -c`), never print.

FAILS OPEN by design. Any unexpected input, parse failure, or internal error
exits 0 (allow). A blocked agent gets worked around; a fleet wedged by its own
guard is worse than one missed write. The rule binds the agent regardless of
whether this hook catches the slip.

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
  "PreToolUse": [{"matcher": "Write|Edit|MultiEdit|Bash",
                  "hooks": [{"type": "command",
                             "command": "python3 ~/.claude/hooks/credential-guard.py"}]}]
"""
import json
import os
import re
import sys

ALLOW = 0

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


def deny(reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))
    sys.exit(0)


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
            if "gitleaks:allow" in line:
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
    if tool == "Bash":
        return [("command", tool_input.get("command") or "")]
    out = []
    for key in ("content", "new_string", "new_source"):
        if tool_input.get(key):
            out.append((f"{key} for {tool_input.get('file_path') or 'file'}", tool_input[key]))
    for edit in tool_input.get("edits") or []:      # MultiEdit
        if isinstance(edit, dict) and edit.get("new_string"):
            out.append((f"edit of {tool_input.get('file_path') or 'file'}", edit["new_string"]))
    return out


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
    try:
        patterns = load_patterns()
        for where, body in bodies_from(tool, tool_input):
            hit = find_credential(body, patterns)
            if hit:
                deny(reason_for(hit[0], where))
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
