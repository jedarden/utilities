#!/usr/bin/env python3
"""PreToolUse guard: blocks file-write and Bash calls that violate hard org rules.

FAILS OPEN by design. Any unexpected input, parse failure, or internal error
exits 0 (allow). A NEEDLE fleet must never be wedged by this hook — a missed
violation is recoverable, a stuck fleet is not.

Write/Edit/MultiEdit/NotebookEdit rules:
  1. no .github/workflows/*            (GitHub Actions are disabled org-wide)
  2. no `kind: Job` / `kind: CronJob`  (ArgoCD cannot prune their pods)
  3. no `image: ...:latest`            (breaks rollback)
  5. no credential VALUES in any file  (secrets travel by reference)
Rules 2-3 apply only to .yaml/.yml and only to real manifest lines, never
comments — so docs that *describe* the prohibitions are not blocked.
Rule 5 applies to EVERY file type: the leak it exists to stop was a live
GitHub OAuth token pasted into a .md notes file by a fleet worker, caught
only by Forgejo's pre-receive hook at push time. Placeholders (all-one-char
bodies, "example"/"REPLACE"/etc.) and lines marked `gitleaks:allow` pass.

Bash rules:
  4. no mutating `kubectl` verbs. Desired state changes go through
     declarative-config + ArgoCD. Read-only verbs and `exec`/`cp`/`logs` stay
     allowed, as does submitting an Argo Workflow to the argo-workflows
     namespace (the sanctioned manual-CI path).
  5. no credential VALUES in commands (same rule 5 as Write/Edit). Catches
     `echo "ghp_..." > file`, `curl -H "Authorization: ghp_..."`, etc.
  6. no blanket `git add` (`-A`, `.`, or `--all`), no `git commit -a`/`--all`,
     no bare `git commit -m` with no pathspec. Both blanket staging and these
     commit forms can silently sweep in another worker's unrelated staged
     files in a checkout shared by concurrent NEEDLE workers (confirmed live
     2026-08-14, commitgraph).
     Stopgap ahead of irreversible-command-gate's own `commit-without-
     pathspec` rule (bead irrevers-57af0680) — replace this rule with that
     project's `git` pack once it ships (~/irreversible-command-gate).

Denial log: every deny appends one JSON line to
  ${XDG_STATE_HOME:-~/.local/state}/org-rule-guard/denials.jsonl
recording which rule fired, where, and a redacted fragment of what matched.
The active file is capped at 256 KiB; when the next record would cross that
limit it is rotated to `denials.jsonl.1`, replacing the previous backup.
An advisory lock in the same directory serializes rotation and append across
concurrent hook processes. The active file, one backup, and lock file are
owned by the user running the hook and kept mode 600 in a mode 700 directory.
The enforcement layer previously had exactly one output path — the deny JSON
on stdout — so nothing could say which rule agents keep hitting, in which
repo, how often, and the CLAUDE.md prose could not be tuned against evidence.
Logging is strictly best-effort: a log that cannot be written must never
change the decision, so every failure in that path is swallowed.
"""
import fcntl
import json
import os
import re
import shlex
import sys
from datetime import datetime, timezone

ALLOW = 0

# Stable slugs for the denial log. One per deny site, not one per numbered
# rule: rule 6 has two distinct failure modes (`-a`/`--all` vs. no pathspec)
# with different prose fixes, so they log separately.
RULE_GITHUB_ACTIONS = "github-actions-workflow"
RULE_JOB_CRONJOB = "k8s-job-cronjob"
RULE_LATEST_TAG = "latest-image-tag"
RULE_MUTATING_KUBECTL = "mutating-kubectl"
RULE_CREDENTIAL = "credential-value"
RULE_GIT_ADD_ALL = "git-add-all"
RULE_COMMIT_ALL = "git-commit-all"
RULE_COMMIT_NO_PATHSPEC = "git-commit-no-pathspec"
RULE_IDS = (
    RULE_GITHUB_ACTIONS, RULE_JOB_CRONJOB, RULE_LATEST_TAG,
    RULE_MUTATING_KUBECTL, RULE_CREDENTIAL, RULE_COMMIT_ALL,
    RULE_COMMIT_NO_PATHSPEC, RULE_GIT_ADD_ALL,
)
SUPPORTED_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit", "Bash")

# The hook input for this invocation, kept for the denial log (session_id,
# cwd, tool). A hook process handles exactly one tool call, so a module
# global is the whole of the state needed.
_PAYLOAD = {}


def deny(rule_id, reason, fragment=""):
    """Emit the deny decision. Logging happens first and can never preempt it:
    an unwritable log denies anyway, never allows."""
    try:
        log_denial(rule_id, fragment)
    except Exception:
        pass
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))
    sys.exit(0)


# --- denial log -------------------------------------------------------------

STATE_DIR_ENV = "ORG_RULE_GUARD_STATE_DIR"
LOG_NAME = "denials.jsonl"
ROTATED_LOG_NAME = "denials.jsonl.1"
LOCK_NAME = "denials.jsonl.lock"
MAX_LOG_BYTES = 256 * 1024
MAX_LOG_FIELD_CHARS = 512


def state_dir():
    """Where the denial log lives. ORG_RULE_GUARD_STATE_DIR overrides the
    XDG default — how a test or a fleet worker points the log somewhere
    without touching the operator's."""
    override = os.environ.get(STATE_DIR_ENV)
    if override:
        return override
    root = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state")
    return os.path.join(root, "org-rule-guard")


def _redact(text):
    """Strip credential shapes from a log fragment and flatten whitespace.

    The credential rule logs its pattern name instead of the match; this is
    the belt to that brace, so a credential reaching the log through any
    *other* rule's fragment — a commit message, a kubectl line — is still not
    stored. Flattening keeps every record on one greppable line.
    """
    out = text or ""
    for _label, pat, _window in SECRET_PATTERNS:
        out = pat.sub("[redacted]", out)
    return " ".join(out.split())


def _log_value(value):
    """Keep metadata bounded so one malformed payload cannot defeat rotation."""
    if not value:
        return ""
    return str(value)[:MAX_LOG_FIELD_CHARS]


def log_denial(rule_id, fragment):
    """Append one bounded JSON line under the lifecycle lock.

    Best-effort by contract: `deny` wraps this in a bare except, so nothing
    here may raise its way into the decision. The lock covers both rotation
    and append; the write itself remains one O_APPEND write so every process
    using this hook contributes a complete record or no record.
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
        "rule_id": rule_id,
        "tool": _log_value(payload.get("tool_name")),
        "cwd": _log_value(cwd),
        "session_id": _log_value(payload.get("session_id")),
        "fragment": _redact(fragment)[:80],
    }
    directory = state_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)          # exist_ok does not fix an existing dir
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
            written = os.write(fd, line)  # single O_APPEND write: no interleaving
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
    """Keep at most MAX_LOG_BYTES from an oversized rotated log.

    Oversized files can predate this lifecycle policy or be supplied by an
    operator. Retaining the newest complete lines is preferable to preserving
    an unbounded history; if no complete line fits, the old backup is emptied.
    """
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


def _utcnow():
    """UTC ISO-8601 with a Z suffix, matching jq's `todate` output so log
    timestamps sort and compare as plain strings in a query."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# High-signal credential shapes only. Deliberately narrow: a false deny blocks
# real work, and this guard already fails open. Length floors are set at the
# real token widths so naming a token *type* in prose never trips it.
# (label, pattern, context_window). The window is how far PAST the match to look
# for a placeholder marker. Token patterns use 0 — the value is self-contained,
# and scanning ahead would let a nearby "example" excuse a real token. The PEM
# header is inherently multi-line: its placeholder body sits on the FOLLOWING
# line (this repo's own <app>-secret.yml.template convention puts a
# YOUR_..._HERE marker there), so without a window it blocks every committed
# secret template.
SECRET_PATTERNS = (
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), 0),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}"), 0),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}"), 0),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{30,}"), 0),
    ("PEM private key header", re.compile(r"-{5}BEGIN (?:[A-Z]+ )?PRIVATE KEY-{5}"), 200),
)
PLACEHOLDER = re.compile(
    r"replace|example|your|dummy|placeholder|redact|changeme|todo|xxxx|\.\.\.",
    re.I,
)

# kubectl verbs that change cluster state.
MUTATING = {
    "apply", "delete", "patch", "edit", "replace", "set", "annotate", "label",
    "scale", "autoscale", "cordon", "uncordon", "drain", "taint", "evict",
    "rollout",          # only `rollout restart|undo|pause|resume` mutate
    "create",           # conditionally allowed for Argo Workflow submission
}
ROLLOUT_SAFE = {"status", "history"}
# Split a shell line into command segments so `grep "kubectl delete"` is safe.
SEGMENT = re.compile(r"(?:\|\||&&|[;&|\n])")
ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# Rule 1 matches a path substring anywhere in the tool input, so it would also
# match the line of source that implements it — this file is written and
# edited through its own installed copy. Assembled from pieces for that reason
# alone; the compiled pattern is identical to the obvious literal.
WORKFLOWS_PATH = re.compile(r"(^|/)\.github/" + r"workflows/")

# `git commit` flags that consume the following token as a value, so it is
# never mistaken for a pathspec. Deliberately not exhaustive — a missed flag
# here just means a false negative (an unsafe commit narrowly slips
# through), never a false deny of a value that happens to look like a path,
# matching this hook's fail-open philosophy.
GIT_COMMIT_VALUE_FLAGS = {
    "-m", "--message", "-c", "-C", "--reuse-message", "--reedit-message",
    "-F", "--file", "--author", "--date", "--template", "--fixup", "--squash",
}
GIT_COMMIT_ALL_FLAGS = {"-a", "--all"}
GIT_ADD_ALL_FLAGS = {"-A", "--all"}
# `--amend` alone (no `-a`) is exempt from the pathspec requirement:
# amending the last commit with whatever is currently staged is a common,
# usually-intentional operation (fix a typo, add a forgotten file to the
# commit you just made) — a different risk profile from a brand-new commit
# silently absorbing whatever a sibling process staged. `-a`/`--all`
# combined with `--amend` still denies via the has_all branch below.
GIT_COMMIT_AMEND_FLAGS = {"--amend"}


def check_git_add(args):
    """Rule 6: blanket `git add` forms must name explicit paths instead.

    `git add -A`, `git add .`, and `git add --all` stage the entire working
    tree (or the entire current directory), which can pull another worker's
    unrelated files into the next commit in a shared checkout.
    """
    try:
        idx = args.index("add")
    except ValueError:
        return
    rest = args[idx + 1:]
    if not any(tok in GIT_ADD_ALL_FLAGS or tok == "." for tok in rest):
        return
    invocation = " ".join(rest)
    deny(
        RULE_GIT_ADD_ALL,
        "`git add -A`/`git add .`/`git add --all` stages the ENTIRE working "
        "tree, which can silently sweep in another worker's unrelated files. "
        "Pass explicit paths instead: `git add <paths>`. Stopgap ahead of "
        "irreversible-command-gate's own commit-without-pathspec rule "
        "(bead irrevers-57af0680) — see the Hard prohibitions section of "
        "~/CLAUDE.md.",
        invocation,
    )


def check_git_commit(args):
    """Rule 6: `git commit` must always name what it is committing.

    `-a`/`--all` and a bare `git commit -m "..."` both commit the ENTIRE
    currently-staged index, not just what this command's own `git add`
    staged. In a checkout shared by concurrent NEEDLE workers, that can
    silently sweep in another worker's uncommitted, unrelated staged files
    — confirmed live 2026-08-14 in commitgraph: a correctly-scoped
    `git add <2 files>` followed by a bare `git commit -m` produced a commit
    that also included ~430 unrelated lines from another worker's pre-staged
    files, caught only because that worker happened to check its own diff
    before pushing.

    `args` must already be shell-quote-aware tokens (shlex, not str.split)
    — a naive space split breaks on any quoted commit message containing a
    space, which is nearly every real one, and would silently defeat this
    check on exactly the case it exists to catch.
    """
    try:
        idx = args.index("commit")
    except ValueError:
        return
    rest = args[idx + 1:]
    invocation = " ".join(rest)
    has_all = False
    has_amend = False
    has_pathspec = False
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok in GIT_COMMIT_ALL_FLAGS:
            has_all = True
            i += 1
        elif tok in GIT_COMMIT_AMEND_FLAGS:
            has_amend = True
            i += 1
        elif tok == "--":
            has_pathspec = has_pathspec or (i + 1 < len(rest))
            break
        elif tok.startswith("--") and "=" in tok:
            i += 1  # combined --flag=value, no separate value token to skip
        elif tok in GIT_COMMIT_VALUE_FLAGS:
            i += 2  # skip the flag and its value
        elif tok.startswith("-"):
            i += 1  # unrecognized flag, assume boolean
        else:
            has_pathspec = True
            i += 1
    if has_all:
        deny(
            RULE_COMMIT_ALL,
            "`git commit -a`/`--all` commits the ENTIRE staged index, not just "
            "the files this agent intended. In a checkout shared by concurrent "
            "NEEDLE workers, that can silently sweep in another worker's "
            "unrelated staged files. Pass explicit paths instead: "
            "`git commit <paths> -m \"...\"`. Stopgap ahead of "
            "irreversible-command-gate's own commit-without-pathspec rule "
            "(bead irrevers-57af0680) — see the Hard prohibitions section of "
            "~/CLAUDE.md.",
            invocation,
        )
    if not has_pathspec and not has_amend:
        deny(
            RULE_COMMIT_NO_PATHSPEC,
            "Bare `git commit -m` with no pathspec commits the ENTIRE staged "
            "index, not just what this agent's own `git add` staged. In a "
            "checkout shared by concurrent NEEDLE workers, that can silently "
            "sweep in another worker's unrelated staged files (confirmed live "
            "2026-08-14 in commitgraph). Pass the same paths to `git commit` "
            "that you passed to `git add`: `git commit <paths> -m \"...\"`. "
            "Stopgap ahead of irreversible-command-gate's own "
            "commit-without-pathspec rule (bead irrevers-57af0680) — see the "
            "Hard prohibitions section of ~/CLAUDE.md.",
            invocation,
        )


def check_bash(cmd):
    # Rule 5 applies to Bash too: never write a credential VALUE, even in a command.
    # This catches things like `echo "ghp_..." > file` that Write/Edit checks miss.
    check_secrets("", cmd or "")

    for seg in SEGMENT.split(cmd or ""):
        toks = seg.strip().split()
        i = 0
        # skip sudo / env assignments / command wrappers
        while i < len(toks) and (toks[i] in ("sudo", "command", "exec", "time", "nohup")
                                 or ENV_ASSIGN.match(toks[i])):
            i += 1
        if i >= len(toks):
            continue
        exe = toks[i].rsplit("/", 1)[-1]
        if exe == "git":
            # Re-tokenize with shlex, not the naive str.split() used for toks
            # above: a quoted commit message containing a space (nearly
            # every real one) splits into multiple toks under plain
            # whitespace splitting, which defeats check_git_commit's
            # flag-value skipping on exactly the case rule 6 exists to
            # catch. Find the same git invocation by basename match rather
            # than reusing index i, since the two tokenizations can disagree
            # on where it falls once quoting is involved.
            # shlex has no notion of $(...) command substitution or heredocs
            # -- a bare `git commit -m "$(cat <<EOF ... EOF)"` parses "wrong"
            # (or raises) and slips through undetected. Accepted, matching
            # this hook's fail-open design: a missed violation here is the
            # same class of gap the kubectl check already has against
            # complex shell syntax, not a new one. A full shell-grammar
            # parser is disproportionate for a stopgap hook.
            try:
                shlex_toks = shlex.split(seg)
            except ValueError:
                continue  # unbalanced quotes etc. -- fail open on this segment
            gi = next((k for k, t in enumerate(shlex_toks)
                       if t.rsplit("/", 1)[-1] == "git"), None)
            if gi is not None:
                git_args = shlex_toks[gi + 1:]
                check_git_add(git_args)
                check_git_commit(git_args)
            continue
        if exe != "kubectl":
            continue
        args = [a for a in toks[i + 1:] if not a.startswith("-")]
        # first non-flag arg after kubectl is the verb; flags may carry values,
        # so also scan a couple of tokens for a known verb
        verb = next((a for a in args if a in MUTATING or a in
                     ("get", "describe", "logs", "exec", "cp", "top", "version",
                      "explain", "wait", "events", "auth", "api-resources",
                      "config", "port-forward", "diff")), None)
        if verb is None or verb not in MUTATING:
            continue
        if verb == "rollout" and any(a in ROLLOUT_SAFE for a in args):
            continue
        if verb == "create" and ("argo-workflows" in seg or "iad-ci" in seg):
            continue  # sanctioned manual Argo Workflow submission
        deny(
            RULE_MUTATING_KUBECTL,
            f"`kubectl {verb}` mutates cluster state, which is prohibited. "
            "ArgoCD selfHeal reverts live edits anyway, so they do not stick and "
            "they fight the controller. Change the manifest in "
            "jedarden/declarative-config, commit, push, and let ArgoCD sync. "
            "Read-only verbs (get/describe/logs/top) plus exec and cp are allowed, "
            "as is `kubectl create` of an Argo Workflow in the argo-workflows "
            "namespace. See the Hard prohibitions section of ~/CLAUDE.md.",
            seg.strip(),
        )


def _is_placeholder(value, context=""):
    """True for documentation stand-ins, so docs that show a credential's
    *shape* are not blocked. `ghp_` + 40 literal x's is the real-world case;
    `context` carries the following lines for multi-line shapes like PEM."""
    if PLACEHOLDER.search(value) or (context and PLACEHOLDER.search(context)):
        return True
    body = re.sub(r"^(?:[A-Za-z_]+[-_.])+", "", value)   # strip every prefix segment: sk-ant-, github_pat_, hvs.
    return len(set(body)) <= 1                     # all-one-character body


def check_secrets(path, body):
    """Rule 5: never write a credential VALUE. Applies to every file type --
    the real leak was a live GitHub OAuth token pasted into a .md notes file.
    The logged fragment is the pattern name, never the match: a credential
    that was blocked still must not end up on disk somewhere else."""
    for label, pat, window in SECRET_PATTERNS:
        for m in pat.finditer(body or ""):
            ctx = body[m.end():m.end() + window] if window else ""
            if _is_placeholder(m.group(0), ctx):
                continue
            start = body.rfind("\n", 0, m.start()) + 1
            end = body.find("\n", m.end())
            if "gitleaks:allow" in body[start:end if end != -1 else len(body)]:
                continue
            deny(
                RULE_CREDENTIAL,
                f"This write contains what looks like a real {label}. Secrets are "
                "handled BY REFERENCE, never by value: write the OpenBao path "
                "(secret/<cluster>/<app>/<key>) or the command that fetches it "
                "(e.g. `gh auth token`) instead of the credential itself. This "
                "applies to files, commits, beads, docs and logs alike. If you "
                "must show a credential works, record the RESULT of the check, "
                "not the credential. Deliberate test fixture? Append a "
                "gitleaks:allow comment to that line. See the Hard prohibitions "
                "section of ~/CLAUDE.md.",
                label,
            )


def check_write(path, body):
    if WORKFLOWS_PATH.search(path):
        deny(RULE_GITHUB_ACTIONS,
             "GitHub Actions are disabled org-wide and must never be re-enabled. "
             "All CI runs on Argo Workflows in the iad-ci cluster; templates live "
             "in declarative-config/k8s/iad-ci/argo-workflows/.",
             path)
    check_secrets(path, body)
    if not re.search(r"\.ya?ml$", path):
        return
    job = re.search(r"^[ \t]*kind:[ \t]*(Job|CronJob)[ \t]*$", body, re.M)
    if job:
        deny(RULE_JOB_CRONJOB,
             "kind: Job and kind: CronJob are banned. ArgoCD cannot manage them "
             "idempotently and their pods are not ArgoCD-owned, so they are never "
             "pruned and hold resource reservations indefinitely. Use a Deployment "
             "with an internal scheduling loop for recurring work, or an Argo "
             "WorkflowTemplate for one-shot work.",
             job.group(0))
    latest = re.search(r"^[ \t]*-?[ \t]*image:[ \t]*[^#\n]*:latest[ \t]*$", body, re.M)
    if latest:
        deny(RULE_LATEST_TAG,
             "The :latest image tag is banned — it silently changes what runs and "
             "makes rollback impossible. Pin a semver tag read from "
             "containers/<name>/VERSION.",
             latest.group(0))


def check_file_tool(tool, tool_input):
    """Inspect the file contents carried by a file-writing tool."""
    path_key = "notebook_path" if tool == "NotebookEdit" else "file_path"
    path = tool_input.get(path_key) or ""
    if not path:
        return
    if tool == "MultiEdit":
        edits = tool_input.get("edits") or []
        bodies = [
            edit.get("new_string")
            for edit in edits
            if isinstance(edit, dict) and isinstance(edit.get("new_string"), str)
        ]
        # Check once even when edits is empty so path-only rules still apply.
        check_write(path, "\n".join(bodies))
        return
    if tool == "NotebookEdit":
        check_write(path, tool_input.get("new_source") or "")
        return
    body = "\n".join(
        value for value in (tool_input.get("content"), tool_input.get("new_string"))
        if value
    )
    check_write(path, body)


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return ALLOW
    if not isinstance(payload, dict):
        return ALLOW
    _PAYLOAD.update(payload)
    tool = payload.get("tool_name") or ""
    if tool not in SUPPORTED_TOOLS:
        return ALLOW
    ti = payload.get("tool_input")
    if not isinstance(ti, dict):
        return ALLOW
    try:
        if tool == "Bash":
            check_bash(ti.get("command") or "")
        else:
            check_file_tool(tool, ti)
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
