#!/bin/sh
# install.sh -- install friction-receipt into the conventional user locations.
#
#   ./install.sh                copy the hook; never overwrite one already there
#   ./install.sh --force        overwrite an existing hook copy
#   ./install.sh --wire         install (overwriting) and merge/upgrade the
#                               SessionEnd entry into settings.json
#   ./install.sh --wire --force replace customized wiring fields too
#   ./install.sh --uninstall    remove the installed hook and unwire its exact
#                               SessionEnd settings entry
#
# Idempotent. Without --wire this script never touches settings.json, and it
# never overwrites a hook file it finds at the destination. Say --force (or
# --wire) to replace it deliberately. --uninstall refuses to remove a hook
# this checkout did not install unless --force is supplied, and unwires the
# settings entry before removing the hook.
set -eu
HERE=$(CDPATH=; cd "$(dirname "$0")" && pwd)
HOOK_DST="${CLAUDE_HOOKS_DIR:-$HOME/.claude/hooks}/friction-receipt.py"
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
force=0
wire=0
case " $* " in *" --force"*) force=1 ;; esac
case " $* " in *" --wire"*) wire=1 ;; esac

case "${1:-}" in
  -h|--help)
    sed -n '2,14p' "$0"
    exit 0
    ;;
  --uninstall)
    if [ -e "$HOOK_DST" ] && [ "$force" -ne 1 ] \
       && ! cmp -s "$HERE/hooks/friction-receipt.py" "$HOOK_DST"; then
      echo "install.sh: refusing to remove $HOOK_DST -- it is not this copy's output; pass --force" >&2
      exit 1
    fi
    python3 - "$SETTINGS" "$HOOK_DST" "$force" <<'PY'
import atexit
import errno
import fcntl
import json
import math
import os
import signal
import stat
import sys
import tempfile
import time

requested_path, hook, force = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
path = os.path.realpath(requested_path)
command = f"python3 {hook}"
hook_timeout = 10
lock_path = path + ".lock"
settings_dir = os.path.dirname(os.path.abspath(path))
lock_timeout = 30.0
raw_timeout = os.environ.get("CLAUDE_SETTINGS_LOCK_TIMEOUT")
if raw_timeout is not None:
    try:
        lock_timeout = float(raw_timeout)
    except ValueError:
        print("install.sh: refusing to uninstall: "
              "CLAUDE_SETTINGS_LOCK_TIMEOUT must be a positive number",
              file=sys.stderr)
        raise SystemExit(1)
    if not math.isfinite(lock_timeout) or lock_timeout <= 0:
        print("install.sh: refusing to uninstall: "
              "CLAUDE_SETTINGS_LOCK_TIMEOUT must be a positive number",
              file=sys.stderr)
        raise SystemExit(1)

if not os.path.isdir(settings_dir):
    print(f"unwired    {requested_path}: settings parent is absent")
    raise SystemExit(0)

try:
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    os.fchmod(lock_fd, 0o600)
except OSError as exc:
    if "lock_fd" in locals():
        os.close(lock_fd)
    print(f"install.sh: refusing to uninstall: could not create settings lock "
          f"{lock_path}: {exc}; installed files were not removed",
          file=sys.stderr)
    raise SystemExit(1)


def write_settings(settings, source_mode):
    fd, temporary = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.friction-receipt.",
        suffix=".tmp", dir=settings_dir
    )
    try:
        os.fchmod(fd, source_mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            json.dump(settings, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if fd is not None:
            os.close(fd)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def recognized(entry, handler):
    # v0.1.0 shipped the command without a timeout. That is the only legacy
    # shape eligible for in-place refresh; the current entry has timeout 10.
    return handler.get("timeout") == hook_timeout or "timeout" not in handler


try:
    deadline = time.monotonic() + lock_timeout
    while True:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                print(f"install.sh: refusing to uninstall: could not acquire "
                      f"settings lock {lock_path} within {lock_timeout:g} "
                      "seconds; installed files were not removed",
                      file=sys.stderr)
                raise SystemExit(1)
            time.sleep(min(0.05, remaining))

    if not os.path.exists(path):
        print(f"unwired    {requested_path}: settings file is absent")
    else:
        source_mode = stat.S_IMODE(os.stat(path).st_mode)
        try:
            with open(path, encoding="utf-8") as handle:
                settings = json.load(handle)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            print(f"install.sh: refusing to uninstall {requested_path}: "
                  f"invalid JSON ({exc}); installed files were not removed",
                  file=sys.stderr)
            raise SystemExit(1)
        if not isinstance(settings, dict):
            print(f"install.sh: refusing to uninstall {requested_path}: "
                  "top-level value must be a JSON object; installed files "
                  "were not removed", file=sys.stderr)
            raise SystemExit(1)

        hooks = settings.get("hooks", {})
        session_end = hooks.get("SessionEnd", []) if isinstance(hooks, dict) else None
        if session_end is None or not isinstance(session_end, list):
            print(f"install.sh: refusing to uninstall {requested_path}: "
                  "hooks.SessionEnd must be a JSON array; installed files "
                  "were not removed", file=sys.stderr)
            raise SystemExit(1)

        matching = []
        for entry in session_end:
            if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                continue
            for handler in entry["hooks"]:
                if isinstance(handler, dict) and handler.get("command") == command:
                    matching.append((entry, handler))

        customized = [(entry, handler) for entry, handler in matching
                      if not recognized(entry, handler)]
        if customized and not force:
            print(f"install.sh: preserved {requested_path}: existing {command} "
                  "wiring is customized; use --uninstall --force to remove "
                  "it (exit 2)", file=sys.stderr)
            raise SystemExit(2)

        if not matching:
            print(f"unwired    {requested_path}: no matching {command} entry")
        else:
            removed = 0
            new_session_end = []
            for entry in session_end:
                if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                    new_session_end.append(entry)
                    continue
                kept = []
                for handler in entry["hooks"]:
                    if (isinstance(handler, dict)
                            and handler.get("command") == command
                            and (force or recognized(entry, handler))):
                        removed += 1
                    else:
                        kept.append(handler)
                if kept:
                    if len(kept) != len(entry["hooks"]):
                        entry["hooks"] = kept
                    new_session_end.append(entry)
            hooks["SessionEnd"] = new_session_end
            write_settings(settings, source_mode)
            print(f"unwired    {requested_path}: removed {removed} {command} entry")
finally:
    try:
        os.unlink(lock_path)
    except FileNotFoundError:
        pass
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
PY
    rm -f "$HOOK_DST"
    echo "removed $HOOK_DST (provenance absent; settings.json and receipts left in place; settings lock removed if present)"
    exit 0
    ;;
esac

install -d -m 700 "$(dirname "$HOOK_DST")"
if [ -e "$HOOK_DST" ] && [ "$force" -ne 1 ] && [ "$wire" -ne 1 ]; then
  echo "exists     $HOOK_DST -- not overwritten"
else
  install -m 755 "$HERE/hooks/friction-receipt.py" "$HOOK_DST"
  echo "installed  $HOOK_DST"
fi

if [ "$wire" -ne 1 ]; then
  echo "Add to $SETTINGS (or re-run with --wire):"
  sed "s#~/.claude/hooks/friction-receipt.py#$HOOK_DST#" "$HERE/examples/settings.json"
  exit 0
fi

python3 - "$SETTINGS" "$HOOK_DST" "$force" <<'PY'
import atexit
import errno
import fcntl
import json
import math
import os
import signal
import shutil
import stat
import sys
import tempfile
import time

requested_path, hook, force = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
# Resolve aliases before taking the lock or replacing the file. In particular,
# os.replace() would otherwise replace a final-component symlink itself.
path = os.path.realpath(requested_path)
command = f"python3 {hook}"
hook_timeout = 10
lock_path = path + ".lock"
settings_dir = os.path.dirname(os.path.abspath(path))
settings_name = os.path.basename(path)
temp_prefix = f".{settings_name}.friction-receipt."
temp_path = None


def cleanup_temp():
    global temp_path
    if temp_path is None:
        return
    try:
        os.unlink(temp_path)
    except FileNotFoundError:
        pass
    finally:
        temp_path = None


def handle_interrupt(signum, _frame):
    cleanup_temp()
    raise SystemExit(128 + signum)


for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    signal.signal(signum, handle_interrupt)
atexit.register(cleanup_temp)

if not os.path.isdir(settings_dir):
    print(f"install.sh: refusing to wire {requested_path}: settings parent "
          f"directory does not exist: {settings_dir}", file=sys.stderr)
    raise SystemExit(1)

lock_timeout = 30.0
raw_timeout = os.environ.get("CLAUDE_SETTINGS_LOCK_TIMEOUT")
if raw_timeout is not None:
    try:
        lock_timeout = float(raw_timeout)
    except ValueError:
        print("install.sh: refusing to wire "
              f"{requested_path}: CLAUDE_SETTINGS_LOCK_TIMEOUT must be a "
              "positive number; settings file was not modified",
              file=sys.stderr)
        raise SystemExit(1)
    if not math.isfinite(lock_timeout) or lock_timeout <= 0:
        print("install.sh: refusing to wire "
              f"{requested_path}: CLAUDE_SETTINGS_LOCK_TIMEOUT must be a "
              "positive number; settings file was not modified",
              file=sys.stderr)
        raise SystemExit(1)


def acquire_settings_lock():
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        os.fchmod(fd, 0o600)
    except OSError as exc:
        if "fd" in locals():
            os.close(fd)
        print(f"install.sh: refusing to wire {requested_path}: could not "
              f"create settings lock {lock_path}: {exc}; settings file was "
              "not modified", file=sys.stderr)
        raise SystemExit(1)

    deadline = time.monotonic() + lock_timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                os.close(fd)
                print(f"install.sh: refusing to wire {requested_path}: could "
                      f"not acquire settings lock {lock_path}: {exc}; "
                      "settings file was not modified", file=sys.stderr)
                raise SystemExit(1)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                os.close(fd)
                print(f"install.sh: refusing to wire {requested_path}: could "
                      f"not acquire settings lock {lock_path} within "
                      f"{lock_timeout:g} seconds; settings file was not "
                      "modified", file=sys.stderr)
                raise SystemExit(1)
            time.sleep(min(0.05, remaining))


def snapshot_backup():
    backup = path + ".bak"
    if os.path.isfile(path) and not os.path.lexists(backup):
        source_mode = stat.S_IMODE(os.stat(path).st_mode)
        shutil.copyfile(path, backup)
        os.chmod(backup, source_mode)
        print(f"backup     {backup}")


def refuse_invalid_settings(reason):
    backup = path + ".bak"
    try:
        snapshot_backup()
    except OSError as exc:
        print(f"install.sh: refusing to wire {path}: {reason}; "
              f"could not create backup {backup}: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(f"install.sh: refusing to wire {path}: {reason}; "
          "settings file was not modified", file=sys.stderr)
    raise SystemExit(1)


def reap_stale_temps():
    for name in os.listdir(settings_dir):
        if not (name.startswith(temp_prefix) and name.endswith(".tmp")):
            continue
        try:
            os.unlink(os.path.join(settings_dir, name))
        except (FileNotFoundError, IsADirectoryError):
            pass


def write_settings(settings, source_mode):
    global temp_path
    fd, temp_path = tempfile.mkstemp(
        prefix=temp_prefix, suffix=".tmp", dir=settings_dir
    )
    try:
        os.fchmod(fd, source_mode if source_mode is not None else 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            json.dump(settings, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if fd is not None:
            os.close(fd)
        cleanup_temp()


def recognized(handler):
    # v0.1.0 shipped the command without a timeout. It is the only legacy
    # shape eligible for in-place refresh; the current entry has timeout 10.
    return handler.get("timeout") == hook_timeout or "timeout" not in handler


lock_fd = acquire_settings_lock()
try:
    reap_stale_temps()
    settings = {}
    source_mode = None
    if os.path.exists(path):
        source_mode = stat.S_IMODE(os.stat(path).st_mode)
        try:
            with open(path, encoding="utf-8") as handle:
                settings = json.load(handle)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            refuse_invalid_settings(f"invalid JSON ({exc})")
        if not isinstance(settings, dict):
            refuse_invalid_settings("top-level value must be a JSON object")

    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        refuse_invalid_settings("hooks must be a JSON object")
    session_end = hooks.setdefault("SessionEnd", [])
    if not isinstance(session_end, list):
        refuse_invalid_settings("hooks.SessionEnd must be a JSON array")

    matching = []
    for entry in session_end:
        if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
            continue
        for handler in entry["hooks"]:
            if isinstance(handler, dict) and handler.get("command") == command:
                matching.append((entry, handler))

    current = [(entry, handler) for entry, handler in matching
               if handler.get("timeout") == hook_timeout]
    legacy = [(entry, handler) for entry, handler in matching
              if "timeout" not in handler]
    recognized_entries = current + legacy
    customized = [pair for pair in matching if pair not in recognized_entries]
    if customized and not force:
        print(f"preserved  {requested_path}: existing {command} wiring is "
              "customized; use --wire --force to replace its timeout "
              "(exit 2)", file=sys.stderr)
        raise SystemExit(2)

    if current and not customized and not legacy:
        print(f"already    {requested_path}")
    elif legacy and not force:
        snapshot_backup()
        for _entry, handler in legacy:
            handler["timeout"] = hook_timeout
        print(f"refreshed  {requested_path}")
        write_settings(settings, source_mode)
    else:
        snapshot_backup()
        if matching:
            for _entry, handler in matching:
                handler["timeout"] = hook_timeout
            print(f"refreshed  {requested_path}")
        else:
            session_end.append({
                "hooks": [{
                    "type": "command",
                    "command": command,
                    "timeout": hook_timeout,
                }]
            })
            print(f"wired      {requested_path}")
        write_settings(settings, source_mode)
finally:
    fcntl.flock(lock_fd, fcntl.LOCK_UN)
    os.close(lock_fd)
PY
