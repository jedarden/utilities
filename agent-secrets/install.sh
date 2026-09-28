#!/bin/sh
# install.sh -- install agent-secrets into the conventional user locations.
#
#   ./install.sh                copy the hook and bao-as; never overwrites
#                               copies already there; print the settings snippet
#   ./install.sh --force        overwrite existing hook / bao-as copies
#   ./install.sh --wire         install (overwriting) and merge/upgrade the
#                               PreToolUse entry into ~/.claude/settings.json
#   ./install.sh --wire --force replace customized wiring fields too
#   ./install.sh --status print the installed version and bundle provenance
#   ./install.sh --uninstall    remove what this script installed and the
#                               settings lock (settings and ~/.config/bao-as
#                               left alone)
#
# Idempotent. Without --wire this script never touches
# ~/.claude/settings.json, and it never overwrites a hook or bao-as copy it
# finds at a destination -- the live copies may carry local edits that only
# their operator has seen, and silently replacing the enforcement layer is
# not a side effect an installer gets to have. Say --force (or --wire) to
# replace them deliberately. --uninstall is bound by the same rule in the
# direction that matters more: it refuses to remove a file this folder did
# not install, since on a machine running the credential guard that file is
# live enforcement for the whole fleet, and the refusal is all-or-nothing so
# no half-uninstalled machine is left behind. Nothing inside
# ~/.config/bao-as/ is ever rewritten: the credential files that appear next
# to instances.conf belong to the operator, and an uninstaller that removed
# them would destroy live AppRole secrets.
set -eu
HERE=$(CDPATH=; cd "$(dirname "$0")" && pwd)
HOOK_DST="${CLAUDE_HOOKS_DIR:-$HOME/.claude/hooks}/credential-guard.py"
BIN_DST="${BIN_DIR:-$HOME/.local/bin}/bao-as"
PROVENANCE_DIR="${CLAUDE_HOOKS_DIR:-$HOME/.claude/hooks}/agent-secrets"
PROVENANCE_DST="$PROVENANCE_DIR/provenance.json"
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
CONF_DIR="${BAO_AS_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/bao-as}"
force=0
case " $* " in *" --force"*) force=1 ;; esac
wire=0
case " $* " in *" --wire"*) wire=1 ;; esac

refuse() {
  echo "install.sh: refusing to remove $1 -- it is not this copy's output," >&2
  echo "            and a hand-edited copy is live enforcement this folder" >&2
  echo "            cannot vouch for. Pass --force to remove it anyway." >&2
  exit 1
}

report_previous_install() {
  if [ ! -f "$PROVENANCE_DST" ]; then
    return 0
  fi
  python3 - "$PROVENANCE_DST" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        provenance = json.load(handle)
    utility = provenance["utility"]
    version = provenance["version"]
except (OSError, KeyError, TypeError, ValueError):
    print("previously installed version unknown (invalid provenance)")
else:
    print(f"previously installed {utility} v{version}")
    for bundle in provenance.get("bundles", []):
        print(
            f"previously bundled {bundle['utility']} v{bundle['version']}"
        )
PY
}

write_provenance() {
  python3 - "$PROVENANCE_DST" "$HERE/VERSION" <<'PY'
import json
import os
import sys
import tempfile

destination, version_path = sys.argv[1:]
with open(version_path, encoding="utf-8") as handle:
    version = handle.readline().strip()
if not version:
    raise SystemExit(f"install.sh: empty utility VERSION: {version_path}")

provenance = {
    "utility": "agent-secrets",
    "version": version,
    "bundles": [],
}
directory = os.path.dirname(destination)
fd, temporary = tempfile.mkstemp(
    prefix=".provenance.", suffix=".tmp", dir=directory
)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        fd = None
        json.dump(provenance, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o644)
    os.replace(temporary, destination)
finally:
    if fd is not None:
        os.close(fd)
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY
}

case "${1:-}" in
  -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
  --status)
    if [ ! -f "$PROVENANCE_DST" ]; then
      echo "install.sh: no installed provenance at $PROVENANCE_DST" >&2
      exit 1
    fi
    cat "$PROVENANCE_DST"
    exit 0 ;;
  --uninstall)
    if [ -e "$HOOK_DST" ] && [ "$force" -ne 1 ] \
       && ! cmp -s "$HERE/hooks/credential-guard.py" "$HOOK_DST"; then
      refuse "$HOOK_DST"
    fi
    if [ -e "$BIN_DST" ] && [ "$force" -ne 1 ] \
       && ! cmp -s "$HERE/bin/bao-as" "$BIN_DST"; then
      refuse "$BIN_DST"
    fi
    python3 - "$SETTINGS" <<'PY'
import errno
import fcntl
import math
import os
import sys
import time

requested_path = sys.argv[1]
path = os.path.realpath(requested_path)
lock_path = path + ".lock"
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

try:
    lock_fd = os.open(lock_path, os.O_RDWR)
except FileNotFoundError:
    lock_fd = None
except OSError as exc:
    print(f"install.sh: refusing to uninstall: could not open settings lock "
          f"{lock_path}: {exc}; installed files were not removed",
          file=sys.stderr)
    raise SystemExit(1)

if lock_fd is not None:
    try:
        os.fchmod(lock_fd, 0o600)
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
                    print(f"install.sh: refusing to uninstall: could not "
                          f"acquire settings lock {lock_path} within "
                          f"{lock_timeout:g} seconds; installed files were "
                          "not removed", file=sys.stderr)
                    raise SystemExit(1)
                time.sleep(min(0.05, remaining))
        try:
            os.unlink(lock_path)
        except FileNotFoundError:
            pass
    except OSError as exc:
        print(f"install.sh: refusing to uninstall: could not remove settings "
              f"lock {lock_path}: {exc}; installed files were not removed",
              file=sys.stderr)
        raise SystemExit(1)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
PY
    rm -f "$HOOK_DST" "$BIN_DST" "$PROVENANCE_DST"
    rmdir "$PROVENANCE_DIR" 2>/dev/null || :
    echo "removed $HOOK_DST and $BIN_DST (settings.json and $CONF_DIR untouched; settings lock removed if present)"
    exit 0 ;;
esac

install -d -m 700 "$(dirname "$HOOK_DST")" "$(dirname "$BIN_DST")" "$CONF_DIR" "$PROVENANCE_DIR"

blocked=0
for dst in "$HOOK_DST" "$BIN_DST"; do
  if [ -e "$dst" ] && [ "$wire" -ne 1 ] && [ "$force" -ne 1 ]; then
    echo "exists     $dst -- not overwritten"
    blocked=1
  fi
done
if [ "$blocked" -eq 1 ]; then
  echo "           use --force to replace it, or --wire to replace it and wire settings.json"
  echo
  echo "Add to $SETTINGS (or re-run with --wire):"
  sed "s#~/.claude/hooks/credential-guard.py#$HOOK_DST#" "$HERE/examples/settings.json"
  exit 0
fi

report_previous_install
install -m 755 "$HERE/hooks/credential-guard.py" "$HOOK_DST"
install -m 755 "$HERE/bin/bao-as" "$BIN_DST"
write_provenance
# instances.conf is the operator's instance table, not code: seed it once at
# 0600, never rewrite it -- not even under --force.
[ -e "$CONF_DIR/instances.conf" ] || install -m 600 "$HERE/examples/bao-as-instances.conf" "$CONF_DIR/instances.conf"
echo "installed  $HOOK_DST"
echo "installed  $BIN_DST"
echo "instances  $CONF_DIR/instances.conf  (edit; put role_id/secret_id under $CONF_DIR/<name>/, mode 0600)"

if [ "$wire" -eq 1 ]; then
  python3 - "$SETTINGS" "$HOOK_DST" "$force" <<'PY'
import atexit
import errno
import fcntl
import json
import signal
import math
import os
import shutil
import stat
import sys
import tempfile
import time
requested_path, hook, force = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
# Resolve aliases before taking the lock or replacing the file.  In
# particular, os.replace() would otherwise replace a final-component symlink
# instead of the settings file it names.
path = os.path.realpath(requested_path)
cmd = f"python3 {hook}"
matcher = "Write|Edit|MultiEdit|Bash"
lock_path = path + ".lock"
settings_dir = os.path.dirname(os.path.abspath(path))
settings_name = os.path.basename(path)
temp_prefix = f".{settings_name}.agent-secrets."
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

def write_settings(s, source_mode):
    global temp_path
    fd, temp_path = tempfile.mkstemp(
        prefix=temp_prefix, suffix=".tmp", dir=settings_dir
    )
    try:
        os.fchmod(fd, source_mode if source_mode is not None else 0o600)
        with os.fdopen(fd, "w") as fh:
            fd = None
            json.dump(s, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if fd is not None:
            os.close(fd)
        cleanup_temp()

lock_fd = acquire_settings_lock()
try:
    reap_stale_temps()
    s = {}
    source_mode = None
    if os.path.exists(path):
        source_mode = stat.S_IMODE(os.stat(path).st_mode)
        try:
            with open(path) as fh:
                s = json.load(fh)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            refuse_invalid_settings(f"invalid JSON ({exc})")
        if not isinstance(s, dict):
            refuse_invalid_settings("top-level value must be a JSON object")
    pre = s.setdefault("hooks", {}).setdefault("PreToolUse", [])
    matching = []
    for entry in pre:
        if not isinstance(entry, dict):
            continue
        for handler in entry.get("hooks", []):
            if isinstance(handler, dict) and handler.get("command") == cmd:
                matching.append((entry, handler))

    current = [
        (entry, handler) for entry, handler in matching
        if entry.get("matcher") == matcher and "timeout" not in handler
    ]
    customized = [pair for pair in matching if pair not in current]
    if customized and not force:
        print(f"preserved  {requested_path}: existing {cmd} wiring is customized; "
              "use --wire --force to replace its matcher/timeout (exit 2)",
              file=sys.stderr)
        raise SystemExit(2)
    if current and not customized:
        print(f"already    {requested_path}")
    else:
        snapshot_backup()
        if matching:
            for entry, handler in matching:
                entry["matcher"] = matcher
                handler.pop("timeout", None)
            print(f"refreshed  {requested_path}")
        else:
            pre.append({"matcher": matcher,
                        "hooks": [{"type": "command", "command": cmd}]})
            print(f"wired      {requested_path}")
        write_settings(s, source_mode)
finally:
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)
PY
else
  echo
  echo "Add to $SETTINGS (or re-run with --wire):"
  sed "s#~/.claude/hooks/credential-guard.py#$HOOK_DST#" "$HERE/examples/settings.json"
fi
