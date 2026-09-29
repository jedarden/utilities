#!/bin/sh
# install.sh -- install agent-secrets into the conventional user locations.
#
#   ./install.sh                copy the hook and bao-as; never overwrites
#                               copies already there; print the settings snippet
#   ./install.sh --force        overwrite existing hook / bao-as copies
#   ./install.sh --wire         install (overwriting) and merge/upgrade the
#                               PreToolUse entry into ~/.claude/settings.json
#   ./install.sh --wire --force replace customized wiring fields too
#   ./install.sh --status print provenance and check installed-file drift
#   ./install.sh --uninstall    remove what this script installed, unwire its
#                               exact-command settings entry, and remove the
#                               settings lock (settings backup, ~/.config/bao-as,
#                               and credential denial state left alone)
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
STATE_DIR="${CREDENTIAL_GUARD_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/credential-guard}"
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
CONF_DIR="${BAO_AS_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/bao-as}"
force=0
case " $* " in *" --force"*) force=1 ;; esac
wire=0
case " $* " in *" --wire"*) wire=1 ;; esac

require_python3() {
  python_version=
  if python_version=$(python3 -c \
    'import sys; print(".".join(str(part) for part in sys.version_info[:3])); raise SystemExit(sys.version_info < (3, 9))' \
    2>/dev/null)
  then
    return 0
  fi
  if [ -n "$python_version" ]; then
    echo "install.sh: warning: Python 3.9 or newer is required; found Python $python_version. Installation aborted. Existing installed hooks fail open if their interpreter cannot start." >&2
  else
    echo "install.sh: warning: Python 3.9 or newer is required, but a working python3 interpreter is missing or could not start. Installation aborted. Existing installed hooks fail open if their interpreter cannot start." >&2
  fi
  exit 1
}

refuse() {
  echo "install.sh: refusing to remove $1 -- it is not this copy's output," >&2
  echo "            and a hand-edited copy is live enforcement this folder" >&2
  echo "            cannot vouch for. Pass --force to remove it anyway." >&2
  exit 1
}

status_error=0

status_report() {
  echo "install.sh: drift: $*; reinstall to repair" >&2
  status_error=1
}

check_installed_file() {
  label=$1
  source=$2
  destination=$3
  if [ ! -f "$destination" ]; then
    status_report "missing installed $label at $destination"
    return
  fi
  if [ ! -f "$source" ]; then
    status_report "cannot re-derive expected $label from missing $source"
    return
  fi
  if command -v cmp >/dev/null 2>&1; then
    if ! cmp -s "$source" "$destination"; then
      status_report "modified or stale $label at $destination"
    fi
  elif [ "$(cat "$source")" != "$(cat "$destination")" ]; then
    status_report "modified or stale $label at $destination"
  fi
  if [ -x "$source" ] && [ ! -x "$destination" ]; then
    status_report "modified mode on installed $label at $destination"
  fi
}

check_unexpected_files() {
  directory=$1
  expected=$2
  for path in "$directory"/.[!.]* "$directory"/*; do
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
      continue
    fi
    case "$path" in
      "$expected") ;;
      *) status_report "stale installed path at $path" ;;
    esac
  done
}

prune_unexpected_files() {
  directory=$1
  expected=$2
  for path in "$directory"/.[!.]* "$directory"/*; do
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
      continue
    fi
    case "$path" in
      "$expected") ;;
      *)
        if [ -f "$path" ] || [ -L "$path" ]; then
          rm -f "$path"
          echo "pruned     $path"
        fi
        ;;
    esac
  done
}

check_installed_state() {
  # The status path intentionally uses only shell built-ins plus cat/cmp.  It
  # remains useful on a host where python3 is unavailable, while the install
  # path still enforces the Python prerequisite before writing anything.
  recorded_utility=
  recorded_version=
  in_bundles=0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      *'"bundles": ['*) in_bundles=1 ;;
      *'"utility": "'*)
        value=${line#*: }
        value=${value#\"}
        value=${value%%\"*}
        if [ "$in_bundles" -eq 0 ]; then
          recorded_utility=$value
        fi
        ;;
      *'"version": "'*)
        value=${line#*: }
        value=${value#\"}
        value=${value%%\"*}
        if [ "$in_bundles" -eq 0 ]; then
          recorded_version=$value
        elif [ -z "${recorded_bundle_version:-}" ]; then
          recorded_bundle_version=$value
        fi
        ;;
    esac
  done < "$PROVENANCE_DST"

  if [ "${recorded_utility:-}" != "agent-secrets" ] || [ -z "${recorded_version:-}" ]; then
    status_report "invalid provenance identity in $PROVENANCE_DST"
  fi
  current_version=$(IFS= read -r first_line < "$HERE/VERSION" && printf '%s' "$first_line" || :)
  if [ -n "${recorded_version:-}" ] && [ "$current_version" != "$recorded_version" ]; then
    status_report "installed utility v$recorded_version does not match this checkout's v$current_version"
  fi
  check_installed_file "credential guard hook" "$HERE/hooks/credential-guard.py" "$HOOK_DST"
  check_installed_file "bao-as wrapper" "$HERE/bin/bao-as" "$BIN_DST"
  check_unexpected_files "$PROVENANCE_DIR" "$PROVENANCE_DST"
  return "$status_error"
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
    "runtime": {"python3": ">=3.9"},
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
    check_installed_state
    exit $? ;;
  --uninstall)
    require_python3
    if [ -e "$HOOK_DST" ] && [ "$force" -ne 1 ] \
       && ! cmp -s "$HERE/hooks/credential-guard.py" "$HOOK_DST"; then
      refuse "$HOOK_DST"
    fi
    if [ -e "$BIN_DST" ] && [ "$force" -ne 1 ] \
       && ! cmp -s "$HERE/bin/bao-as" "$BIN_DST"; then
      refuse "$BIN_DST"
    fi
    python3 - "$SETTINGS" "$HOOK_DST" "$force" <<'PY'
import errno
import fcntl
import json
import math
import os
import stat
import sys
import tempfile
import time

requested_path, hook, force = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
path = os.path.realpath(requested_path)
cmd = f"python3 {hook}"
matcher = "Write|Edit|MultiEdit|NotebookEdit|Bash"
hook_timeout = 10
legacy_matchers = {matcher, "Write|Edit|MultiEdit|Bash"}
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
        prefix=f".{os.path.basename(path)}.agent-secrets.",
        suffix=".tmp", dir=settings_dir
    )
    try:
        os.fchmod(fd, source_mode)
        with os.fdopen(fd, "w") as handle:
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
            with open(path) as handle:
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
        pre = hooks.get("PreToolUse", []) if isinstance(hooks, dict) else None
        if pre is None or not isinstance(pre, list):
            print(f"install.sh: refusing to uninstall {requested_path}: "
                  "hooks.PreToolUse must be a JSON array; installed files "
                  "were not removed", file=sys.stderr)
            raise SystemExit(1)

        matching = []
        for entry in pre:
            if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                continue
            for handler in entry["hooks"]:
                if isinstance(handler, dict) and handler.get("command") == cmd:
                    matching.append((entry, handler))

        def recognized(entry, handler):
            return (
                entry.get("matcher") == matcher
                and handler.get("timeout") == hook_timeout
            ) or (
                entry.get("matcher") in legacy_matchers
                and "timeout" not in handler
            )

        customized = [(entry, handler) for entry, handler in matching
                      if not recognized(entry, handler)]
        if customized and not force:
            print(f"install.sh: preserved {requested_path}: existing {cmd} "
                  "wiring is customized; use --uninstall --force to remove "
                  "it (exit 2)", file=sys.stderr)
            raise SystemExit(2)

        if not matching:
            print(f"unwired    {requested_path}: no matching {cmd} entry")
        else:
            removed = 0
            new_pre = []
            for entry in pre:
                if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                    new_pre.append(entry)
                    continue
                kept = []
                for handler in entry["hooks"]:
                    if (isinstance(handler, dict)
                            and handler.get("command") == cmd
                            and (force or recognized(entry, handler))):
                        removed += 1
                    else:
                        kept.append(handler)
                if kept:
                    if len(kept) != len(entry["hooks"]):
                        entry["hooks"] = kept
                    new_pre.append(entry)
            hooks["PreToolUse"] = new_pre
            write_settings(settings, source_mode)
            print(f"unwired    {requested_path}: removed {removed} {cmd} entry")
finally:
    try:
        os.unlink(lock_path)
    except FileNotFoundError:
        pass
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
PY
    rm -f "$HOOK_DST" "$BIN_DST" "$PROVENANCE_DST"
    # The provenance record describes this installed copy and is removed with
    # it. The denial state is independent audit data: retain the active log,
    # rotated backup, lock, and state directory so uninstall cannot erase the
    # bounded record of what this guard denied.
    rmdir "$PROVENANCE_DIR" 2>/dev/null || :
    echo "removed $HOOK_DST and $BIN_DST (provenance removed; settings.json, $CONF_DIR, and $STATE_DIR untouched; settings lock removed if present)"
    exit 0 ;;
esac

require_python3
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

prune_unexpected_files "$PROVENANCE_DIR" "$PROVENANCE_DST"
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
matcher = "Write|Edit|MultiEdit|NotebookEdit|Bash"
hook_timeout = 10
legacy_matchers = {
    matcher,
    "Write|Edit|MultiEdit|Bash",
}
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
        if entry.get("matcher") == matcher
        and handler.get("timeout") == hook_timeout
    ]
    legacy = [
        (entry, handler) for entry, handler in matching
        if entry.get("matcher") in legacy_matchers
        and "timeout" not in handler
    ]
    recognized = current + legacy
    customized = [pair for pair in matching if pair not in recognized]
    if customized and not force:
        print(f"preserved  {requested_path}: existing {cmd} wiring is customized; "
              "use --wire --force to replace its matcher/timeout (exit 2)",
              file=sys.stderr)
        raise SystemExit(2)
    if current and not customized and not legacy:
        print(f"already    {requested_path}")
    elif legacy and not force:
        snapshot_backup()
        for entry, handler in legacy:
            entry["matcher"] = matcher
            handler["timeout"] = hook_timeout
        print(f"refreshed  {requested_path}")
        write_settings(s, source_mode)
    else:
        snapshot_backup()
        if matching:
            for entry, handler in matching:
                entry["matcher"] = matcher
                handler["timeout"] = hook_timeout
            print(f"refreshed  {requested_path}")
        else:
            pre.append({"matcher": matcher,
                        "hooks": [{"type": "command", "command": cmd,
                                   "timeout": hook_timeout}]})
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
