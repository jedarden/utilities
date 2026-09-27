#!/bin/sh
# install.sh -- install agent-secrets into the conventional user locations.
#
#   ./install.sh                copy the hook and bao-as; never overwrites
#                               copies already there; print the settings snippet
#   ./install.sh --force        overwrite existing hook / bao-as copies
#   ./install.sh --wire         install (overwriting) and merge/upgrade the
#                               PreToolUse entry into ~/.claude/settings.json
#   ./install.sh --wire --force replace customized wiring fields too
#   ./install.sh --uninstall    remove what this script installed (settings
#                               and ~/.config/bao-as left alone)
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

case "${1:-}" in
  -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
  --uninstall)
    if [ -e "$HOOK_DST" ] && [ "$force" -ne 1 ] \
       && ! cmp -s "$HERE/hooks/credential-guard.py" "$HOOK_DST"; then
      refuse "$HOOK_DST"
    fi
    if [ -e "$BIN_DST" ] && [ "$force" -ne 1 ] \
       && ! cmp -s "$HERE/bin/bao-as" "$BIN_DST"; then
      refuse "$BIN_DST"
    fi
    rm -f "$HOOK_DST" "$BIN_DST"
    echo "removed $HOOK_DST and $BIN_DST (settings.json and $CONF_DIR untouched)"
    exit 0 ;;
esac

install -d -m 700 "$(dirname "$HOOK_DST")" "$(dirname "$BIN_DST")" "$CONF_DIR"

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

install -m 755 "$HERE/hooks/credential-guard.py" "$HOOK_DST"
install -m 755 "$HERE/bin/bao-as" "$BIN_DST"
# instances.conf is the operator's instance table, not code: seed it once at
# 0600, never rewrite it -- not even under --force.
[ -e "$CONF_DIR/instances.conf" ] || install -m 600 "$HERE/examples/bao-as-instances.conf" "$CONF_DIR/instances.conf"
echo "installed  $HOOK_DST"
echo "installed  $BIN_DST"
echo "instances  $CONF_DIR/instances.conf  (edit; put role_id/secret_id under $CONF_DIR/<name>/, mode 0600)"

if [ "$wire" -eq 1 ]; then
  python3 - "$SETTINGS" "$HOOK_DST" "$force" <<'PY'
import fcntl
import json
import os
import shutil
import stat
import sys
import tempfile
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

if not os.path.isdir(settings_dir):
    print(f"install.sh: refusing to wire {requested_path}: settings parent "
          f"directory does not exist: {settings_dir}", file=sys.stderr)
    raise SystemExit(1)

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

with open(lock_path, "a+") as lock:
    os.chmod(lock_path, stat.S_IRUSR | stat.S_IWUSR)
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)

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

    current = next(
        ((entry, handler) for entry, handler in matching
         if entry.get("matcher") == matcher and "timeout" not in handler),
        None,
    )
    if current is not None:
        print(f"already    {requested_path}")
    elif matching and not force:
        print(f"preserved  {requested_path}: existing {cmd} wiring is customized; "
              "use --wire --force to replace its matcher/timeout", file=sys.stderr)
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
        fd, tmp = tempfile.mkstemp(
            prefix=f".{settings_name}.", suffix=".tmp", dir=settings_dir
        )
        try:
            if source_mode is not None:
                os.fchmod(fd, source_mode)
            with os.fdopen(fd, "w") as fh:
                fd = None
                json.dump(s, fh, indent=2)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
            tmp = None
        finally:
            if fd is not None:
                os.close(fd)
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass
PY
else
  echo
  echo "Add to $SETTINGS (or re-run with --wire):"
  sed "s#~/.claude/hooks/credential-guard.py#$HOOK_DST#" "$HERE/examples/settings.json"
fi
