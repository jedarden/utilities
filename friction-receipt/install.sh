#!/bin/sh
# Install the standalone SessionEnd friction receipt hook.
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
    sed -n '2,5p' "$0"
    exit 0
    ;;
  --uninstall)
    if [ -e "$HOOK_DST" ] && [ "$force" -ne 1 ] \
       && ! cmp -s "$HERE/hooks/friction-receipt.py" "$HOOK_DST"; then
      echo "install.sh: refusing to remove $HOOK_DST -- it is not this copy's output; pass --force" >&2
      exit 1
    fi
    rm -f "$HOOK_DST"
    echo "removed $HOOK_DST (settings.json and receipts left in place)"
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

python3 - "$SETTINGS" "$HOOK_DST" <<'PY'
import json
import os
import stat
import sys
import tempfile

settings, hook = sys.argv[1:]
directory = os.path.dirname(os.path.abspath(settings))
if not os.path.isdir(directory):
    raise SystemExit(f"install.sh: settings parent does not exist: {directory}")
path = os.path.realpath(settings)
mode = stat.S_IMODE(os.stat(path).st_mode) if os.path.exists(path) else 0o600
if os.path.exists(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise SystemExit("install.sh: settings root must be an object")
else:
    data = {}
hooks = data.setdefault("hooks", {})
session_end = hooks.setdefault("SessionEnd", [])
command = f"python3 {hook}"
if not any(
    isinstance(entry, dict)
    and any(isinstance(item, dict) and item.get("command") == command
            for item in entry.get("hooks", []))
    for entry in session_end
):
    session_end.append({"hooks": [{"type": "command", "command": command}]})
    fd, temporary = tempfile.mkstemp(prefix=".settings.friction-receipt.", suffix=".tmp", dir=directory)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            json.dump(data, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    print(f"wired      {settings}")
else:
    print(f"already    {settings}")
PY
