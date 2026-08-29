#!/usr/bin/env bash
# install.sh -- install agent-secrets into the conventional user locations.
#
#   ./install.sh                copy the hook and bao-as; print the settings snippet
#   ./install.sh --wire         also merge the PreToolUse entry into ~/.claude/settings.json
#   ./install.sh --uninstall    remove what this script installed (settings left alone)
#
# Idempotent. Never edits ~/.claude/settings.json unless --wire is given, and
# then only adds the one hook entry if it is not already present.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK_DST="${CLAUDE_HOOKS_DIR:-$HOME/.claude/hooks}/credential-guard.py"
BIN_DST="${BIN_DIR:-$HOME/.local/bin}/bao-as"
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
CONF_DIR="${BAO_AS_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/bao-as}"

case "${1:-}" in
  -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
  --uninstall)
    rm -f "$HOOK_DST" "$BIN_DST"
    echo "removed $HOOK_DST and $BIN_DST (settings.json and $CONF_DIR untouched)"
    exit 0 ;;
esac

install -d -m 700 "$(dirname "$HOOK_DST")" "$(dirname "$BIN_DST")" "$CONF_DIR"
install -m 755 "$HERE/hooks/credential-guard.py" "$HOOK_DST"
install -m 755 "$HERE/bin/bao-as" "$BIN_DST"
[ -e "$CONF_DIR/instances.conf" ] || install -m 600 "$HERE/examples/bao-as-instances.conf" "$CONF_DIR/instances.conf"
echo "installed  $HOOK_DST"
echo "installed  $BIN_DST"
echo "instances  $CONF_DIR/instances.conf  (edit; put role_id/secret_id under $CONF_DIR/<name>/)"

if [ "${1:-}" = "--wire" ]; then
  python3 - "$SETTINGS" "$HOOK_DST" <<'PY'
import json, os, sys
path, hook = sys.argv[1], sys.argv[2]
cmd = f"python3 {hook}"
s = {}
if os.path.exists(path):
    with open(path) as fh:
        s = json.load(fh)
pre = s.setdefault("hooks", {}).setdefault("PreToolUse", [])
present = any(h.get("command") == cmd for e in pre for h in e.get("hooks", []))
if not present:
    pre.append({"matcher": "Write|Edit|MultiEdit|Bash",
                "hooks": [{"type": "command", "command": cmd}]})
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(s, fh, indent=2); fh.write("\n")
    os.replace(tmp, path)
    print(f"wired      {path}")
else:
    print(f"already    {path}")
PY
else
  echo
  echo "Add to $SETTINGS (or re-run with --wire):"
  sed "s#~/.claude/hooks/credential-guard.py#$HOOK_DST#" "$HERE/examples/settings.json"
fi
