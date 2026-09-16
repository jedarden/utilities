#!/usr/bin/env bash
# install.sh -- install agent-secrets into the conventional user locations.
#
#   ./install.sh                copy the hook and bao-as; never overwrites
#                               copies already there; print the settings snippet
#   ./install.sh --force        overwrite existing hook / bao-as copies
#   ./install.sh --wire         install (overwriting) and merge the PreToolUse
#                               entry into ~/.claude/settings.json
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
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK_DST="${CLAUDE_HOOKS_DIR:-$HOME/.claude/hooks}/credential-guard.py"
BIN_DST="${BIN_DIR:-$HOME/.local/bin}/bao-as"
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
CONF_DIR="${BAO_AS_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/bao-as}"
force=0
case " $* " in *" --force"*) force=1 ;; esac

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

mode="${1:-}"
blocked=0
for dst in "$HOOK_DST" "$BIN_DST"; do
  if [ -e "$dst" ] && [ "$mode" != "--wire" ] && [ "$force" -ne 1 ]; then
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

if [ "$mode" = "--wire" ]; then
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
