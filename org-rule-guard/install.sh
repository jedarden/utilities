#!/usr/bin/env bash
# install.sh -- install org-rule-guard into the conventional user locations.
#
#   ./install.sh                copy the hook; never overwrites one already there
#   ./install.sh --force        overwrite an existing hook copy
#   ./install.sh --wire         install (overwriting) and merge the PreToolUse
#                               entry into ~/.claude/settings.json
#   ./install.sh --uninstall    remove the installed hook (settings left alone)
#
# The credential guard is a pinned install-time bundle.  The source lives in
# agent-secrets in this checkout, but the installed copy lives under this
# utility's own hook layout and is not looked up or executed from the sibling
# at runtime.  Keep BUNDLE_VERSION in sync with bundled-dependencies.json.
#
# Idempotent. Without --wire this script never touches ~/.claude/settings.json,
# and it never overwrites a hook file it finds at the destination -- the live
# copy may carry local edits that only its operator has seen, and silently
# replacing the enforcement layer is not a side effect an installer gets to
# have. Say --force (or --wire) to replace it deliberately. --uninstall is
# bound by the same rule in the direction that matters more: it refuses to
# remove a file this folder did not install, since on a machine running the
# pre-port hook that file is live enforcement for the whole fleet.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK_DST="${CLAUDE_HOOKS_DIR:-$HOME/.claude/hooks}/org-rule-guard.py"
BUNDLE_VERSION="0.1.0"
BUNDLE_SOURCE="$HERE/../agent-secrets/hooks/credential-guard.py"
BUNDLE_DST="${HOOK_DST%.py}/credential-guard.py"
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
force=0
case " $* " in *" --force"*) force=1 ;; esac

case "${1:-}" in
  -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
  --uninstall)
    if [ -e "$HOOK_DST" ] && [ "$force" -ne 1 ] \
       && ! cmp -s "$HERE/hooks/org-rule-guard.py" "$HOOK_DST"; then
      echo "install.sh: refusing to remove $HOOK_DST -- it is not this copy's output," >&2
      echo "            and on a machine still running the pre-port hook that file is" >&2
      echo "            live enforcement. Pass --force to remove it anyway." >&2
      exit 1
    fi
    if [ -e "$BUNDLE_DST" ] && [ "$force" -ne 1 ] \
       && ! cmp -s "$BUNDLE_SOURCE" "$BUNDLE_DST"; then
      echo "install.sh: refusing to remove $BUNDLE_DST -- it is not this copy's output," >&2
      echo "            and a hand-edited bundle may be live enforcement. Pass --force." >&2
      exit 1
    fi
    rm -f "$HOOK_DST" "$BUNDLE_DST"
    echo "removed $HOOK_DST and $BUNDLE_DST (settings.json and ${XDG_STATE_HOME:-$HOME/.local/state}/org-rule-guard untouched)"
    exit 0 ;;
esac

if [ ! -f "$BUNDLE_SOURCE" ]; then
  echo "install.sh: pinned bundle source is missing: $BUNDLE_SOURCE" >&2
  exit 1
fi
source_version="$(sed -n '1{s/^[[:space:]]*//;s/[[:space:]]*$//;p;}' "$HERE/../agent-secrets/VERSION")"
if [ "$source_version" != "$BUNDLE_VERSION" ]; then
  echo "install.sh: agent-secrets VERSION is $source_version, expected pinned $BUNDLE_VERSION" >&2
  exit 1
fi

install -d -m 700 "$(dirname "$HOOK_DST")" "${HOOK_DST%.py}"

mode="${1:-}"
blocked=0
for dst in "$HOOK_DST" "$BUNDLE_DST"; do
  if [ -e "$dst" ] && [ "$mode" != "--wire" ] && [ "$mode" != "--force" ]; then
    echo "exists     $dst -- not overwritten"
    blocked=1
  fi
done
if [ "$blocked" -eq 1 ]; then
  echo "           use --force to replace it, or --wire to replace it and wire settings.json"
  echo
  echo "Add to $SETTINGS (or re-run with --wire):"
  sed "s#~/.claude/hooks/org-rule-guard.py#$HOOK_DST#" "$HERE/examples/settings.json"
  exit 0
fi

install -m 755 "$HERE/hooks/org-rule-guard.py" "$HOOK_DST"
install -m 755 "$HERE/../agent-secrets/hooks/credential-guard.py" "$BUNDLE_DST"
echo "installed  $HOOK_DST"
echo "bundled    $BUNDLE_DST (agent-secrets v$BUNDLE_VERSION)"
echo "log        ${XDG_STATE_HOME:-$HOME/.local/state}/org-rule-guard/denials.jsonl  (written on the first denial)"

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
    pre.append({"matcher": "Write|Edit|Bash",
                "hooks": [{"type": "command", "command": cmd, "timeout": 10}]})
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
  sed "s#~/.claude/hooks/org-rule-guard.py#$HOOK_DST#" "$HERE/examples/settings.json"
fi
