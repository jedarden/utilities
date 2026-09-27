#!/usr/bin/env bash
# check-shellcheck.sh -- enforce the repository's ShellCheck version floor.
#
# Verify the tool before invoking it so a stale CI image or local install
# cannot silently run a different analysis surface than the repository uses.

set -eu

minimum_version='0.9.0'

fail() {
    printf 'check-shellcheck: %s\n' "$*" >&2
    printf 'check-shellcheck: install ShellCheck %s or newer and ensure it is on PATH, then retry.\n' \
        "$minimum_version" >&2
    exit 1
}

if ! command -v shellcheck >/dev/null 2>&1; then
    fail "ShellCheck $minimum_version or newer is required, but 'shellcheck' was not found"
fi

if ! version_output=$(shellcheck --version 2>&1); then
    fail "could not query the installed ShellCheck version: $version_output"
fi

version=$(printf '%s\n' "$version_output" |
    sed -n 's/^version:[[:space:]]*//p' |
    head -n 1)
if [[ -z $version ]]; then
    fail "could not find a version in 'shellcheck --version' output"
fi
if [[ ! $version =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    fail "ShellCheck reported unsupported version '$version'; expected a numeric version such as $minimum_version"
fi

major=$((10#${BASH_REMATCH[1]}))
minor=$((10#${BASH_REMATCH[2]}))
if (( major < 0 || (major == 0 && minor < 9) )); then
    fail "ShellCheck $version is too old; this repository requires $minimum_version or newer"
fi

printf 'check-shellcheck: ShellCheck %s satisfies the minimum %s\n' \
    "$version" "$minimum_version"

if (( $# == 0 )); then
    set -- \
        agent-secrets/install.sh \
        agent-secrets/bin/bao-as \
        org-rule-guard/install.sh \
        scripts/check-versions.sh \
        scripts/check-shellcheck.sh
fi

exec shellcheck "$@"
