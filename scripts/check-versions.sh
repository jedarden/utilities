#!/usr/bin/env bash
# check-versions.sh -- enforce the per-utility VERSION <-> git tag contract.
#
# docs/plan/plan.md: every utility folder carries a semver `<utility>/VERSION`
# and every release is a git tag `<utility>/vX.Y.Z`. Nothing about that is
# self-enforcing; this script is the check utilities-ci runs on every push.
#
# It fails when:
#   - a `<utility>/VERSION` at HEAD is not semver X.Y.Z;
#   - the tag `<utility>/v<version>` does not exist (VERSION bumped, never
#     released);
#   - a `<utility>/v*` tag points at a commit where `<utility>/VERSION` is
#     missing or disagrees with the tag's version (tagged before the bump,
#     utility folder absent at the tag, ...);
#   - `*/v*` tags exist but no `*/VERSION` file does (utilities unversioned).
#
# Release flow that stays green: commit the VERSION bump, tag it, push commit
# and tag together --
#   git tag <utility>/v<X.Y.Z> && git push origin main <utility>/v<X.Y.Z>
# Pushing the commit alone fails CI until the tag lands.
#
# Works in a full checkout (pre-push release check) and in utilities-ci's
# shallow clone (the template fetches `origin --tags` before invoking this;
# tag objects beyond the shallow window are fetched with the tag refs).

set -eu

die() { printf 'check-versions: %s\n' "$*" >&2; exit 1; }

top=$(git rev-parse --show-toplevel 2>/dev/null) || die "not a git repository"
cd "$top"

errors=0
fail() { printf 'check-versions: %s\n' "$*" >&2; errors=$((errors + 1)); }

# VERSION content of <utility> at <rev>, first line, whitespace-trimmed.
# Empty output means "no such file at that rev" (git show's own error is
# suppressed; the callers treat empty as the failure).
version_at() {
    git show "$1:$2/VERSION" 2>/dev/null |
        sed -n '1{s/^[[:space:]]*//;s/[[:space:]]*$//;p;}'
}

semver='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'

# -- forward: every VERSION at HEAD must have a tag at exactly its version

utilities=0
shopt -s nullglob
for version_file in */VERSION; do
    utilities=$((utilities + 1))
    utility=${version_file%/VERSION}

    version=$(sed -n '1{s/^[[:space:]]*//;s/[[:space:]]*$//;p;}' "$version_file")
    if [[ ! $version =~ $semver ]]; then
        fail "$utility/VERSION is '$version', expected semver X.Y.Z"
        continue
    fi
    if ! git rev-parse -q --verify "refs/tags/$utility/v$version^{commit}" >/dev/null; then
        fail "no tag $utility/v$version -- $utility/VERSION says $version but nothing was released"
    fi
done

# -- reverse: every <utility>/v* tag must agree with VERSION at its commit

for tag in $(git tag -l -- '*/v*'); do
    utility=${tag%/v*}
    tagged=${tag##*/v}
    if [[ $utility == '' || $utility == */* || ! $tagged =~ $semver ]]; then
        fail "tag $tag is not shaped <utility>/vX.Y.Z"
        continue
    fi
    at=$(version_at "refs/tags/$tag" "$utility")
    if [[ -z $at ]]; then
        fail "tag $tag points at a commit with no $utility/VERSION"
    elif [[ $at != "$tagged" ]]; then
        fail "tag $tag points at a commit where $utility/VERSION reads '$at', not $tagged"
    fi
done

if [[ $utilities -eq 0 ]] && [[ -n $(git tag -l -- '*/v*') ]]; then
    fail "no */VERSION files at HEAD but */v* tags exist"
fi

[[ $errors -eq 0 ]] || die "$errors mismatch(es) between VERSION files and tags"

printf 'check-versions: %d utilities, VERSION files and tags agree\n' "$utilities"
