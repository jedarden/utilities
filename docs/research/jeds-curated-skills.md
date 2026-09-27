# Prior art: `jeds-curated-skills` install-time inlining

## Source

- [Canonical Forgejo repository](https://git.ardenone.com/jedarden/jeds-curated-skills)
- [GitHub read-only mirror](https://github.com/jedarden/jeds-curated-skills)
- Checkout inspected for this note: commit `288465c87d3e0324c87d1c514306261ad690a5ab`

The relevant implementation is in `install.sh`, `lib/common.sh`,
`lib/inline.sh`, and `scripts/check-installed.sh` in that repository.

## Problem

The skills repository has a shared `lib/common.sh` containing shell helpers
used by scripts in several skills. A full repository checkout can resolve
those scripts' `../../lib/common.sh` source path, but a selective install
places only one skill under `~/.claude/skills/<skill>`. A byte-for-byte copy of
that skill therefore leaves a source path that cannot resolve at runtime.

The repository README calls out the failure mode explicitly: bare `cp -r` can
produce a copy that looks identical to the source while still failing when a
script starts.

## Pattern used

`install.sh` copies the selected skill and then finds shell scripts that source
`../../lib/common.sh`. For each one it emits a replacement containing the
script's own content plus the helper body from `lib/common.sh`, marked with an
inlining comment. The installed skill is consequently executable without the
repository-level `lib/` directory.

The transformation lives once in `lib/inline.sh`. The installer and
`scripts/check-installed.sh` both use it, so the checker can re-derive the
expected inline from the current script and current library. A current inline
is treated as the expected install difference; an inline made from an older
library or edited after installation is reported as stale drift and repaired by
reinstalling the skill.

## What this establishes for `utilities`

This is direct prior art for keeping a selective install self-contained: the
repository may share implementation source while the installed artifact must
not depend on a repository-level runtime path. It supports the utilities
decision to keep each utility a runtime leaf and to make reuse an explicit
install-time operation.

The utilities repository narrows and formalizes the exception further. A
cross-utility copy must be declared in `bundled-dependencies.json`, pin the
sibling `VERSION`, and be validated by `scripts/check-structure.py`. That
manifest and version check provide provenance for a bundle; they do not permit
an installed utility to consult the sibling checkout later.

## Trade-offs observed

- The installed copy is self-contained, but it duplicates the helper source.
- A change to `lib/common.sh` does not update existing installs; they become
  stale until reinstalled.
- Installer and drift-checker behavior must share one derivation function, or
  fresh installs will be incorrectly reported as drift.
- The pattern solves install-time source availability; it does not justify a
  general shared runtime library for independently installable utilities.
