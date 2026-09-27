# Design decisions

This note records the repository-level decisions that shape the utilities
layout. The longer implementation plan is in [`docs/plan/plan.md`](../plan/plan.md);
this is the short rationale to consult when adding or extracting a utility.

## Utilities are runtime leaves

Each top-level utility owns its runtime files and can be installed without
bringing the rest of this repository along. There is intentionally no shared
runtime `lib/` directory and no utility may import, execute, or discover a
sibling at runtime.

The reason is operational: a shared runtime directory makes an apparently
single-utility install depend on the whole checkout and gives an installed
utility a hidden path back into the repository. Host settings may compose
optional companions, but the utility itself must remain a standalone runtime
leaf.

The consequence is some deliberate duplication between utilities. That cost
is preferable to a broken selective install or an undeclared cross-utility
runtime dependency. The cited prior art and its install-time inlining pattern
are recorded in [`docs/research/jeds-curated-skills.md`](../research/jeds-curated-skills.md).

## Install-time bundles are the only reuse exception

When a utility needs to ship a companion file, reuse happens only at install
time. A `bundled-dependencies.json` entry names the sibling, pins its exact
`VERSION`, identifies the source, and names the destination inside the
utility's own installed layout. The installer copies that pinned source; the
installed copy, not the sibling checkout, is the runtime input.

This keeps the installed utility self-contained while allowing a reviewed,
versioned seam for narrow reuse. `scripts/check-structure.py` validates the
manifest, source, pinned version, and copy reference, and rejects undeclared
sibling references. The current `org-rule-guard` bundle of
`agent-secrets/hooks/credential-guard.py` is the concrete example; its
standalone credential fallback remains available.

The pin is a lockstep constraint, not historical metadata: it must equal the
sibling's current `VERSION` at `HEAD`. The combined version gate runs this
structural check, so a sibling release leaves the repository failing until the
bundle pin is updated. Bump `bundled-dependencies.json` in the same push as the
sibling release, or publish a dependent utility release that updates the pin;
for the `org-rule-guard` bundle, that means updating its `agent-secrets` pin
alongside the relevant `agent-secrets` release or in a subsequent
`org-rule-guard` release.

## Version files, changelogs, and tags are a release contract

Versioning belongs to each utility: `<utility>/VERSION` contains a semver
value, `<utility>/CHANGELOG.md` records what users should expect from each
release, and the corresponding release tag is `<utility>/vX.Y.Z`. Every
release entry uses the exact heading `## [X.Y.Z] - YYYY-MM-DD` and is committed
with the matching VERSION bump. The contract is bidirectional.
`scripts/check-versions.sh` verifies that every VERSION at `HEAD` has its
current-version changelog heading and exact tag, and that every utility tag
points to a commit whose VERSION agrees with the tag.

Therefore a release is one changelog entry and VERSION bump followed by a
matching tag, pushed together with the commit:

```text
git push origin main <utility>/vX.Y.Z
```

Pushing only the VERSION change intentionally leaves the repository failing
the release gate. This makes the source version, user-facing change summary,
and published identity unambiguous for each independently installable utility.
For an `agent-secrets` release, the same push must also update
`org-rule-guard/bundled-dependencies.json` so its pinned `agent-secrets`
version equals the new `agent-secrets/VERSION`. If that pin cannot be included
in the same push, immediately follow with a dependent `org-rule-guard` release
that updates it; the combined gate stays red while the pin is stale.

## Small, dependency-light repository tooling

Utility shell scripts use POSIX `sh`; Python utility code uses the standard
library, and utility installers do not install packages. Repository tooling
under `scripts/` and documentation under `docs/` are not utility runtime and
are exempt from those runtime checks. This boundary lets the structural gate
remain usable on a minimal machine without weakening the installed utility
contract.
