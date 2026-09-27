# Credential-guard pattern inventory

This document is the human-readable companion to
[`hooks/credential-guard.py`](../hooks/credential-guard.py). The
`BUILTIN_PATTERNS` tuple in that file is the executable source of truth; this
inventory must be updated in the same change whenever that tuple changes. The
credential-guard unittest suite compares the exact labels and regexes below
with the tuple, and also checks the exemption table, so documentation drift
fails the normal regression gate.

## What counts as high-signal

The guard is intentionally a narrow credential-shape check, not a generic
secret or entropy detector. A built-in pattern qualifies as high-signal only
when it has:

1. a vendor- or product-specific prefix or grammar;
2. a minimum width at the real credential width (a token-type name by itself
   must stay below the match threshold); and
3. enough structure that ordinary hashes, UUIDs, base64 data, prose, and
   documentation examples are not normally matches.

The PEM private-key header is the one multi-line exception: the header is
specific enough to identify the credential type, and the matcher checks the
following 200 characters for a placeholder before denying. Every other
built-in pattern is self-contained and does not use nearby text to excuse a
match.

The matcher also skips a match when its value is an obvious documentation
stand-in: a placeholder word (`example`, `REPLACE`, `your`, `dummy`,
`placeholder`, `redact`, `changeme`, `todo`, `xxxx`, or `...`), a body made of
one repeated character, or a line marked `gitleaks:allow`. These exemptions
are part of the guard contract and do not lower the high-signal bar for new
patterns.

## Built-in inventory

The table records the regex, its minimum shape, and whether the matcher looks
past the match for a placeholder. The regexes use Python's `re` syntax.

| Label | Regex | Minimum shape / context |
|---|---|---|
| GitHub token | `\bgh[pousr]_[A-Za-z0-9]{30,}` | Known `gh*` vendor prefix plus at least 30 body characters; no look-ahead |
| GitHub fine-grained PAT | `\bgithub_pat_[A-Za-z0-9_]{40,}` | `github_pat_` plus at least 40 body characters; no look-ahead |
| GitLab token | `\bglpat-[A-Za-z0-9_-]{20,}` | `glpat-` plus at least 20 body characters; no look-ahead |
| npm token | `\bnpm_[A-Za-z0-9]{36,}` | `npm_` plus at least 36 body characters; no look-ahead |
| AWS access key id | `\bAKIA[0-9A-Z]{16}\b` | Exact `AKIA` plus 16 uppercase alphanumeric characters; no look-ahead |
| Google API key | `\bAIza[0-9A-Za-z_-]{35}\b` | Exact `AIza` plus 35 body characters; no look-ahead |
| Slack token | `\bxox[baprse]-[A-Za-z0-9-]{20,}` | Known `xox*` prefix plus at least 20 body characters; no look-ahead |
| Stripe live key | `\b[sr]k_live_[0-9a-zA-Z]{24,}` | `sk_live_` or `rk_live_` plus at least 24 body characters; no look-ahead |
| Anthropic API key | `\bsk-ant-[A-Za-z0-9_-]{30,}` | `sk-ant-` plus at least 30 body characters; no look-ahead |
| OpenAI API key | `\bsk-proj-[A-Za-z0-9_-]{40,}` | `sk-proj-` plus at least 40 body characters; no look-ahead |
| Vault/OpenBao token | `\bhv[sbr]\.[A-Za-z0-9_-]{24,}` | Known `hv*.` prefix plus at least 24 body characters; no look-ahead |
| PEM private key header | `-{5}BEGIN (?:[A-Z]+ )?PRIVATE KEY-{5}` | Header match; inspect the next 200 characters for a placeholder |

## Exemptions

These executable definitions are checked against the matcher implementation as
part of the same documentation-drift regression check. Keep the code-valued
cells exact when changing the exemption behavior.

| Exemption | Executable definition |
|---|---|
| Placeholder regex | `replace|example|your|dummy|placeholder|redact|changeme|todo|xxxx|\.\.\.` |
| Repeated-character body | `len(set(body)) <= 1` |
| Fixture line marker | `gitleaks:allow` |

The length floors are conservative by design. They are not claims that every
provider's credential has exactly that width; they are the minimums used to
avoid blocking token-type prose and short examples. The matcher returns the
first non-exempt match in pattern order and never prints the matched value.

## Extending the set

Use the checked-in built-ins for credential families that should be protected
for every installation. Use the operator-owned extra file for a local or
organization-specific shape:

```json
[
  {
    "label": "Acme API key",
    "pattern": "\\bacme_[A-Za-z0-9]{32}",
    "window": 0
  }
]
```

`label` and `pattern` are required. `window` is optional and defaults to zero;
when nonzero, it is the number of characters after the match in which the
placeholder exemption is checked. Keep the same high-signal bar as the
built-ins: use a known prefix or grammar and a real-width floor, and do not
add a generic high-entropy or bare-length rule. The file is loaded from
`~/.config/credential-guard/patterns.json` (or the equivalent
`XDG_CONFIG_HOME` path), appended after the built-ins. A missing file or a
loading/validation error is swallowed so the guard remains fail-open; if a
later entry is malformed, entries successfully read before that error remain
in the loaded set.

When a new credential shape should become built-in, follow this maintenance
path in one commit:

1. Confirm the format from the provider or from a concrete false-negative
   report. Record the stable vendor/product label and choose the narrowest
   regex that meets the high-signal bar.
2. Add one `(label, regex, window)` tuple to `BUILTIN_PATTERNS`. Use a
   zero-width window unless a format genuinely needs nearby text, such as the
   PEM body placeholder check.
3. Add runtime-built positive and placeholder/fixture cases to
   `hooks/test_credential_guard.py`. Do not put a real-looking credential
   literal in source; construct test values from fragments. If the change
   alters an exemption, update the matching row in the **Exemptions** table.
4. Update this inventory table and the README's supported-shape summary in
   the same commit. The documentation-drift tests compare both tables with
   the hook, so an intentional source change and its documentation update must
   land together. If the change is part of a released utility version, add a
   concise entry to `CHANGELOG.md` and publish a new `agent-secrets/vX.Y.Z`
   tag rather than silently changing an installed hook.
5. Run the hook suite and review false-positive behavior before release:

   ```bash
   python3 -m unittest discover -s agent-secrets/hooks -v
   ```

The regression suite pins matching and exemption behavior; this document
owns the inventory, the high-signal policy, and the process for changing it.
