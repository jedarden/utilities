# agent-secrets

The pieces that let a coding agent read and write a secrets store without a
credential value ever becoming text it produced. Three parts, each usable
alone:

| Part | What it does |
|---|---|
| `hooks/credential-guard.py` | Claude Code `PreToolUse` hook. Denies any Write / Edit / MultiEdit / Bash call whose body carries a high-signal credential shape (GitHub, GitLab, npm, AWS, Google, Slack, Stripe, Anthropic, OpenAI, Vault/OpenBao tokens, PEM private keys). Fails open. The [pattern inventory and update process](docs/credential-patterns.md) are part of this utility's contract. |
| `bin/bao-as` | `bao-as <instance> <command...>` — AppRole login to one named OpenBao/Vault instance with credentials passed as `@file`, then `exec` the command with the token only in its environment. |
| `policies/*.hcl` | Prefix-scoped policy templates: one agent ↔ one prefix, writer, reader, and the superuser carve-outs that deny `sys/audit*` and `sys/seal`. |

The rule they enforce, in one line: **secrets travel by reference, never by
value.** The store is not the thing being protected — the transcript is. A
value that appears in a command line, a tool result, or a file is logged,
cached, and unrecallable. Every part here keeps a value moving through file
descriptors nothing reads back.

Background: [*'Ignore .env' is not a defense*](https://jedarden.com/notes/ignore-env-is-not-a-defense/).

See [`CHANGELOG.md`](CHANGELOG.md) for release notes.

## Install

For a reproducible install, select the utility's release tag before running
the installer. The tag is the version selector; `install.sh` intentionally has
no separate `--version` flag. Keep a checkout per utility so pinning this
utility does not change the source revision used for another utility in the
monorepo:

```bash
git clone --branch agent-secrets/v0.1.0 --depth 1 \
  https://git.ardenone.com/jedarden/utilities.git ~/utilities-agent-secrets
~/utilities-agent-secrets/agent-secrets/install.sh --wire
```

The same command works with any released `agent-secrets/vX.Y.Z` tag. Without
`--wire` the script prints the `settings.json` snippet instead of editing
anything, and it never replaces a hook or `bao-as` copy already at a
destination without `--force`. `--wire` is the upgrade mode: it replaces the
installed hook and `bao-as` with the copies from the selected checkout and
merges the hook entry into `settings.json`.

Python 3 and bash are the only dependencies; `bao-as` additionally needs the
`bao` (or `vault`, via `BAO_AS_BIN=vault`) CLI.

### Pin, upgrade, and remove

To upgrade an existing tagged install, fetch the new release, check it out,
and run that release's installer with `--wire`:

```bash
cd ~/utilities-agent-secrets
git fetch --tags origin
git checkout --detach agent-secrets/vX.Y.Z
./agent-secrets/install.sh --wire
```

The installer preserves `~/.config/bao-as/`, including `instances.conf` and
the AppRole credential files. Review and commit any local changes in the
source checkout before changing tags; `git checkout` will refuse to overwrite
uncommitted work.

To remove the installed files, run `--uninstall` from the exact release
checkout that supplied them (or from the currently installed release after an
upgrade):

```bash
./agent-secrets/install.sh --uninstall
```

The uninstaller removes the hook and `bao-as` only when they still match this
checkout, refusing a hand-edited or unknown copy unless `--force` is supplied.
It intentionally leaves `settings.json`, `~/.config/bao-as/`, and the
credential denial log untouched.
After uninstalling, remove this utility's `PreToolUse` command from
`settings.json` yourself; keep the entry if another installed copy still uses
that same destination. The source checkout can then be deleted if it is no
longer needed.

Run the tests:

```bash
python3 -m unittest discover -s ~/utilities/agent-secrets/hooks -v     # credential-guard suite
python3 -m unittest discover -s ~/utilities/agent-secrets/bin -v       # bao-as suite (stub `bao`; contacts no store)
python3 -m unittest discover -s ~/utilities/agent-secrets/policies -v  # policy-template suite (HCL-subset check)
```

## The hook

Claude Code calls it before every matching tool use with the call's input on
stdin. It scans every text field a value could hide in — `content`,
`new_string`, each entry of a MultiEdit `edits` array, a Bash `command` — and
prints a deny decision if a pattern matches. The deny message tells the agent
what to do instead (write the path, use a pipe or `@file`, record the result
of a check rather than the credential).

What passes, deliberately:

- **Documentation stand-ins.** A token whose body is one repeated character
  (`ghp_xxxxxxxx…`), or one sitting next to `example`, `REPLACE`, `your`,
  `dummy`, `placeholder`, `redact`, `changeme`, `todo`, `xxxx`, `...`.
- **Prose that names a token type** without a value — "rotate the `ghp_` token".
  Every pattern has a vendor prefix *and* a length floor at the real width.
- **Lines marked `gitleaks:allow`** — deliberate test fixtures.
- **PEM templates** whose body is a placeholder on the following line.

What it does **not** do, and you should know:

- **It fails open.** Malformed input, an internal error, anything unexpected
  → allow. A guard that wedges the agent gets worked around; the rule binds
  the agent whether or not the hook fires.
- **It cannot see tool output.** An agent that `cat`s a secret has leaked it
  and nothing here stopped it. The defense on that side is habit: check
  presence (`wc -c`, `md5sum`, `-field=x | wc -c`), never print. Truncation
  (`head -c 100`) is not redaction.
- **It is narrow on purpose.** Generic high-entropy detection produces false
  denies on hashes, UUIDs and base64 blobs, and a false deny blocks real work.
  Add your own vendor shapes in `~/.config/credential-guard/patterns.json`:

  ```json
  [{"label": "Acme API key", "pattern": "\\bacme_[A-Za-z0-9]{32}"}]
  ```

The built-in labels, exact regexes, definition of “high-signal,” and the
maintenance path for adding a new credential family are documented in the
[credential-guard pattern inventory](docs/credential-patterns.md). Keep that
document synchronized with `hooks/credential-guard.py` when changing the
matcher.

Pair it with a server-side secret scan on your git host (Forgejo/Gitea
`pre-receive`, GitHub push protection, gitleaks). Two independent detectors
between an agent's slip and the public internet is the point; either alone
is one bug away from nothing.

## Composing with org-rule-guard

This utility is an optional companion to `org-rule-guard`, not a runtime
dependency of it. The org guard keeps a standalone credential fallback; when
Phase 3(b) reuses this hook, it may do so only through the checked-in,
version-pinned install-time bundle declared by `org-rule-guard`'s
`bundled-dependencies.json`. That installer copies this hook into its own
installed layout, so no installed code looks up this utility at runtime. This
hook adds a broader pattern set and optional extra patterns when both are
installed. Wire both independent entries with the checked-in
[`../docs/examples/settings-both.json`](../docs/examples/settings-both.json)
example, or run both installers' `--wire` modes against the same settings file.

Claude Code runs matching `PreToolUse` handlers in parallel, and a deny wins
over an allow. Therefore the JSON entry order does not establish precedence.
If both guards recognize one credential, the tool call is blocked once even
though both handlers may return a deny. Each guard records its own decision:
`org-rule-guard` writes its redacted-fragment record, while this hook writes a
property-only record to its own log. This is an expected pair of audit records,
not two tool executions or two permission prompts. If this hook is not
installed, the org guard's bundled credential check still runs. If the org
guard is not installed, this hook still protects credentials but cannot enforce
the org-specific rules.

### Credential denial log

Every credential denial appends one JSONL record to:

```
${XDG_STATE_HOME:-~/.local/state}/credential-guard/denials.jsonl
```

The active log is bounded to 256 KiB with one rotated backup at
`denials.jsonl.1`; a mode-700 directory, mode-600 log files, and an advisory
lock keep concurrent hook processes from interleaving records. Each record is
property-only and contains `ts`, `rule_id`, `tool`, `cwd`, `session_id`, and
`payload_shape`. The shape is a fixed label such as `Bash.command`,
`Write.content`, `Edit.new_string`, or `MultiEdit.edits[].new_string`. The
command, file path, matched text, pattern label, and credential value are never
written. Logging is best-effort: an unwritable log never turns a deny into an
allow.

The log can be counted by rule with the same seven-day query used by the org
guard, changing only the directory:

```bash
LOG=${XDG_STATE_HOME:-$HOME/.local/state}/credential-guard/denials.jsonl
jq -r 'select(.ts >= $cutoff) | .rule_id' \
  --arg cutoff "$(date -u -d '7 days ago' +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v-7d +"%Y-%m-%dT%H:%M:%SZ")" \
  "$LOG" | sort | uniq -c | sort -rn
```

## bao-as

`bao-as` requires an instance table and two AppRole credential files for the
named instance. With the default settings, the layout is:

```
~/.config/bao-as/                    config directory (created mode 0700)
~/.config/bao-as/instances.conf     instance table (created mode 0600)
~/.config/bao-as/<name>/role_id     AppRole role ID (required, mode 0600)
~/.config/bao-as/<name>/secret_id   AppRole secret ID (required, mode 0600)
```

`instances.conf` is a whitespace-delimited two-column file. Each nonblank,
non-comment line has this schema:

```
<instance-name>  <BAO_ADDR>
```

The first field is the name passed to `bao-as <instance-name> ...`; the second
field is the complete OpenBao/Vault endpoint URL for that instance, including
the port when it is not the endpoint default. Names must not contain
whitespace. A blank line or a line whose first non-whitespace character is
`#` is ignored. Keep the table to two fields; fields after the address are not
configuration.

The requested name selects the matching row, and its address is exported as
both `BAO_ADDR` and `VAULT_ADDR` for the child command. The wrapper overwrites
any inherited values, so the table—not the caller's environment—chooses the
endpoint. Duplicate names are ambiguous; use each name once.

The installer creates the config directory with mode `0700` and the table
with mode `0600`. Credential files must be owner-only readable (`0600` is the
intended mode), and the per-instance directory should be `0700`. At runtime,
`bao-as` refuses to contact the CLI when either credential file is missing or
readable by group/other; this check happens before login. The table and
credential paths contain references only—the role and secret values must never
be put in `instances.conf`.

The config location and login CLI can be overridden without changing the
table schema:

| Setting | Effect |
|---|---|
| `BAO_AS_CONFIG_DIR` | Uses this directory as the config root. `instances.conf` and `<name>/` are read directly beneath it. |
| `XDG_CONFIG_HOME` | Changes the default parent to `$XDG_CONFIG_HOME/bao-as` when `BAO_AS_CONFIG_DIR` is unset. |
| `BAO_AS_BIN` | Selects the login executable; defaults to `bao`, and may be set to `vault`. |

There is no separate endpoint setting: the address in the selected table row
is used for that invocation. `BAO_AS_CONFIG_DIR` is a directory override, not
an override for the `instances.conf` filename.

Start from the placeholder-only file at
[`examples/bao-as-instances.conf`](examples/bao-as-instances.conf), replace
both placeholders, then create the matching credential directory and files:

```bash
config_root="${BAO_AS_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/bao-as}"
instance_name='replace-with-instance-name'
install -d -m 700 "$config_root/$instance_name"
chmod 600 "$config_root/$instance_name/role_id" \
  "$config_root/$instance_name/secret_id"
```

The installer seeds `instances.conf` once and never rewrites it, so adding or
changing an instance is an operator action.

```bash
bao-as "$instance_name" bao kv metadata get secret/app/db          # verify by property: current_version
openssl rand -base64 32 | bao-as "$instance_name" bao kv put -cas=3 secret/app/db password=-
bao-as "$instance_name" bao kv get -field=token secret/app/api > ~/.config/app/token   # to a 0600 file, never stdout
```

Why a wrapper at all: the `bao` CLI's token helper writes `~/.vault-token`,
which then silently applies to *every* instance and outlives the session.
`bao-as` never touches it. The token exists only in the child's environment
and dies with the command. Instances are independent token namespaces, and
you always say which one you mean.

Give the agent its own AppRole with a periodic, short-lived token and the
`agent-prefix.hcl` policy bound to its prefix — never a human's token, never
root:

```bash
bao auth enable approle
bao policy write agent-secrets policies/agent-prefix.hcl      # after replacing PREFIX
bao write auth/approle/role/coding-agent token_policies=agent-secrets token_period=1h
bao read -field=role_id auth/approle/role/coding-agent/role-id > ~/.config/bao-as/prod/role_id
bao write -field=secret_id -f auth/approle/role/coding-agent/secret-id > ~/.config/bao-as/prod/secret_id
chmod 600 ~/.config/bao-as/prod/*
```

(Both redirects go straight to a file. Neither value is ever printed.)

## Policies

Choose the narrowest policy that matches the identity. Capabilities from all
policies attached to a token are combined, so do not attach multiple
prefix-level policies unless that union is intentional.

| Identity | Template | Grant |
|---|---|---|
| Interactive coding agent | `agent-prefix.hcl` | Create/read/update/delete data under one prefix; read/list metadata and delete metadata for paths it owns. |
| Automated writer, sync, backup, or replicator | `writer-prefix.hcl` | Create/read/update data and read/list metadata under one prefix; no delete capability. |
| Reference-only consumer, such as External Secrets Operator or a deploy | `reader-prefix.hcl` | Read/list data and metadata under one prefix; use a short-TTL Kubernetes-auth role rather than a static token. |
| Reconciler that genuinely needs broad store access | `superuser-carveouts.hcl` alongside its broad policy | Denies the documented store-control paths even when another attached policy grants `sudo`. |

### Render and apply a prefix template

In the first three templates, `PREFIX` means a path relative to the `secret`
KV mount. For example, use `team-x/app`, not
`secret/data/team-x/app`, `secret/metadata/team-x/app`, or a path ending in
`/*`. Keep the same prefix in both the data and metadata paths. A prefix must
be non-empty, begin with a letter or digit, and contain only letters, digits,
`.`, `_`, `-`, and `/`; this also prevents the replacement from changing HCL
syntax.

Render a temporary copy so the shipped template remains unchanged. The
replacement below changes only the literal placeholder and rejects an unsafe
prefix before anything is sent to OpenBao:

```bash
instance_name='replace-with-instance-name'
role_name='replace-with-role-name'
template='agent-secrets/policies/agent-prefix.hcl' # choose one row above
prefix='team-x/app'                                # mount-relative
policy_name='agent-team-x-app'
rendered=$(mktemp)
trap 'rm -f "$rendered"' EXIT

python3 - "$template" "$rendered" "$prefix" <<'PY'
from pathlib import Path
import re
import sys

source, destination, prefix = sys.argv[1:]
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", prefix):
    raise SystemExit(
        "PREFIX must start with a letter/digit and contain only "
        "letters, digits, '.', '_', '-', and '/'"
    )
Path(destination).write_text(
    Path(source).read_text(encoding="utf-8").replace("PREFIX", prefix),
    encoding="utf-8",
)
PY

# Inspect paths and capabilities; this prints policy text only, never a secret.
awk '/^path / || /capabilities/' "$rendered"
bao-as "$instance_name" bao policy write "$policy_name" "$rendered"
```

Set `template` and `policy_name` to match the identity being provisioned.
Apply `agent-prefix.hcl`, `writer-prefix.hcl`, and `reader-prefix.hcl` with
the same rendering flow; only the selected grant table changes. Bind the
resulting policy to that identity's short-lived AppRole or Kubernetes-auth
role. Do not use a human or root token for the agent.

### Apply the superuser carve-outs

`superuser-carveouts.hcl` has no `PREFIX` placeholder and must not be narrowed,
rendered, or edited as part of the prefix flow. Load it unchanged as its own
policy, then attach it alongside the broad policy on the reconciler's role:

```bash
bao-as "$instance_name" bao policy write superuser-carveouts \
  agent-secrets/policies/superuser-carveouts.hcl
bao-as "$instance_name" bao write "auth/approle/role/$role_name" \
  token_policies="broad-reconciler,superuser-carveouts" token_period=1h
```

Preserve all five deny paths: `sys/audit`, `sys/audit/*`,
`sys/config/auditing/*`, `sys/seal`, and `sys/step-down`. The carve-out is
deny-only, not a replacement for the broad policy, and `deny` wins over
`sudo`. Do not replace the five paths with only `sys/audit*`; the auditing
configuration and step-down paths are separate controls.

Every template is checked by `policies/test_policies.py` against a small,
stdlib-only HCL subset and against the grant table above. This is a fast
structural check for the constructs these templates use, not a reimplementation
of OpenBao's loader: it currently accepts same-line object members without
commas, duplicate attributes, and boolean `required_parameters` items that the
OpenBao 2.5 loader rejects, while rejecting unquoted block labels that OpenBao
accepts. A passing suite therefore does not prove that arbitrary policy text
will pass `bao policy write`.

Before applying a rendered policy, run the real local parser on the disposable
copy (it formats the file in place):

```bash
bao policy fmt "$rendered"
```

The final authority is the target OpenBao instance when `bao policy write` is
run. The same suite pins each template to the grant table above; it does not
replace that real-loader check.

Turn on check-and-set for the mount so racing writers get a 400 instead of a
silent overwrite: `bao-as "$instance_name" bao write secret/config
cas_required=true max_versions=20`.

### Verify the effective policy safely

Run the policy-template suite before applying a change, then inspect the
rendered paths and capabilities. After binding the policy, ask OpenBao for
the effective capabilities of the exact short-lived identity; `-self` makes
the CLI use its environment token, so no token value is placed in argv:

```bash
python3 -m unittest discover -s agent-secrets/policies -v
check_path="$prefix/example"
bao-as "$instance_name" bao token capabilities -self \
  "secret/data/$check_path"
bao-as "$instance_name" bao token capabilities -self \
  "secret/metadata/$check_path"
bao-as "$instance_name" bao token capabilities -self \
  "secret/data/${prefix}-outside/example"
```

For a prefix policy, the first two checks should show the capabilities from
the selected row and the outside-prefix check should be denied (unless some
other deliberately attached policy grants it). For a role carrying the
carve-outs, verify that each fixed control path reports `deny`:

```bash
for denied_path in \
  sys/audit sys/audit/example sys/config/auditing/example \
  sys/seal sys/step-down; do
  bao-as "$instance_name" bao token capabilities -self "$denied_path"
done
```

`bao policy read -format=json <name>` is also safe for confirming the policy
definition because it returns ACL text, not secret data. To prove a KV entry
exists or to check CAS state, use metadata only:

```bash
bao-as "$instance_name" bao kv metadata get -format=json \
  "secret/$prefix/example" | jq -r '.data.current_version'
```

Never use `bao kv get` as a verification step, print a token, or put a token
in a command argument; check capabilities, metadata, exit status, or byte
counts instead.

## Verify by property, never by value

Every proof of success in this kit is something that demonstrates a value
without showing it:

| Instead of | Do |
|---|---|
| `bao kv get secret/app/db` | `bao kv metadata get -format=json secret/app/db \| jq .data.current_version` |
| printing a token to see if it works | run the call that needs it with the token in its env, report the HTTP status |
| reading a synced Secret back | `kubectl get externalsecret app -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'` |
| revoking a token by value | `bao token revoke -accessor <accessor>` |
| `head -c 100` | `wc -c` / `md5sum` |

If a check would need to print the thing to succeed, the check is wrong.

## Not covered here

Unseal, backup and restore, and an immutable audit sink are the store's own
hardening and are out of scope for this folder. The hook is also blind to tool
*output*; a PostToolUse redactor is an open question in `docs/plan/plan.md`.
