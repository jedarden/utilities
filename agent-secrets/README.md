# agent-secrets

The pieces that let a coding agent read and write a secrets store without a
credential value ever becoming text it produced. Three parts, each usable
alone:

| Part | What it does |
|---|---|
| `hooks/credential-guard.py` | Claude Code `PreToolUse` hook. Denies any Write / Edit / MultiEdit / NotebookEdit / Bash call whose body carries a high-signal credential shape (GitHub, GitLab, npm, AWS, Google, Slack, Stripe, Anthropic, OpenAI, Vault/OpenBao tokens, PEM private keys). Fails open. The [pattern inventory and update process](docs/credential-patterns.md) are part of this utility's contract. |
| `bin/bao-as` | `bao-as <instance> <command...>` — AppRole login to one named OpenBao/Vault instance with credentials passed as `@file`, then `exec` the command with the token only in its environment. |
| `policies/*.hcl` | Prefix-scoped policy templates: one agent ↔ one prefix, writer, reader, and the superuser carve-outs that deny `sys/audit*` and `sys/seal`. |

The rule they enforce, in one line: **secrets travel by reference, never by
value.** The store is not the thing being protected — the transcript is. A
value that appears in a command line, a tool result, or a file is logged,
cached, and unrecallable. Every part here keeps a value moving through file
descriptors nothing reads back.

Background: [*'Ignore .env' is not a defense*](https://jedarden.com/notes/ignore-env-is-not-a-defense/).

See [`CHANGELOG.md`](CHANGELOG.md) for release notes.

## License

The source files in this utility and the hook and wrapper files copied to user
hosts by `install.sh` are licensed under the MIT License. Installation does
not change that coverage. The installer does not copy a separate license file;
retain the repository's [LICENSE](../LICENSE) text when redistributing an
installed copy.

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
merges or upgrades the hook entry in `settings.json`. The entry is identified
by its exact command. The current shipped entry uses matcher
`Write|Edit|MultiEdit|NotebookEdit|Bash` and has no `timeout` field, so re-running `--wire`
is a no-op. The previous shipped matcher `Write|Edit|MultiEdit|Bash`, with no
timeout, is refreshed in place during an upgrade. The pre-`MultiEdit` matcher
`Write|Edit|Bash`, with or without a timeout, is not an in-place refresh
candidate and is treated as customized.

If a same-command entry has any other matcher or timeout, `--wire` preserves
the settings file byte-for-byte, writes exactly one `preserved` report to
stderr, and exits 2. The report has this form:
`preserved  <settings-path>: existing <exact-command> wiring is customized;
use --wire --force to replace its matcher/timeout (exit 2)`. The installer's
stdout may still contain the ordinary hook/provenance installation messages;
the customization report is never sent to stdout. Exit 2 is therefore a
customization conflict, not a successful warning. `--wire --force` exits 0 and
replaces the matcher and timeout fields on every matching exact-command entry
with this release's fields (matcher `Write|Edit|MultiEdit|NotebookEdit|Bash`, no timeout),
while preserving each command, handler type, other fields, and unrelated
settings. If the command is absent, the entry is appended.

The settings merge is protected by an exclusive advisory lock at
`$CLAUDE_SETTINGS.lock` (or `~/.claude/settings.json.lock`), which is kept so
concurrent `--wire` runs use the same lock. The lock covers reading, merging,
backup creation, and replacement. Each changed file is written to a uniquely
named temporary file in the settings file's directory, flushed, and
atomically renamed into place; an interruption before the rename leaves the
live file complete. The temporary name includes `agent-secrets`, and each run
reaps only its own leftover `.tmp` files while holding the lock. Normal errors
and HUP/INT/TERM interruptions remove the current temporary file; a hard kill
can leave one for the next `--wire` run to reap. Rewriting an existing file
preserves its permission bits,
including mode `0600`. If the settings file does not exist, `--wire` creates it
with mode `0600`, regardless of the process umask. If the two utility
installers run concurrently, the
second waits and rereads the first result, preserving both hook entries and
unrelated settings. Manual writers that do not honor the same advisory lock
must not edit the file during a wire; their races are outside this guarantee.

The lock file is created lazily with mode `0600` (and is corrected to that
mode if it already exists). The kernel lock belongs to the wiring process, not
to the pathname: normal exit, an exception, or a crash releases it, while the
empty `.lock` file may remain. A leftover lock file is stale metadata, not a
permanent block; a later `--wire` opens and acquires it normally. A wire that
cannot create the lock, or cannot acquire it within 30 seconds, prints a
refusal to stderr, exits nonzero, and does not modify the settings file. Set
`CLAUDE_SETTINGS_LOCK_TIMEOUT` to a different positive number when an
environment needs a different finite deadline; waiting is never indefinite.
`--uninstall` uses the same lock and deadline before removing the lock file,
then removes it if present. If the lock cannot be acquired or removed,
uninstall aborts before removing installed files.

Every successful install writes JSON provenance to
`~/.claude/hooks/agent-secrets/provenance.json` (or the corresponding
`CLAUDE_HOOKS_DIR`). It contains this utility's `VERSION`, the runtime
requirement `"runtime": {"python3": ">=3.9"}`, and an empty `bundles` list.
Query the installed copy without changing anything with:

```bash
./agent-secrets/install.sh --status
```

The command prints that JSON and exits nonzero when no provenance record is
present. A forced reinstall reports the previously installed utility version
before replacing the hook, wrapper, and provenance record. `--uninstall`
removes the provenance record with those installed files.

### Installed runtime prerequisite

The installed credential guard is wired as `python3
~/.claude/hooks/credential-guard.py`, so the host must provide a working
`python3` command at version 3.9 or newer. `install.sh` checks this before
copying or wiring anything and aborts with a warning when the interpreter is
missing, cannot start, or is too old. `--status` remains available without a
working Python interpreter and reports the requirement from the provenance
record.

If an already-installed hook is run on a host without that prerequisite, the
interpreter fails before the hook starts. The guard emits no denial or hook
diagnostic; its fail-open contract allows the tool call to proceed, so
credential protection is absent until Python 3.9 or newer is restored.

`CLAUDE_SETTINGS` defaults to `~/.claude/settings.json` and is used literally
for `--wire`. An absolute value is used as an absolute path. A relative value
is resolved against the installer's current working directory, not against the
utility checkout or `$HOME`; use the same working directory as well as the
same value on every run. The settings parent directory must already exist:
the settings step exits nonzero without creating a missing parent, settings
file, lock, or backup. The utility destinations may already have been copied
before that failed settings step, so retry after fixing the path.

Symlinks in the path are resolved before the settings file is read, locked,
backed up, or replaced. A final-component symlink is preserved and its target
is updated; the target's directory receives the `.lock`, temporary file, and
`.bak`. The target must be writable, and its parent must exist.

The two installers do not coordinate different settings files. If one run
uses path A and a later run uses distinct path B, each file receives only the
entry for the utility run against it, and each existing file gets its own
one-time pre-wiring `.bak`. Neither backup is a rollback point for the
combined installation. To compose both guards and retain one rollback point,
run both installers against the same effective settings target (the same path
or symlink-resolved target) every time.

When `--wire` changes an existing settings file, it creates
the effective settings target's `.bak` (normally
`$CLAUDE_SETTINGS.bak`, or `~/.claude/settings.json.bak`) immediately before
the first wiring change, but only if that backup does not already exist. For a
symlinked settings value, this is beside the resolved target, as described
above. The backup therefore remains the pre-wiring settings file when another
utility is wired later or this installer is run again. If the settings file
does not yet exist, no backup is created because there is no prior file to
preserve.

The `.bak` is a permanent, one-time pre-wiring snapshot rather than a rolling
backup. `--wire` and `--uninstall` never rewrite or remove an existing backup.
Inspect a suspected bad wire with:

```bash
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
diff -u "$SETTINGS.bak" "$SETTINGS"
```

After reviewing the diff, restore the whole pre-wiring file with
`cp -p "$SETTINGS.bak" "$SETTINGS"`, or merge only the wiring changes if
later settings edits must be kept. The installer gives the backup
the source file's permission bits, so a mode-`0600` settings file produces a
mode-`0600` backup. Delete the backup only after the live settings are verified
and this rollback point is no longer needed; the next wiring change creates a
new snapshot when no backup is present.

If an existing settings file is malformed JSON, or its top-level value is not
an object, `--wire` creates the pre-wiring `.bak` when it is owed, prints a
clear refusal to stderr, exits nonzero, and leaves the settings file
byte-for-byte unchanged. It never appends a hook entry to such a file.

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
`new_string`, each entry of a MultiEdit `edits` array, a NotebookEdit
`new_source`, or a Bash `command` — and
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

The state directory is created with mode `0700`, and the active log, one
rotated backup at `denials.jsonl.1`, and advisory lock are created with mode
`0600`, regardless of the caller's umask. These private modes keep concurrent
hook metadata from being exposed or records from interleaving. On later writes,
the hook may tighten an existing path to these private modes, but it never
loosens an existing log's permissions. Each record is property-only and
contains `ts`, `rule_id`, `tool`, `cwd`, `session_id`, and `payload_shape`. The
shape is a fixed label such as `Bash.command`, `Write.content`,
`Edit.new_string`, or `MultiEdit.edits[].new_string`. The command, file path,
matched text, pattern label, and credential value are never written. Logging is
best-effort: an unwritable log never turns a deny into an allow.

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

### CLI compatibility contract

`BAO_AS_BIN` selects only the executable used for the AppRole login. When it is
unset or empty, `bao-as` uses `bao`; a non-empty value is used as an executable
name resolved through `PATH` or as a path. There is no fallback to `bao` when
an override is missing, non-executable, or incompatible. The selected
executable must accept this exact login invocation and print only a non-empty
token on stdout:

```
<cli> write -field=token auth/approle/login \
  role_id=@<role_id-file> secret_id=@<secret_id-file>
```

The CLI must support `write`, `-field=token`, the AppRole login endpoint, and
the `key=@file` argument form. The wrapper supplies both `BAO_ADDR` and
`VAULT_ADDR` for login, then exports the returned value as both
`BAO_TOKEN` and `VAULT_TOKEN` to the child. A missing or non-executable
selected CLI exits with `EX_UNAVAILABLE` (69); a failed login or an empty
token exits with `EX_NOPERM` (77). In either case the requested child is not
started and `bao` is never tried as a fallback.

The command after the instance is passed through unchanged. `BAO_AS_BIN` does
not rewrite `bao` to `vault` (or vice versa), and `bao-as` does not inspect or
translate that command's flags. A caller using the selected CLI must therefore
use its own KV-v2 command surface:

```bash
# OpenBao path-style forms used by this utility's examples.
bao-as "$instance_name" bao kv metadata get -format=json secret/app/db
openssl rand -base64 32 | bao-as "$instance_name" bao kv put \
  -cas=3 secret/app/db password=-
bao-as "$instance_name" bao kv get -field=token secret/app/api

# Vault: use explicit mount and secret path forms to avoid KV-v2 path
# detection differences between CLI versions.
bao-as "$instance_name" vault kv metadata get -mount=secret -format=json app/db
openssl rand -base64 32 | bao-as "$instance_name" vault kv put \
  -mount=secret -cas=3 app/db password=-
bao-as "$instance_name" vault kv get -mount=secret -field=token app/api
```

For this contract, `kv get` must support `-field` and `-format=json`, `kv put`
must support `-cas=N` and stdin values such as `password=-`, and `kv metadata
get` must support `-format=json` with the current version at
`.data.current_version`. `-cas=0` is create-only; a positive value must match
the current version. Pass an explicit CAS value rather than relying on a
CLI/backend default. `kv metadata get` reports version metadata; it does not
replace `kv put`'s CAS check.

HashiCorp documents the explicit `-mount` KV syntax as available in Vault 1.11
and later; older Vault versions require the deprecated path-like form. That is
a syntax floor for the Vault example, not a tested release floor: this
repository's tests use stubs and do not run a Vault binary or contact a Vault
server. Validate the installed Vault version and the target mount separately
before using it. See the [Vault KV command documentation](https://developer.hashicorp.com/vault/docs/commands/kv),
[`kv put` CAS options](https://developer.hashicorp.com/vault/docs/commands/kv/put),
and [AppRole CLI login](https://developer.hashicorp.com/vault/docs/auth/approle)
for the upstream command details.

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
