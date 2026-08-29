# agent-secrets

The pieces that let a coding agent read and write a secrets store without a
credential value ever becoming text it produced. Three parts, each usable
alone:

| Part | What it does |
|---|---|
| `hooks/credential-guard.py` | Claude Code `PreToolUse` hook. Denies any Write / Edit / MultiEdit / Bash call whose body carries a high-signal credential shape (GitHub, GitLab, npm, AWS, Google, Slack, Stripe, Anthropic, OpenAI, Vault/OpenBao tokens, PEM private keys). Fails open. |
| `bin/bao-as` | `bao-as <instance> <command...>` — AppRole login to one named OpenBao/Vault instance with credentials passed as `@file`, then `exec` the command with the token only in its environment. |
| `policies/*.hcl` | Prefix-scoped policy templates: one agent ↔ one prefix, writer, reader, and the superuser carve-outs that deny `sys/audit*` and `sys/seal`. |

The rule they enforce, in one line: **secrets travel by reference, never by
value.** The store is not the thing being protected — the transcript is. A
value that appears in a command line, a tool result, or a file is logged,
cached, and unrecallable. Every part here keeps a value moving through file
descriptors nothing reads back.

Background: [*'Ignore .env' is not a defense*](https://jedarden.com/notes/ignore-env-is-not-a-defense/).

## Install

```bash
git clone https://github.com/jedarden/utilities ~/utilities
~/utilities/agent-secrets/install.sh --wire     # copies the hook + bao-as, adds the PreToolUse entry
```

Without `--wire` the script prints the `settings.json` snippet instead of
editing anything. `--uninstall` removes what it installed. Python 3 and bash
are the only dependencies; `bao-as` additionally needs the `bao` (or `vault`,
via `BAO_AS_BIN=vault`) CLI.

Run the tests:

```bash
python3 -m unittest discover -s ~/utilities/agent-secrets/hooks -v
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

Pair it with a server-side secret scan on your git host (Forgejo/Gitea
`pre-receive`, GitHub push protection, gitleaks). Two independent detectors
between an agent's slip and the public internet is the point; either alone
is one bug away from nothing.

## bao-as

```
~/.config/bao-as/instances.conf     <name> <address>, one per line
~/.config/bao-as/<name>/role_id     mode 0600
~/.config/bao-as/<name>/secret_id   mode 0600
```

```bash
bao-as prod bao kv metadata get secret/app/db          # verify by property: current_version
openssl rand -base64 32 | bao-as prod bao kv put -cas=3 secret/app/db password=-
bao-as prod bao kv get -field=token secret/app/api > ~/.config/app/token   # to a 0600 file, never stdout
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

`PREFIX` in each file is the path this identity owns. Replace it, then
`bao policy write <name> <file>`.

- `agent-prefix.hcl` — the interactive agent: create/read/update/delete on
  its prefix, plus metadata read (for `current_version`) and metadata delete.
- `writer-prefix.hcl` — an automated writer (sync, backup, replicator): its
  own prefix, no delete. Two writers cannot read each other's output.
- `reader-prefix.hcl` — a consumer that resolves by reference (External
  Secrets Operator, a deploy): read and list only. Bind to a short-TTL
  Kubernetes-auth role, not a static token.
- `superuser-carveouts.hcl` — attach alongside any broad policy. `deny` wins
  over `sudo`, so an identity with "everything" still cannot disable the
  audit device or seal the store.

Turn on check-and-set for the mount so racing writers get a 400 instead of a
silent overwrite: `bao write secret/config cas_required=true max_versions=20`.

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
