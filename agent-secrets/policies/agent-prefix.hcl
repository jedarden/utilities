# One coding agent, one prefix. Replace PREFIX with the path this agent owns
# (e.g. "ardenone-cluster" or "team-x/app"). Nothing outside it is granted —
# not even list at the mount root — so a compromised agent token maps to one
# prefix, not the store.
#
# KV v2 splits data and metadata. The agent needs metadata read for
# verify-by-property (`bao kv metadata get` -> current_version) and metadata
# delete so it can retire a path it created.
path "secret/data/PREFIX/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/PREFIX/*" {
  capabilities = ["read", "list", "delete"]
}
