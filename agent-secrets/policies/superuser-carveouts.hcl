# Attach ALONGSIDE any broad "everything" policy given to an agent or a
# reconciler. `deny` wins over any other capability on the same path, so
# these hold even under `path "*" { capabilities = ["sudo", ...] }`.
#
# Why: complete access is sometimes the honest grant for a reconciler that
# manages the store's own config. That grant is only acceptable because two
# compensating controls exist — an audit ledger and off-store snapshots. An
# identity that can switch off its own audit device voids the first; one
# that can seal the store can hold it hostage. Carve both out before
# granting anything else.
path "sys/audit"             { capabilities = ["deny"] }
path "sys/audit/*"           { capabilities = ["deny"] }
path "sys/config/auditing/*" { capabilities = ["deny"] }
path "sys/seal"              { capabilities = ["deny"] }
path "sys/step-down"         { capabilities = ["deny"] }
