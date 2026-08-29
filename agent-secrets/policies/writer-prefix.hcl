# An automated writer (a sync job, a backup exporter, a replicator) gets
# exactly the prefix it produces. No delete: a writer that can delete can be
# tricked into deleting. Two writers with different prefixes cannot read each
# other's output.
path "secret/data/PREFIX/*" {
  capabilities = ["create", "read", "update", "list"]
}
path "secret/metadata/PREFIX/*" {
  capabilities = ["read", "list"]
}
