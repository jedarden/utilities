# A consumer that only resolves secrets by reference (External Secrets
# Operator, a deploy job). Read and list, nothing else. Bind this to a
# short-TTL Kubernetes-auth role rather than a static token.
path "secret/data/PREFIX/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/PREFIX/*" {
  capabilities = ["read", "list"]
}
