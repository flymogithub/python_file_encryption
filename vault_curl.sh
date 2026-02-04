#!/bin/bash

VAULT_ADDR="https://vault.local:8200"
TOKEN=""
CERT_FILE="/etc/vault-client/mike/mike.pem"
CA_CERT="/etc/vault-client/mike/vault-server-ca.pem"

jq -Rs --arg policies "encryption" --arg name "mike" \
  '{certificate: ., policies: $policies, display_name: $name}' \
  "$CERT_FILE" | \
curl -s \
  --header "X-Vault-Token: $TOKEN" \
  --cacert "$CA_CERT" \
  --request POST \
  --data @- \
  "$VAULT_ADDR/v1/auth/cert/certs/mike"

