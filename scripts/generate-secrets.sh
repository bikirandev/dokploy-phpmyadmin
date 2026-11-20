#!/bin/sh
# Prints fresh random secrets for Dokploy's Environment tab.
# Keep a copy of VAULT_KEY somewhere safe (a password manager): without it, saved
# database passwords cannot be decrypted after a restore.
set -eu
echo "VAULT_KEY=$(openssl rand -base64 32)"
echo "GATEWAY_TOKEN=$(openssl rand -hex 32)"
echo "PMA_TOKEN=$(openssl rand -hex 32)"
echo "PGA_TOKEN=$(openssl rand -hex 32)"
