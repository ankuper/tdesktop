#!/usr/bin/env bash
# gen-sandbox-secrets.sh — deterministic sandbox credential generator for
# story 2.10 E2E tests. Uses a fixed RNG seed so CI runs are reproducible.
# MUST NOT be used with production credentials.
#
# Outputs:
#   tdesktop/tests/fixtures/sandbox-secret        (AES-256 key, 32 bytes hex)
#   tdesktop/tests/fixtures/sandbox-type3-secret.hex  (Type3 secret: 0xff + 16 bytes hex)
#
# The generated credentials are test-only. They bear no relation to any
# deployed instance and MUST NOT be used on port 3129 (production).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Fixed seed string for reproducibility across CI runs.
SEED="teleproto3-story-2.10-sandbox-test-seed-v1"

# Generate 32-byte AES key deterministically using SHA-256 of the seed.
AES_KEY=$(printf '%s' "$SEED:aes" | openssl dgst -sha256 -hex | awk '{print $2}')
echo "$AES_KEY" > "$SCRIPT_DIR/sandbox-secret"

# Generate 16-byte Type3 key (0xff prefix makes it a Type3 secret).
T3_BYTES=$(printf '%s' "$SEED:type3" | openssl dgst -sha256 -hex | awk '{print $2}' | cut -c1-32)
echo "ff${T3_BYTES}" > "$SCRIPT_DIR/sandbox-type3-secret.hex"

echo "Sandbox credentials written to $SCRIPT_DIR"
echo "  sandbox-secret: $(cat "$SCRIPT_DIR/sandbox-secret")"
echo "  sandbox-type3-secret.hex: $(cat "$SCRIPT_DIR/sandbox-type3-secret.hex")"
echo "WARNING: These are test-only credentials. Do NOT use on production port 3129."
