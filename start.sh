#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration parameters
# You can override these by setting them as environment variables before running,
# e.g.: PORT=9090 PUBLIC_URL=https://my-domain.com ./start.sh
# -----------------------------------------------------------------------------
PORT="${PORT:-8080}"
BIND="${BIND:-127.0.0.1}"
PUBLIC_URL="${PUBLIC_URL:-http://localhost:8080}"

# Internal paths
DATA_DIR="data"
DB_FILE="${DATA_DIR}/roundtable.db"
KEY_FILE="${DATA_DIR}/signing-key"

# Ensure data directory exists
mkdir -p "${DATA_DIR}"

# Generate a persistent 32-byte signing key if one doesn't exist
if [ ! -f "${KEY_FILE}" ]; then
    echo "Generating new secure signing key at ${KEY_FILE}..."
    head -c 32 /dev/urandom | base64 > "${KEY_FILE}"
    chmod 600 "${KEY_FILE}"
fi

echo "Starting neo-roundtable on ${BIND}:${PORT}..."
echo "Public URL: ${PUBLIC_URL}"

# Use 'exec' so that the go binary replaces the bash process,
# allowing it to properly receive OS signals (like SIGTERM for graceful shutdown).
exec ./roundtable serve \
    -db "${DB_FILE}" \
    -signing-key-file "${KEY_FILE}" \
    -public-url "${PUBLIC_URL}" \
    -bind "${BIND}" \
    -port "${PORT}"
