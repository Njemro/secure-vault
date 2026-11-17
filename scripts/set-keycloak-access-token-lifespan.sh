
#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

# Load project environment variables.
if [[ -f "${PROJECT_DIR}/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${PROJECT_DIR}/.env"
    set +a
fi

# Keycloak configuration.
KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-${KEYCLOAK_SERVER_URL:-http://localhost:8080}}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-secure-vault}"
KEYCLOAK_ADMIN_CLIENT_ID="${KEYCLOAK_ADMIN_CLIENT_ID:-secure-vault-admin}"
KEYCLOAK_ACCESS_TOKEN_LIFESPAN_SECONDS="${KEYCLOAK_ACCESS_TOKEN_LIFESPAN_SECONDS:-60}"

# Remove trailing slash.
KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL%/}"

# Validate required configuration.
: "${KEYCLOAK_ADMIN_CLIENT_SECRET:?Set KEYCLOAK_ADMIN_CLIENT_SECRET in .env}"

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required. Install jq first."
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl is required."
    exit 1
fi

if ! [[ "$KEYCLOAK_ACCESS_TOKEN_LIFESPAN_SECONDS" =~ ^[0-9]+$ ]] ||
   (( KEYCLOAK_ACCESS_TOKEN_LIFESPAN_SECONDS < 1 )); then
    echo "ERROR: KEYCLOAK_ACCESS_TOKEN_LIFESPAN_SECONDS must be a positive integer."
    exit 1
fi

TOKEN_URL="${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token"
ADMIN_API_URL="${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}"

echo "=========================================="
echo " Secure Vault - Keycloak Access Token"
echo "=========================================="
echo "Realm: ${KEYCLOAK_REALM}"
echo "New access token lifespan: ${KEYCLOAK_ACCESS_TOKEN_LIFESPAN_SECONDS}s"
echo

# Step 1: Obtain service-account access token.
echo "[1/3] Authenticating service account..."

TOKEN_RESPONSE=$(curl --fail-with-body --silent --show-error \
    --request POST \
    --user "${KEYCLOAK_ADMIN_CLIENT_ID}:${KEYCLOAK_ADMIN_CLIENT_SECRET}" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=client_credentials" \
    "${TOKEN_URL}") || {
        echo
        echo "ERROR: Could not authenticate service account."
        echo "Check client ID, client secret and service account configuration."
        exit 1
    }

ADMIN_TOKEN=$(printf '%s' "$TOKEN_RESPONSE" | jq -r '.access_token // empty')

if [[ -z "$ADMIN_TOKEN" ]]; then
    echo "ERROR: Keycloak did not return an access token."
    exit 1
fi

echo "Service account authentication successful."
echo

# Step 2: Read current realm configuration.
echo "[2/3] Reading realm configuration..."

REALM_JSON=$(curl --fail-with-body --silent --show-error \
    --header "Authorization: Bearer ${ADMIN_TOKEN}" \
    --header "Accept: application/json" \
    "${ADMIN_API_URL}") || {
        echo
        echo "ERROR: Could not read realm configuration."
        echo "Check service-account permissions."
        exit 1
    }

CURRENT_LIFESPAN=$(printf '%s' "$REALM_JSON" | jq -r '.accessTokenLifespan // empty')

if [[ -z "$CURRENT_LIFESPAN" ]]; then
    echo "ERROR: Could not determine current access token lifespan."
    exit 1
fi

echo "Current lifespan: ${CURRENT_LIFESPAN}s"
echo

# Step 3: Update only accessTokenLifespan.
echo "[3/3] Updating access token lifespan..."

UPDATED_REALM=$(printf '%s' "$REALM_JSON" | jq \
    --argjson lifespan "$KEYCLOAK_ACCESS_TOKEN_LIFESPAN_SECONDS" \
    '.accessTokenLifespan = $lifespan')

curl --fail-with-body --silent --show-error \
    --request PUT \
    --header "Authorization: Bearer ${ADMIN_TOKEN}" \
    --header "Content-Type: application/json" \
    --data "$UPDATED_REALM" \
    "${ADMIN_API_URL}" || {
        echo
        echo "ERROR: Could not update realm configuration."
        echo "Check service-account permissions."
        exit 1
    }

echo
echo "=========================================="
echo " SUCCESS"
echo "=========================================="
echo "Realm: ${KEYCLOAK_REALM}"
echo "Previous lifespan: ${CURRENT_LIFESPAN}s"
echo "New lifespan: ${KEYCLOAK_ACCESS_TOKEN_LIFESPAN_SECONDS}s"
echo
echo "Only accessTokenLifespan was changed."
echo "MFA and other realm settings were not modified."
echo "The setting remains active until changed again."
