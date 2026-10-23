// API service layer for Secure Vault registration and key management.
// All functions return promises. Base URLs are configurable via
// import-time constants; no secrets are stored here.

const BACKEND_BASE = 'http://localhost:8000/api'   // via gateway
const KEYCLOAK_BASE = 'http://localhost:8080'      // direct Keycloak access
const KEYCLOAK_REALM = 'secure-vault'
const KEYCLOAK_CLIENT_ID = 'admin-cli'

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/** Register a new account: Keycloak user + local provisioning. */
export async function register({ username, email, keycloakPassword }) {
  const res = await fetch(`${BACKEND_BASE}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, keycloakPassword }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.message || `Registration failed (${res.status})`)
  }
  return res.json()
}

/**
 * Obtain a Keycloak JWT via the direct grant API.
 * Used immediately after registration so the client can call authenticated
 * endpoints (key registration). The Keycloak login password and the vault
 * master password are logically separate - this only handles the former.
 */
export async function loginWithKeycloak(username, password) {
  const form = new URLSearchParams()
  form.append('grant_type', 'password')
  form.append('client_id', KEYCLOAK_CLIENT_ID)
  form.append('username', username)
  form.append('password', password)

  const res = await fetch(
    `${KEYCLOAK_BASE}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
    }
  )
  if (!res.ok) {
    throw new Error('Keycloak login failed')
  }
  const data = await res.json()
  return data.access_token
}

// ---------------------------------------------------------------------------
// Key registration (existing backend endpoint: PUT /api/users/keys)
// ---------------------------------------------------------------------------

/** Upload the client-encrypted key material to the backend. */
export async function registerKeys(accessToken, keyMaterial) {
  const res = await fetch(`${BACKEND_BASE}/users/keys`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify(keyMaterial),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.message || `Key registration failed (${res.status})`)
  }
  return res.ok
}

/** Fetch the authenticated user's key material (for checking if keys exist). */
export async function getMyKeys(accessToken) {
  const res = await fetch(`${BACKEND_BASE}/users/me/keys`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  })
  if (res.status === 404) return null
  if (!res.ok) {
    throw new Error(`Failed to fetch keys (${res.status})`)
  }
  return res.json()
}