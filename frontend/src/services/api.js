// API service layer for Secure Vault.
// All functions return promises. The Gateway base URL is read from Vite env
// (VITE_API_BASE_URL). Keycloak direct-grant calls go to the configured
// Keycloak base. No secrets are stored here.

const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api'
const KEYCLOAK_BASE = 'http://localhost:8080'
const KEYCLOAK_REALM = 'secure-vault'
const KEYCLOAK_CLIENT_ID = 'admin-cli'

// ---------------------------------------------------------------------------
// Authenticated fetch helper
// ---------------------------------------------------------------------------

/** Fetch with an optional Bearer token. Returns the Response object. */
export async function authenticatedFetch(url, { token, ...init } = {}) {
  const headers = { ...(init.headers || {}) }
  if (token) {
    headers.Authorization = `Bearer ${token}`
  }
  const res = await fetch(url, { ...init, headers })
  return res
}

/** Read JSON body from a response, throwing a descriptive error on failure. */
export async function readJson(res) {
  let body
  try {
    body = await res.json()
  } catch {
    body = {}
  }
  if (!res.ok) {
    throw new Error(body.message || `Request failed (${res.status})`)
  }
  return body
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/** Register a new account: Keycloak user + local provisioning. */
export async function register({ username, email, keycloakPassword }) {
  const res = await fetch(`${API_BASE}/auth/register`, {
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
  const res = await authenticatedFetch(`${API_BASE}/users/keys`, {
    token: accessToken,
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
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
  const res = await authenticatedFetch(`${API_BASE}/users/me/keys`, {
    token: accessToken,
  })
  if (res.status === 404) return null
  if (!res.ok) {
    throw new Error(`Failed to fetch keys (${res.status})`)
  }
  return res.json()
}

// ---------------------------------------------------------------------------
// Authentication (login / MFA via Gateway)
// ---------------------------------------------------------------------------

/** First-factor login: returns accessToken (or null if MFA is required). */
export async function login({ username, password }) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  return readJson(res)
}

/** Second-factor: verify TOTP code using a temporary token. */
export async function verifyMfa(tempToken, code) {
  const res = await authenticatedFetch(`${API_BASE}/auth/mfa/verify`, {
    token: tempToken,
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  })
  return readJson(res)
}

/** Fetch the authenticated user's key material (alias for getMyKeys). */
export async function getMyKeysV2(token) {
  const res = await authenticatedFetch(`${API_BASE}/users/me/keys`, { token })
  if (res.status === 404) return null
  if (!res.ok) {
    throw new Error(`Failed to fetch keys (${res.status})`)
  }
  return res.json()
}

/** Fetch a user's public key (for sharing). */
export async function getPublicKey(token, userId) {
  const res = await authenticatedFetch(`${API_BASE}/users/${userId}/public-key`, {
    token,
  })
  return readJson(res)
}