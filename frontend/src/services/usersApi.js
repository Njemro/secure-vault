// User-related API client (public keys, key material).
import { authenticatedFetch, readJson } from './api.js'

const BASE = `${import.meta.env.VITE_API_BASE_URL || '/api'}/users`

/** Register or replace the authenticated user's key material. */
export async function registerKeys(token, keyMaterial) {
  const res = await authenticatedFetch(`${BASE}/keys`, {
    token,
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(keyMaterial),
  })
  if (res.status === 204) return
  return readJson(res)
}

/** Fetch the authenticated user's key material. */
export async function getMyKeys(token) {
  const res = await authenticatedFetch(`${BASE}/me/keys`, { token })
  if (res.status === 404) return null
  return readJson(res)
}

/** Fetch a user's public key (for sharing). */
export async function getPublicKey(token, userId) {
  const res = await authenticatedFetch(`${BASE}/${userId}/public-key`, { token })
  return readJson(res)
}