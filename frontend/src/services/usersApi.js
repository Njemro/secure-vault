// User-related API client (public keys, key material).
import { authenticatedFetch, readJson } from './api.js'

const BASE = '/users'

/** Register or replace the authenticated user's key material. */
export async function registerKeys(keyMaterial) {
  const res = await authenticatedFetch(`${BASE}/keys`, {
    method: 'PUT',
    body: keyMaterial,
  })

  if (res.status === 204) return null

  return readJson(res)
}

/** Fetch the authenticated user's key material. */
export async function getMyKeys() {
  const res = await authenticatedFetch(`${BASE}/me/keys`)

  if (res.status === 404) return null

  return readJson(res)
}

/** Fetch a user's public key (for sharing). */
export async function getPublicKey(userId) {
  const res = await authenticatedFetch(
    `${BASE}/${encodeURIComponent(userId)}/public-key`
  )

  return readJson(res)
}