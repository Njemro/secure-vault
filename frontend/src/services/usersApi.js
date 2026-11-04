// User-related API client (public keys, key material and developers).
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

/** Fetch active developers who have registered public keys. */
export async function listDevelopers() {
  const res = await authenticatedFetch(`${BASE}/developers`)

  return readJson(res)
}
/** Admin: list all registered user accounts. */
export async function listAdminUsers() {
  const res = await authenticatedFetch(`${BASE}`)
  return readJson(res)
}
export async function getAdminUser(userId) {
  const res = await authenticatedFetch(`${BASE}/${encodeURIComponent(userId)}`)
  return readJson(res)
}
export async function updateAdminUserRole(userId, role) {
  const res = await authenticatedFetch(`${BASE}/${encodeURIComponent(userId)}/role`, {
    method: 'PUT', body: { role },
  })
  return readJson(res)
}
export async function updateAdminUserStatus(userId, status) {
  const res = await authenticatedFetch(`${BASE}/${encodeURIComponent(userId)}/status`, {
    method: 'PUT', body: { status },
  })
  return readJson(res)
}
