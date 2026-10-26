// Secret CRUD and sharing API client.
// All calls go through the Gateway (VITE_API_BASE_URL). Binary fields
// (IVs, ciphertext, wrapped DEKs) are Base64 strings at the JSON boundary and
// are converted to/from Uint8Array by the caller.
import { authenticatedFetch, readJson } from './api.js'

const BASE = `${import.meta.env.VITE_API_BASE_URL || '/api'}/secrets`

/** List secrets owned by the authenticated user. */
export async function listSecrets(token) {
  const res = await authenticatedFetch(BASE, { token })
  return readJson(res)
}

/** Get one owned secret by id. */
export async function getSecret(token, id) {
  const res = await authenticatedFetch(`${BASE}/${id}`, { token })
  return readJson(res)
}

/** Create a new encrypted secret (client produces ciphertext). */
export async function createSecret(token, payload) {
  const res = await authenticatedFetch(BASE, {
    token,
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  return readJson(res)
}

/** Replace a secret's metadata and encrypted payload. */
export async function updateSecret(token, id, payload) {
  const res = await authenticatedFetch(`${BASE}/${id}`, {
    token,
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  return readJson(res)
}

/** Delete an owned secret. */
export async function deleteSecret(token, id) {
  const res = await authenticatedFetch(`${BASE}/${id}`, {
    token,
    method: 'DELETE',
  })
  if (res.status === 204) return
  return readJson(res)
}

/** List secrets shared with the authenticated user. */
export async function listSharedSecrets(token) {
  const res = await authenticatedFetch(`${BASE}/shared`, { token })
  return readJson(res)
}

/** Get one shared secret (recipient-only). */
export async function getSharedSecret(token, id) {
  const res = await authenticatedFetch(`${BASE}/shared/${id}`, { token })
  return readJson(res)
}

/** Share a secret with one or more recipients (client wraps DEK per recipient). */
export async function shareSecret(token, secretId, recipients) {
  const res = await authenticatedFetch(`${BASE}/${secretId}/shares`, {
    token,
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recipients }),
  })
  return readJson(res)
}