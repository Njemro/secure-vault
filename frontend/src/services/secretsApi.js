// Secret CRUD and sharing API client.
// All calls go through the Gateway (VITE_API_BASE_URL).
// Binary fields (IVs, ciphertext, wrapped DEKs) are Base64 strings at the JSON boundary.

import { authenticatedFetch, readJson } from './api.js'

const BASE = '/secrets'

/** List secrets owned by the authenticated user. */
export async function listSecrets() {
  const res = await authenticatedFetch(BASE)
  return readJson(res)
}

/** Get one owned secret by id. */
export async function getSecret(id) {
  const res = await authenticatedFetch(`${BASE}/${encodeURIComponent(id)}`)
  return readJson(res)
}

/** Create a new encrypted secret. */
export async function createSecret(payload) {
  const res = await authenticatedFetch(BASE, {
    method: 'POST',
    body: payload,
  })
  return readJson(res)
}

/** Replace a secret's metadata and encrypted payload. */
export async function updateSecret(id, payload) {
  const res = await authenticatedFetch(
    `${BASE}/${encodeURIComponent(id)}`,
    {
      method: 'PUT',
      body: payload,
    },
  )
  return readJson(res)
}

/** Delete an owned secret. */
export async function deleteSecret(id) {
  const res = await authenticatedFetch(
    `${BASE}/${encodeURIComponent(id)}`,
    {
      method: 'DELETE',
    },
  )

  if (res.status === 204) return null

  return readJson(res)
}

/** List secrets shared with the authenticated user. */
export async function listSharedSecrets() {
  const res = await authenticatedFetch(`${BASE}/shared`)
  return readJson(res)
}

/** Get one shared secret. */
export async function getSharedSecret(id) {
  const res = await authenticatedFetch(
    `${BASE}/shared/${encodeURIComponent(id)}`,
  )
  return readJson(res)
}

/** Share a secret with one or more recipients. */
export async function shareSecret(secretId, recipients) {
  const res = await authenticatedFetch(
    `${BASE}/${encodeURIComponent(secretId)}/shares`,
    {
      method: 'POST',
      body: { recipients },
    },
  )

  return readJson(res)
}