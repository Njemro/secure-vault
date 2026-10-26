// MFA/TOTP API client.
import { authenticatedFetch, readJson } from './api.js'

const BASE = `${import.meta.env.VITE_API_BASE_URL || '/api'}/auth/mfa`

/** Get current MFA enrollment/enforcement status. */
export async function getMfaStatus(token) {
  const res = await authenticatedFetch(`${BASE}/status`, { token })
  return readJson(res)
}

/** Start MFA enrollment: returns provisioning URI and secret. */
export async function enrollMfa(token) {
  const res = await authenticatedFetch(`${BASE}/enroll`, {
    token,
    method: 'POST',
  })
  return readJson(res)
}

/** Confirm MFA enrollment with a TOTP code. */
export async function confirmMfa(token, code) {
  const res = await authenticatedFetch(`${BASE}/confirm`, {
    token,
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  })
  return readJson(res)
}

/** Disable MFA (requires a valid TOTP code as reauthentication). */
export async function disableMfa(token, code) {
  const res = await authenticatedFetch(`${BASE}/disable`, {
    token,
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  })
  return readJson(res)
}