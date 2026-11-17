const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api'


async function getCsrfToken() {
  const response = await fetch('/auth/csrf', {
    method: 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { Accept: 'application/json' },
  })
  if (!response.ok) throw new Error('Nije moguće dobiti CSRF token.')
  const csrf = await response.json()
  if (!csrf?.token || !csrf?.headerName) {
    throw new Error('CSRF token nije ispravan.')
  }
  return csrf
}

export async function authenticatedFetch(path, options = {}) {
  const headers = new Headers(options.headers || {})
  const method = (options.method || 'GET').toUpperCase()

  if (options.body && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
  }

  if (!['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method)) {
    // CSRF token is kept in memory and returned as JSON; the session cookie
    // itself remains HttpOnly, Secure and SameSite=Strict.
    const csrf = await getCsrfToken()
    headers.set(csrf.headerName, csrf.token)
  }

  const fetchOptions = { ...options }
  delete fetchOptions.auth
  delete fetchOptions.token

  return fetch(
    path.startsWith('http') ? path : `${API_BASE}${path}`,
    {
      ...fetchOptions,
      method,
      credentials: 'same-origin',
      cache: options.cache || 'no-store',
      headers,
      body:
        options.body && typeof options.body !== 'string' && !(options.body instanceof FormData)
          ? JSON.stringify(options.body)
          : options.body,
    },
  )
}

export async function readJson(response) {
  if (!response.ok) {
    const text = await response.text()
    let message = text || `HTTP ${response.status}`
    let parsed = null

    try {
      parsed = JSON.parse(text)
      message = parsed.message || parsed.error || parsed.detail || message
    } catch {
      // Non-JSON response.
    }

    const error = new Error(message)
    error.status = response.status
    error.code = parsed?.code || response.headers.get('X-SecureVault-Block-Reason') || null

    if (response.status === 401 ||
        (response.status === 403 && ['ACCOUNT_SUSPENDED', 'ACCOUNT_DISABLED', 'ROLE_CHANGED'].includes(error.code))) {
      window.dispatchEvent(new CustomEvent('secure-vault:session-expired', {
        detail: { reason: error.code || 'session-expired' },
      }))
    }

    throw error
  }

  if (response.status === 204) return null

  const contentType = response.headers.get('content-type') || ''
  if (contentType.includes('application/json')) return response.json()
  return response.text()
}

export async function request(path, options = {}) {
  const response = await authenticatedFetch(path, options)
  return readJson(response)
}

// Public registration endpoint; CSRF is still required by the BFF.
export function register({ username, email, keycloakPassword }) {
  return request('/auth/register', {
    method: 'POST',
    auth: false,
    body: { username, email, keycloakPassword },
  })
}

export function registerKeys(keyData) {
  return request('/users/keys', { method: 'PUT', body: keyData })
}

export function getMyKeys() {
  return request('/users/me/keys', { method: 'GET' })
}

export function getPublicKey(userId) {
  return request(`/users/${encodeURIComponent(userId)}/public-key`, { method: 'GET' })
}

export async function reportDecryptionFailure() {
  try {
    await request('/security-events/decryption-failure', {
      method: 'POST',
      body: { reason: 'CLIENT_SIDE_DECRYPTION_FAILED' },
    })
  } catch (error) {
    // Reporting must never replace the original decryption error shown to user.
    console.warn('Could not report decryption failure:', error)
  }
}
