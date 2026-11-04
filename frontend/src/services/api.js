const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api'

let accessTokenProvider = null
let sessionExpiredHandler = null

export function setAccessTokenProvider(provider) {
  accessTokenProvider = provider
}

export function setSessionExpiredHandler(handler) {
  sessionExpiredHandler = handler
}

export async function authenticatedFetch(path, options = {}) {
  const headers = new Headers(options.headers || {})

  if (options.body && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
  }

  let token = null

  if (options.auth !== false) {
    if (accessTokenProvider) {
      token = await accessTokenProvider()

      if (!token) {
        throw new Error('Sesija je istekla. Prijavi se ponovo.')
      }
    } else if (options.token) {
      token = options.token
    } else {
      throw new Error('Access token provider nije konfigurisan.')
    }
  }

  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  } else {
    headers.delete('Authorization')
  }

  const fetchOptions = { ...options }
  delete fetchOptions.token
  delete fetchOptions.auth

  return fetch(
    path.startsWith('http') ? path : `${API_BASE}${path}`,
    {
      ...fetchOptions,
      headers,
      body:
        options.body && typeof options.body !== 'string'
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
      message =
        parsed.message ||
        parsed.error ||
        parsed.detail ||
        message
    } catch {
      // Odgovor nije JSON.
    }

    const error = new Error(message)
    error.status = response.status
    error.code = parsed?.code || null

    if (
      (
        (response.status === 401 &&
          (error.code === 'SESSION_INACTIVE' || error.code === 'SESSION_MAX_DURATION')) ||
        (response.status === 403 &&
          (error.code === 'ACCOUNT_SUSPENDED' || error.code === 'ACCOUNT_DISABLED' || error.code === 'ROLE_CHANGED'))
      )
    ) {
      sessionExpiredHandler?.(error.code)
    }

    throw error
  }

  if (response.status === 204) {
    return null
  }

  const contentType = response.headers.get('content-type') || ''

  if (contentType.includes('application/json')) {
    return response.json()
  }

  return response.text()
}

export async function request(path, options = {}) {
  const response = await authenticatedFetch(path, options)
  return readJson(response)
}

// Javni endpoint - registracija.
export function register({ username, email, keycloakPassword }) {
  return request('/auth/register', {
    method: 'POST',
    auth: false,
    body: { username, email, keycloakPassword },
  })
}

// Zaštićeni endpointi.
export function registerKeys(keyData) {
  return request('/users/keys', {
    method: 'PUT',
    body: keyData,
  })
}

export function getMyKeys() {
  return request('/users/me/keys', {
    method: 'GET',
  })
}

export function getPublicKey(userId) {
  return request(`/users/${encodeURIComponent(userId)}/public-key`, {
    method: 'GET',
  })
}