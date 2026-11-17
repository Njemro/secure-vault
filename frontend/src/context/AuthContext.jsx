import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [authenticated, setAuthenticated] = useState(false)
  const [user, setUser] = useState(null)
  const [initializing, setInitializing] = useState(true)

  const loadSession = useCallback(async () => {
    try {
      const response = await fetch('/auth/me', {
        method: 'GET',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
        cache: 'no-store',
      })

      if (!response.ok) {
        setAuthenticated(false)
        setUser(null)
        return false
      }

      const identity = await response.json()
      setUser(identity)
      setAuthenticated(identity?.authenticated === true)
      return identity?.authenticated === true
    } catch (error) {
      console.error('Session check failed:', error)
      setAuthenticated(false)
      setUser(null)
      return false
    } finally {
      setInitializing(false)
    }
  }, [])

  useEffect(() => {
    loadSession()
  }, [loadSession])


  const signIn = useCallback(() => {
    window.location.assign('/oauth2/authorization/keycloak')
  }, [])

  const signOut = useCallback(async () => {
    try {
      const csrfResponse = await fetch('/auth/csrf', {
        credentials: 'same-origin',
        cache: 'no-store',
      })
      if (!csrfResponse.ok) throw new Error('Nije moguće pripremiti sigurnu odjavu.')
      const csrf = await csrfResponse.json()

      // A real top-level form navigation lets Spring Security complete OIDC logout
      // and redirect the browser to the Keycloak end-session endpoint.
      const form = document.createElement('form')
      form.method = 'POST'
      form.action = '/auth/logout'
      const field = document.createElement('input')
      field.type = 'hidden'
      field.name = '_csrf'
      field.value = csrf.token
      form.appendChild(field)
      document.body.appendChild(form)
      form.submit()
    } catch (error) {
      console.error('Logout failed:', error)
      window.location.assign('/login')
    }
  }, [])

  const handleSessionExpired = useCallback(async (reason = 'session-expired') => {
    const requiresIdentityProviderLogout = [
      'SESSION_INACTIVE',
      'SESSION_MAX_DURATION',
      'ROLE_CHANGED',
      'ACCOUNT_SUSPENDED',
      'ACCOUNT_DISABLED',
    ].includes(reason)

    setAuthenticated(false)
    setUser(null)

    if (requiresIdentityProviderLogout) {
      await signOut()
      return
    }

    if (window.location.pathname !== '/login') {
      window.location.assign(`/login?reason=${encodeURIComponent(reason)}`)
    }
  }, [signOut])


  useEffect(() => {
    const onExpired = (event) => handleSessionExpired(event.detail?.reason)
    window.addEventListener('secure-vault:session-expired', onExpired)
    return () => window.removeEventListener('secure-vault:session-expired', onExpired)
  }, [handleSessionExpired])

  const value = useMemo(() => ({
    authenticated,
    initializing,
    user,
    signIn,
    signOut,
    refreshSession: loadSession,
    handleSessionExpired,
  }), [authenticated, initializing, user, signIn, signOut, loadSession, handleSessionExpired])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside AuthProvider')
  return context
}
