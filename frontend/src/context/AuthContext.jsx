import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'

import keycloak from '../auth/keycloak'

import {
  setAccessTokenProvider,
  setSessionExpiredHandler,
} from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [authenticated, setAuthenticated] = useState(
    Boolean(keycloak.authenticated),
  )
  const [token, setToken] = useState(keycloak.token || null)
  const [user, setUser] = useState(keycloak.tokenParsed || null)

  const sessionEnding = useRef(false)

  const syncSession = useCallback(() => {
    setAuthenticated(Boolean(keycloak.authenticated))
    setToken(keycloak.token || null)
    setUser(keycloak.tokenParsed || null)
  }, [])

  const handleSessionExpired = useCallback(async (reason = 'session-expired') => {
    if (sessionEnding.current) {
      return
    }
  
    sessionEnding.current = true
  
    setAuthenticated(false)
    setToken(null)
    setUser(null)
  
    window.dispatchEvent(
      new CustomEvent('secure-vault:session-expired', {
        detail: { reason },
      }),
    )
  
    const redirectUri = `${window.location.origin}/login`
  
    try {
      if (keycloak.authenticated) {
        await keycloak.logout({ redirectUri })
      } else {
        window.location.replace(redirectUri)
      }
    } catch (error) {
      console.error('Keycloak logout failed:', error)
      window.location.replace(redirectUri)
    }
  }, [])

  useEffect(() => {
    keycloak.onAuthSuccess = syncSession
    keycloak.onAuthRefreshSuccess = syncSession
    keycloak.onAuthLogout = syncSession

    keycloak.onTokenExpired = async () => {
      try {
        await keycloak.updateToken(30)
        syncSession()
      } catch (error) {
        console.error('Token refresh failed:', error)
        handleSessionExpired('session-expired')
      }
    }

    return () => {
      keycloak.onAuthSuccess = undefined
      keycloak.onAuthRefreshSuccess = undefined
      keycloak.onAuthLogout = undefined
      keycloak.onTokenExpired = undefined
    }
  }, [syncSession, handleSessionExpired])

  const signIn = useCallback(async () => {
    sessionEnding.current = false

    await keycloak.login({
      redirectUri: `${window.location.origin}/dashboard`,
    })
  }, [])

  const signOut = useCallback(async () => {
    sessionEnding.current = true
    window.dispatchEvent(
      new CustomEvent('secure-vault:session-expired', {
        detail: { reason: 'logout' },
      }),
    )

    await keycloak.logout({
      redirectUri: `${window.location.origin}/login`,
    })
  }, [])

  const getAccessToken = useCallback(async () => {
    if (!keycloak.authenticated) {
      await handleSessionExpired('session-expired')
      return null
    }

    try {
      await keycloak.updateToken(30)

      if (!keycloak.authenticated || !keycloak.token) {
        await handleSessionExpired('session-expired')
        return null
      }

      syncSession()
      return keycloak.token
    } catch (error) {
      console.error('Token refresh failed:', error)
      await handleSessionExpired('session-expired')
      return null
    }
  }, [syncSession, handleSessionExpired])

  useEffect(() => {
    setAccessTokenProvider(getAccessToken)
    setSessionExpiredHandler(handleSessionExpired)

    return () => {
      setAccessTokenProvider(null)
      setSessionExpiredHandler(null)
    }
  }, [getAccessToken, handleSessionExpired])

  const value = useMemo(
    () => ({
      authenticated,
      token,
      user,
      signIn,
      signOut,
      getAccessToken,
    }),
    [authenticated, token, user, signIn, signOut, getAccessToken],
  )

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)

  if (!context) {
    throw new Error('useAuth must be used inside AuthProvider')
  }

  return context
}