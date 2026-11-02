
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react'
import keycloak from '../auth/keycloak'

import { setAccessTokenProvider } from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [authenticated, setAuthenticated] = useState(
    Boolean(keycloak.authenticated),
  )
  const [token, setToken] = useState(keycloak.token || null)
  const [user, setUser] = useState(keycloak.tokenParsed || null)

  const syncSession = useCallback(() => {
    setAuthenticated(Boolean(keycloak.authenticated))
    setToken(keycloak.token || null)
    setUser(keycloak.tokenParsed || null)
  }, [])

  const handleSessionExpired = useCallback(() => {
    setAuthenticated(false)
    setToken(null)
    setUser(null)
    
    // Potpuno učitavanje stranice uklanja osjetljive podatke
    // koji su ostali u memoriji aplikacije, uključujući Vault ključeve.
    window.location.replace('/login?reason=session-expired')
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
        handleSessionExpired()
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
    await keycloak.login({
      redirectUri: `${window.location.origin}/dashboard`,
    })
  }, [])

  const signOut = useCallback(async () => {
    await keycloak.logout({
      redirectUri: `${window.location.origin}/login`,
    })
  }, [])


  const getAccessToken = useCallback(async () => {
    if (!keycloak.authenticated) {
      handleSessionExpired()
      return null
    }

    try {
      await keycloak.updateToken(30)

      if (!keycloak.authenticated || !keycloak.token) {
        handleSessionExpired()
        return null
      }

      syncSession()
      return keycloak.token
    } catch (error) {
      console.error('Token refresh failed:', error)
      handleSessionExpired()
      return null
    }
  }, [syncSession, handleSessionExpired])

  useEffect(() => {
    setAccessTokenProvider(getAccessToken)

    return () => {
      setAccessTokenProvider(null)
    }
  }, [getAccessToken])

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

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)

  if (!context) {
    throw new Error('useAuth must be used inside AuthProvider')
  }

  return context
}
