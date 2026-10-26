import { createContext, useContext, useState, useCallback } from 'react'
import { login, verifyMfa } from '../services/api.js'
import { getMfaStatus } from '../services/mfaApi.js'

const AuthContext = createContext(null)

/**
 * Authentication context for Secure Vault.
 *
 * The access token is kept in memory only (never localStorage). It is
 * attached to every authenticated API request. On 401 the consumer should
 * redirect to login.
 */
export function AuthProvider({ children }) {
  const [token, setToken] = useState(null)
  const [user, setUser] = useState(null)

  const signIn = useCallback(async ({ username, password }) => {
    const response = await login({ username, password })
    setToken(response.accessToken || null)
    setUser({
      id: response.userId,
      username: response.username,
      role: response.role,
      status: response.status,
      mfaRequired: response.mfaRequired,
      mfaEnrolled: response.mfaEnrolled,
    })
    return response
  }, [])

  const completeMfa = useCallback(async (tempToken, code) => {
    const response = await verifyMfa(tempToken, code)
    setToken(response.accessToken || null)
    setUser({
      id: response.userId,
      username: response.username,
      role: response.role,
      status: response.status,
      mfaRequired: response.mfaRequired,
      mfaEnrolled: response.mfaEnrolled,
    })
    return response
  }, [])

  const signOut = useCallback(() => {
    setToken(null)
    setUser(null)
  }, [])

  const checkMfaStatus = useCallback(async () => {
    if (!token) return null
    return getMfaStatus(token)
  }, [token])

  const value = {
    token,
    user,
    isAuthenticated: !!token,
    signIn,
    completeMfa,
    signOut,
    checkMfaStatus,
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return ctx
}