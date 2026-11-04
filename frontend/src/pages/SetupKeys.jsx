import { useEffect, useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'

import { useAuth } from '../context/AuthContext.jsx'
import { useVault } from '../context/VaultContext.jsx'
import { registerKeys } from '../services/usersApi.js'
import { createVaultKeyMaterial } from '../crypto/vaultKeySetup.js'

import { getSecurityPolicy } from '../services/securityPolicyApi.js'

import './SetupKeys.css'

export default function SetupKeys() {
  const { authenticated } = useAuth()
  const { completeVaultSetup } = useVault()
  const navigate = useNavigate()

  const [masterPassword, setMasterPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const [minMasterPasswordLength, setMinMasterPasswordLength] = useState(null)
  const [policyLoading, setPolicyLoading] = useState(true)
  const [policyError, setPolicyError] = useState('')

  useEffect(() => {
    if (!authenticated) return
    
    let active = true
    
    async function loadPolicy() {
      try {
        setPolicyLoading(true)
        setPolicyError('')
      
        const policy = await getSecurityPolicy()
      
        if (active) {
          setMinMasterPasswordLength(policy.minMasterPasswordLength)
        }
      } catch (err) {
        if (active) {
          setPolicyError(
            err.message || 'Nije moguće učitati sigurnosnu politiku.',
          )
        }
      } finally {
        if (active) setPolicyLoading(false)
      }
    }
  
    loadPolicy()
  
    return () => {
      active = false
    }
  }, [authenticated])
  
  if (!authenticated) {
    return <Navigate to="/login" replace />
  }

  async function handleSubmit(event) {
    event.preventDefault()

    if (loading) return

    setError('')

    if (policyLoading || minMasterPasswordLength === null) {
      setError('Sigurnosna politika još nije učitana.')
      return
    }

    if (masterPassword.length < minMasterPasswordLength) {
      setError(
        `Master lozinka mora imati najmanje ${minMasterPasswordLength} znakova.`,
      )
      return
    }

    if (masterPassword !== confirmPassword) {
      setError('Master lozinke se ne poklapaju.')
      return
    }

    try {
      setLoading(true)

      const keyMaterial = await createVaultKeyMaterial(
        masterPassword,
        minMasterPasswordLength,
      )

      await registerKeys(keyMaterial)

      completeVaultSetup(keyMaterial)

      setMasterPassword('')
      setConfirmPassword('')

      navigate('/unlock-vault', { replace: true })
    } catch (err) {
      console.error('Greška pri kreiranju ključeva:', err)

      setError(
        err?.message || 'Registracija ključeva nije uspjela.',
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="setup-keys-page">
      <section className="setup-keys-card">
        <h1>Zaštiti svoj trezor</h1>

        <p>
          Postavi master lozinku (najmanje {minMasterPasswordLength ?? "..."} znakova).
          Ona se koristi u tvom browseru za šifrovanje
          privatnog ključa i ne šalje se serveru.
        </p>

        <form onSubmit={handleSubmit}>
          <label htmlFor="masterPassword">
            Master lozinka
          </label>

          <input
            id="masterPassword"
            type="password"
            autoComplete="new-password"
            minLength={minMasterPasswordLength ?? undefined}
            value={masterPassword}
            onChange={(event) =>
              setMasterPassword(event.target.value)
            }
            required
            disabled={loading || policyLoading || minMasterPasswordLength === null}
          />

          <label htmlFor="confirmPassword">
            Potvrdi master lozinku
          </label>

          <input
            id="confirmPassword"
            type="password"
            autoComplete="new-password"
            minLength={minMasterPasswordLength ?? undefined}
            value={confirmPassword}
            onChange={(event) =>
              setConfirmPassword(event.target.value)
            }
            required
            disabled={loading || policyLoading || minMasterPasswordLength === null}
          />

          {error && (
            <p
              role="alert"
              style={{
                color: '#dc2626',
                marginTop: '12px',
                overflowWrap: 'anywhere',
              }}
            >
              {error}
            </p>
          )}

          {policyLoading && <p>Učitavanje sigurnosnih pravila...</p>}

          {policyError && (
            <p className="error-message">{policyError}</p>
          )}

          <button type="submit" disabled={policyLoading || minMasterPasswordLength === null || loading}>
            {loading
              ? 'Kreiranje ključeva...'
              : 'Kreiraj ključeve trezora'}
          </button>
        </form>
      </section>
    </main>
  )
}