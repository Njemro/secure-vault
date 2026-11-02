import { useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'

import { useAuth } from '../context/AuthContext.jsx'
import { useVault } from '../context/VaultContext.jsx'
import { registerKeys } from '../services/usersApi.js'
import { createVaultKeyMaterial } from '../crypto/vaultKeySetup.js'

import './SetupKeys.css'

export default function SetupKeys() {
  const { authenticated } = useAuth()
  const { completeVaultSetup } = useVault()
  const navigate = useNavigate()

  const [masterPassword, setMasterPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  if (!authenticated) {
    return <Navigate to="/login" replace />
  }

  async function handleSubmit(event) {
    event.preventDefault()

    if (loading) return

    setError('')

    if (masterPassword.length < 12) {
      setError('Master lozinka mora imati najmanje 12 znakova.')
      return
    }

    if (masterPassword !== confirmPassword) {
      setError('Master lozinke se ne poklapaju.')
      return
    }

    setLoading(true)

    try {
      const keyMaterial = await createVaultKeyMaterial(masterPassword)

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
          Postavi master lozinku (najmanje 12 znakova).
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
            minLength={12}
            value={masterPassword}
            onChange={(event) =>
              setMasterPassword(event.target.value)
            }
            required
            disabled={loading}
          />

          <label htmlFor="confirmPassword">
            Potvrdi master lozinku
          </label>

          <input
            id="confirmPassword"
            type="password"
            autoComplete="new-password"
            minLength={12}
            value={confirmPassword}
            onChange={(event) =>
              setConfirmPassword(event.target.value)
            }
            required
            disabled={loading}
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

          <button type="submit" disabled={loading}>
            {loading
              ? 'Kreiranje ključeva...'
              : 'Kreiraj ključeve trezora'}
          </button>
        </form>
      </section>
    </main>
  )
}