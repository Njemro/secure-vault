import { useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { useVault } from '../context/VaultContext.jsx'
import './UnlockVault.css'

export default function UnlockVault() {
  const navigate = useNavigate()

  const {
    status,
    error: vaultError,
    unlock,
    refreshVaultStatus,
  } = useVault()

  const [masterPassword, setMasterPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  if (status === 'checking') {
    return (
      <main className="unlock-vault-page">
        <section className="unlock-vault-card">
          <p>Provjeravam stanje trezora...</p>
        </section>
      </main>
    )
  }

  if (status === 'error') {
    return (
      <main className="unlock-vault-page">
        <section className="unlock-vault-card">
          <h1>Nije moguće učitati trezor</h1>
          <p role="alert">
            {vaultError || 'Došlo je do greške prilikom učitavanja trezora.'}
          </p>

          <button type="button" onClick={refreshVaultStatus}>
            Pokušaj ponovo
          </button>
        </section>
      </main>
    )
  }

  if (status === 'unlocked') {
    return <Navigate to="/dashboard" replace />
  }

  async function handleSubmit(event) {
    event.preventDefault()

    if (loading) return

    setError('')
    setLoading(true)

    try {
      await unlock(masterPassword)
      setMasterPassword('')
      navigate('/dashboard', { replace: true })
    } catch (err) {
      setError(
        err?.message || 'Otključavanje trezora nije uspjelo.',
      )
      setMasterPassword('')
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="unlock-vault-page">
      <section className="unlock-vault-card">
        <div className="unlock-vault-icon" aria-hidden="true">
          🔐
        </div>

        <h1>Otključaj svoj trezor</h1>

        <p>
          Unesi master lozinku koju si postavio prilikom kreiranja
          trezora. Ona se obrađuje lokalno u browseru.
        </p>

        <form onSubmit={handleSubmit}>
          <label htmlFor="masterPassword">
            Master lozinka
          </label>

          <input
            id="masterPassword"
            type="password"
            autoComplete="current-password"
            value={masterPassword}
            onChange={(event) => setMasterPassword(event.target.value)}
            required
            autoFocus
            disabled={loading}
          />

          {error && (
            <p className="unlock-vault-error" role="alert">
              {error}
            </p>
          )}

          <button type="submit" disabled={loading || !masterPassword}>
            {loading ? 'Otključavanje...' : 'Otključaj trezor'}
          </button>
        </form>
      </section>
    </main>
  )
}