import { Navigate } from 'react-router-dom'
import { useVault } from '../context/VaultContext.jsx'

function VaultLoading() {
  return (
    <main className="unlock-vault-page">
      <section className="unlock-vault-card">
        <p>Provjeravam stanje trezora...</p>
      </section>
    </main>
  )
}

function VaultError({ error, retry }) {
  return (
    <main className="unlock-vault-page">
      <section className="unlock-vault-card">
        <h1>Greška trezora</h1>
        <p role="alert">{error || 'Nije moguće učitati trezor.'}</p>
        <button type="button" onClick={retry}>
          Pokušaj ponovo
        </button>
      </section>
    </main>
  )
}

export function RequireUnlockedVault({ children }) {
  const { status, error, refreshVaultStatus } = useVault()

  if (status === 'checking') {
    return <VaultLoading />
  }

  if (status === 'error') {
    return <VaultError error={error} retry={refreshVaultStatus} />
  }

  if (status === 'needs-setup') {
    return <Navigate to="/setup-keys" replace />
  }

  if (status === 'locked') {
    return <Navigate to="/unlock-vault" replace />
  }

  if (status === 'unlocked') {
    return children
  }

  return <Navigate to="/unlock-vault" replace />
}

export function RequireSetupKeys({ children }) {
  const { status, error, refreshVaultStatus } = useVault()

  if (status === 'checking') {
    return <VaultLoading />
  }

  if (status === 'error') {
    return <VaultError error={error} retry={refreshVaultStatus} />
  }

  if (status === 'locked') {
    return <Navigate to="/unlock-vault" replace />
  }

  if (status === 'unlocked') {
    return <Navigate to="/dashboard" replace />
  }

  return children
}