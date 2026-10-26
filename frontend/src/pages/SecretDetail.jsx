import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import { useVault } from '../context/VaultContext.jsx'
import { getSecret, deleteSecret } from '../services/secretsApi.js'
import PageHeader from '../components/PageHeader.jsx'

export default function SecretDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { token } = useAuth()
  const { unlocked, unlock, decryptSecret } = useVault()

  const [secret, setSecret] = useState(null)
  const [decryptedValue, setDecryptedValue] = useState(null)
  const [showDecrypted, setShowDecrypted] = useState(false)
  const [masterPassword, setMasterPassword] = useState('')
  const [showUnlock, setShowUnlock] = useState(true)
  const [unlockError, setUnlockError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [deleting, setDeleting] = useState(false)

  const loadSecret = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getSecret(token, id)
      setSecret(data)
    } catch (err) {
      setError(err.message || 'Failed to load secret')
    } finally {
      setLoading(false)
    }
  }, [token, id])

  useEffect(() => {
    const fetchData = async () => {
      await loadSecret()
    }
    fetchData()
  }, [loadSecret])

  const handleUnlock = async (e) => {
    e && e.preventDefault()
    setUnlockError(null)
    try {
      await unlock(masterPassword)
      setShowUnlock(false)
    } catch (err) {
      setUnlockError('Failed to unlock vault: ' + (err.message || 'unknown error'))
    }
  }

  const handleDecrypt = async () => {
    if (!secret) return
    setError(null)
    try {
      const plaintext = await decryptSecret({
        encryptedValue: secret.encryptedValue,
        contentIv: secret.contentIv,
        encryptedDek: secret.encryptedDek,
        dekIv: secret.dekIv,
      })
      setDecryptedValue(plaintext)
      setShowDecrypted(true)
    } catch (err) {
      setError('Failed to decrypt secret: ' + (err.message || 'unknown error'))
    }
  }

  const handleDelete = async (e) => {
    e.preventDefault()
    if (!window.confirm('Are you sure you want to delete this secret?')) return
    setDeleting(true)
    try {
      await deleteSecret(token, id)
      navigate('/my-secrets', { replace: true })
    } catch (err) {
      setError(err.message || 'Failed to delete secret')
    } finally {
      setDeleting(false)
    }
  }

  if (loading) {
    return (
      <section className="page">
        <PageHeader title="Loading" subtitle="Please wait..." />
        <p>Loading secret...</p>
      </section>
    )
  }

  if (error) {
    return (
      <section className="page">
        <PageHeader title="Error" subtitle="Could not load secret." />
        <p className="form__error">{error}</p>
      </section>
    )
  }

  if (showUnlock) {
    return (
      <section className="page">
        <PageHeader title="Unlock Vault" subtitle="Enter your master password to view this secret." />
        <form onSubmit={handleUnlock} className="form">
          <div className="form__group">
            <label className="form__label">Master Password</label>
            <input
              className="form__input"
              type="password"
              value={masterPassword}
              onChange={(e) => setMasterPassword(e.target.value)}
              placeholder="Your vault master password"
              required
              autoComplete="new-password"
            />
          </div>
          {unlockError && <p className="form__error">{unlockError}</p>}
          <button type="submit" className="btn btn--primary btn--full">
            Unlock Vault
          </button>
        </form>
      </section>
    )
  }

  return (
    <section className="page">
      <PageHeader title={secret.name} subtitle="Secret details" />
      <div className="card">
        <p><strong>Name:</strong> {secret.name}</p>
        <p><strong>Description:</strong> {secret.description || '—'}</p>
        <p><strong>Algorithm:</strong> {secret.encryptionAlgorithm}</p>
        <p><strong>Created:</strong> {secret.createdAt}</p>
        <p><strong>Last rotated:</strong> {secret.lastRotatedAt || '—'}</p>
      </div>

      <div className="card">
        <h3 className="card__title">Secret Value</h3>
        {showDecrypted ? (
          <>
            <p className="form__error">
              Warning: plaintext is visible only in this browser session.
            </p>
            <p><strong>Value:</strong> {decryptedValue}</p>
            <button
              type="button"
              className="btn btn--outline"
              onClick={() => setShowDecrypted(false)}
            >
              Hide Value
            </button>
          </>
        ) : (
          <button
            type="button"
            className="btn btn--primary"
            onClick={handleDecrypt}
            disabled={!unlocked}
          >
            {unlocked ? 'Reveal Secret Value' : 'Unlock to Reveal'}
          </button>
        )}
        {error && <p className="form__error">{error}</p>}
      </div>

      <div className="card">
        <Link to={`/secrets/${id}/edit`} className="btn btn--outline">
          Edit Secret
        </Link>
        <button
          type="button"
          className="btn btn--danger"
          onClick={handleDelete}
          disabled={deleting}
        >
          {deleting ? 'Deleting...' : 'Delete Secret'}
        </button>
      </div>
    </section>
  )
}