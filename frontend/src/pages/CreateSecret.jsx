import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import { useVault } from '../context/VaultContext.jsx'
import { createSecret } from '../services/secretsApi.js'
import PageHeader from '../components/PageHeader.jsx'

export default function CreateSecret() {
  const navigate = useNavigate()
  const { token } = useAuth()
  const { unlocked, unlock, encryptSecret } = useVault()

  const [form, setForm] = useState({ name: '', description: '', value: '' })
  const [masterPassword, setMasterPassword] = useState('')
  const [unlockError, setUnlockError] = useState(null)
  const [showUnlock, setShowUnlock] = useState(!unlocked)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const updateField = (key, value) => {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

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

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)

    if (!unlocked) {
      setShowUnlock(true)
      return
    }

    setLoading(true)
    try {
      const encrypted = await encryptSecret(form.value)
      await createSecret(token, {
        name: form.name,
        description: form.description,
        encryptedValue: encrypted.encryptedValue,
        encryptedDek: encrypted.encryptedDek,
        contentIv: encrypted.contentIv,
        dekIv: encrypted.dekIv,
        encryptionAlgorithm: encrypted.encryptionAlgorithm,
      })
      navigate('/my-secrets', { replace: true })
    } catch (err) {
      setError(err.message || 'Failed to create secret')
    } finally {
      setLoading(false)
    }
  }

  if (showUnlock) {
    return (
      <section className="page">
        <PageHeader
          title="Unlock Vault"
          subtitle="Enter your master password to create a new secret."
        />
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
            <p className="form__hint">
              Client-side only. Used to derive the key encryption key (KEK).
              Never sent to the server.
            </p>
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
      <PageHeader
        title="Create Secret"
        subtitle="Encrypt and store a new secret. Encryption happens client-side."
      />
      <form onSubmit={handleSubmit} className="form">
        <div className="form__group">
          <label className="form__label">Name</label>
          <input
            className="form__input"
            type="text"
            value={form.name}
            onChange={(e) => updateField('name', e.target.value)}
            placeholder="e.g. Production Database Password"
            required
          />
        </div>
        <div className="form__group">
          <label className="form__label">Description</label>
          <textarea
            className="form__input"
            value={form.description}
            onChange={(e) => updateField('description', e.target.value)}
            placeholder="Optional description"
          />
        </div>
        <div className="form__group">
          <label className="form__label">Secret Value</label>
          <textarea
            className="form__input"
            value={form.value}
            onChange={(e) => updateField('value', e.target.value)}
            placeholder="The plaintext secret value (encrypted client-side before sending)"
            required
          />
          <p className="form__hint">
            This value is encrypted with AES-256-GCM in your browser before it
            leaves this page. The backend never sees the plaintext.
          </p>
        </div>
        {error && <p className="form__error">{error}</p>}
        <button
          type="submit"
          className="btn btn--primary btn--full"
          disabled={loading}
        >
          {loading ? 'Encrypting...' : 'Create Secret'}
        </button>
      </form>
    </section>
  )
}