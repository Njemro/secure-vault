import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import { useVault } from '../context/VaultContext.jsx'
import { getSecret, updateSecret } from '../services/secretsApi.js'
import PageHeader from '../components/PageHeader.jsx'

export default function EditSecret() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { token } = useAuth()
  const { unlocked, unlock, encryptSecret } = useVault()

  const [form, setForm] = useState({ name: '', description: '', value: '' })
  const [masterPassword, setMasterPassword] = useState('')
  const [showUnlock, setShowUnlock] = useState(true)
  const [unlockError, setUnlockError] = useState(null)
  const [loading, setLoading] = useState(Boolean(token))
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)

  const loadSecret = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getSecret(token, id)
      setForm({ name: data.name, description: data.description || '', value: '' })
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

  const updateField = (key, value) => {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)

    if (!unlocked) {
      setShowUnlock(true)
      return
    }

    setSaving(true)
    try {
      const encrypted = await encryptSecret(form.value)
      await updateSecret(token, id, {
        name: form.name,
        description: form.description,
        encryptedValue: encrypted.encryptedValue,
        encryptedDek: encrypted.encryptedDek,
        contentIv: encrypted.contentIv,
        dekIv: encrypted.dekIv,
        encryptionAlgorithm: encrypted.encryptionAlgorithm,
      })
      navigate(`/secrets/${id}`, { replace: true })
    } catch (err) {
      setError(err.message || 'Failed to update secret')
    } finally {
      setSaving(false)
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
        <PageHeader title="Unlock Vault" subtitle="Enter your master password to edit this secret." />
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
      <PageHeader title="Edit Secret" subtitle="Update metadata and re-encrypt the value." />
      <form onSubmit={handleSubmit} className="form">
        <div className="form__group">
          <label className="form__label">Name</label>
          <input
            className="form__input"
            type="text"
            value={form.name}
            onChange={(e) => updateField('name', e.target.value)}
            required
          />
        </div>
        <div className="form__group">
          <label className="form__label">Description</label>
          <textarea
            className="form__input"
            value={form.description}
            onChange={(e) => updateField('description', e.target.value)}
          />
        </div>
        <div className="form__group">
          <label className="form__label">Secret Value</label>
          <textarea
            className="form__input"
            value={form.value}
            onChange={(e) => updateField('value', e.target.value)}
            placeholder="Leave blank to keep the current value"
          />
          <p className="form__hint">
            New value is encrypted client-side before sending. Leave blank to
            keep the current encrypted value unchanged (note: this implementation
            always re-encrypts when a value is provided).
          </p>
        </div>
        {error && <p className="form__error">{error}</p>}
        <button type="submit" className="btn btn--primary btn--full" disabled={saving}>
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </form>
      <p className="form__footer">
        <Link to={`/secrets/${id}`} className="form__link">Cancel</Link>
      </p>
    </section>
  )
}