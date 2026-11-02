import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useVault } from '../context/VaultContext.jsx'
import { createSecret } from '../services/secretsApi.js'

export default function CreateSecret() {
  const navigate = useNavigate()
  const { unlocked, unlock, encryptSecret } = useVault()

  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [value, setValue] = useState('')
  const [masterPassword, setMasterPassword] = useState('')

  const [showUnlock, setShowUnlock] = useState(!unlocked)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function handleUnlock(event) {
    event.preventDefault()
    setError('')

    try {
      await unlock(masterPassword)
      setMasterPassword('')
      setShowUnlock(false)
    } catch (err) {
      setError(err.message || 'Pogrešna master lozinka.')
    }
  }

  async function handleSubmit(event) {
    event.preventDefault()
    setError('')

    if (!unlocked) {
      setShowUnlock(true)
      setError('Prvo otključajte vault.')
      return
    }

    if (!name.trim() || !value.trim()) {
      setError('Naziv i sadržaj tajne su obavezni.')
      return
    }

    setLoading(true)

    try {
      const encryptedData = await encryptSecret(value)

      await createSecret({
        name: name.trim(),
        description: description.trim(),
        encryptedValue: encryptedData.encryptedValue,
        encryptedDek: encryptedData.encryptedDek,
        contentIv: encryptedData.contentIv,
        dekIv: encryptedData.dekIv,
        encryptionAlgorithm: encryptedData.encryptionAlgorithm,
      })

      setName('')
      setDescription('')
      setValue('')

      navigate('/secrets', { replace: true })
    } catch (err) {
      setError(err.message || 'Greška prilikom kreiranja tajne.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="secret-page">
      <h1>Kreiranje nove tajne</h1>

      <p>
        Sadržaj tajne se šifruje na tvom uređaju prije slanja serveru.
      </p>

      {error && (
        <p role="alert" style={{ color: 'red' }}>
          {error}
        </p>
      )}

      {showUnlock && !unlocked && (
        <form onSubmit={handleUnlock}>
          <h2>Otključaj vault</h2>

          <label htmlFor="masterPassword">Master lozinka</label>
          <input
            id="masterPassword"
            type="password"
            value={masterPassword}
            onChange={(e) => setMasterPassword(e.target.value)}
            required
          />

          <button type="submit" disabled={!masterPassword}>
            Otključaj
          </button>
        </form>
      )}

      {(!showUnlock || unlocked) && (
        <form onSubmit={handleSubmit}>
          <div>
            <label htmlFor="name">Naziv tajne</label>
            <input
              id="name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={255}
              required
            />
          </div>

          <div>
            <label htmlFor="description">Opis</label>
            <textarea
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
            />
          </div>

          <div>
            <label htmlFor="value">Sadržaj tajne</label>
            <textarea
              id="value"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              rows={8}
              required
            />
          </div>

          <button type="submit" disabled={loading}>
            {loading ? 'Čuvanje...' : 'Sačuvaj tajnu'}
          </button>
        </form>
      )}

      <p>
        <Link to="/secrets">Nazad na moje tajne</Link>
      </p>
    </main>
  )
}