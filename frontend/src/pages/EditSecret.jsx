import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useVault } from '../context/VaultContext.jsx'
import { getSecret, updateSecret } from '../services/secretsApi.js'

export default function EditSecret() {
  const { id } = useParams()
  const navigate = useNavigate()

  const { unlocked, unlock, encryptSecret } = useVault()

  const [secret, setSecret] = useState(null)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [value, setValue] = useState('')

  const [masterPassword, setMasterPassword] = useState('')
  const showUnlock = !unlocked

  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')


  useEffect(() => {
    let cancelled = false

    async function loadSecret() {
      setLoading(true)
      setError('')

      try {
        const data = await getSecret(id)

        if (!cancelled) {
          setSecret(data)
          setName(data.name || '')
          setDescription(data.description || '')
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || 'Greška prilikom učitavanja tajne.')
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    loadSecret()

    return () => {
      cancelled = true
    }
  }, [id])

  async function handleUnlock(event) {
    event.preventDefault()
    setError('')

    try {
      await unlock(masterPassword)
      setMasterPassword('')
    } catch (err) {
      setError(err.message || 'Pogrešna master lozinka.')
    }
  }

  async function handleSubmit(event) {
    event.preventDefault()
    setError('')

    if (!secret) {
      setError('Tajna nije učitana.')
      return
    }

    if (!unlocked) {
      setError('Prvo otključajte vault.')
      return
    }

    if (!name.trim()) {
      setError('Naziv tajne je obavezan.')
      return
    }

    setSaving(true)

    try {
      let encryptedData = {
        encryptedValue: secret.encryptedValue,
        encryptedDek: secret.encryptedDek,
        contentIv: secret.contentIv,
        dekIv: secret.dekIv,
        encryptionAlgorithm: secret.encryptionAlgorithm,
      }

      if (value.trim()) {
        encryptedData = await encryptSecret(value)
      }

      await updateSecret(id, {
        name: name.trim(),
        description: description.trim(),
        ...encryptedData,
      })

      navigate(`/secrets/${id}`, { replace: true })
    } catch (err) {
      setError(err.message || 'Greška prilikom izmjene tajne.')
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return <p>Učitavanje tajne...</p>
  }

  if (!secret) {
    return (
      <main>
        <h1>Izmjena tajne</h1>
        <p role="alert">{error || 'Tajna nije pronađena.'}</p>
        <Link to="/secrets">Nazad na moje tajne</Link>
      </main>
    )
  }

  return (
    <main className="secret-page">
      <h1>Izmjena tajne</h1>

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
            <label htmlFor="name">Naziv</label>
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
            <label htmlFor="value">Novi sadržaj tajne</label>
            <textarea
              id="value"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              rows={8}
              placeholder="Ostavi prazno ako ne želiš mijenjati sadržaj."
            />
          </div>

          <button type="submit" disabled={saving}>
            {saving ? 'Čuvanje...' : 'Sačuvaj izmjene'}
          </button>
        </form>
      )}

      <p>
        <Link to={`/secrets/${id}`}>Odustani</Link>
      </p>
    </main>
  )
}