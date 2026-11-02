import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useVault } from '../context/VaultContext.jsx'
import {
  getSecret,
  deleteSecret,
} from '../services/secretsApi.js'

export default function SecretDetail() {
  const { id } = useParams()
  const navigate = useNavigate()

  const { unlocked, unlock, decryptSecret } = useVault()

  const [secret, setSecret] = useState(null)
  const [masterPassword, setMasterPassword] = useState('')

  const [decryptedValue, setDecryptedValue] = useState('')
  const [isDecrypted, setIsDecrypted] = useState(false)

  const [loading, setLoading] = useState(true)
  const [decrypting, setDecrypting] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState('')

  const showUnlock = !unlocked
  const visibleDecryptedValue =
    unlocked && isDecrypted ? decryptedValue : ''

  useEffect(() => {
    let cancelled = false

    async function loadSecret() {
      setLoading(true)
      setError('')

      try {
        const data = await getSecret(id)

        if (!cancelled) {
          setSecret(data)
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

  async function handleDecrypt() {
    if (!secret) return

    setError('')

    if (!unlocked) {
      setError('Prvo otključajte vault.')
      return
    }

    setDecrypting(true)

    try {
      const plaintext = await decryptSecret({
        encryptedValue: secret.encryptedValue,
        contentIv: secret.contentIv,
        encryptedDek: secret.encryptedDek,
        dekIv: secret.dekIv,
      })

      setDecryptedValue(plaintext)
      setIsDecrypted(true)
    } catch (err) {
      setError(err.message || 'Dešifrovanje nije uspjelo.')
    } finally {
      setDecrypting(false)
    }
  }

  function hideDecryptedValue() {
    setDecryptedValue('')
    setIsDecrypted(false)
  }

  async function handleDelete() {
    const confirmed = window.confirm(
      'Da li ste sigurni da želite trajno obrisati ovu tajnu?',
    )

    if (!confirmed) return

    setDeleting(true)
    setError('')

    try {
      await deleteSecret(id)
      navigate('/secrets', { replace: true })
    } catch (err) {
      setError(err.message || 'Greška prilikom brisanja tajne.')
    } finally {
      setDeleting(false)
    }
  }

  if (loading) {
    return <p>Učitavanje tajne...</p>
  }

  if (!secret) {
    return (
      <main>
        <h1>Tajna</h1>
        <p role="alert">{error || 'Tajna nije pronađena.'}</p>
        <Link to="/secrets">Nazad na moje tajne</Link>
      </main>
    )
  }

  return (
    <main className="secret-page">
      <h1>{secret.name}</h1>

      {secret.description && (
        <p>{secret.description}</p>
      )}

      <p>
        <strong>Algoritam:</strong>{' '}
        {secret.encryptionAlgorithm || 'Nije naveden'}
      </p>

      <p>
        <strong>Kreirano:</strong>{' '}
        {secret.createdAt
          ? new Date(secret.createdAt).toLocaleString()
          : 'Nepoznato'}
      </p>

      {error && (
        <p role="alert" style={{ color: 'red' }}>
          {error}
        </p>
      )}

      {showUnlock && (
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

      <section>
        <h2>Sadržaj tajne</h2>

        {!unlocked || !isDecrypted ? (
          <button
            type="button"
            onClick={handleDecrypt}
            disabled={decrypting || !unlocked}
          >
            {decrypting ? 'Dešifrovanje...' : 'Prikaži sadržaj'}
          </button>
        ) : (
          <>
            <pre
              style={{
                whiteSpace: 'pre-wrap',
                overflowWrap: 'anywhere',
              }}
            >
              {visibleDecryptedValue}
            </pre>

            <button
              type="button"
              onClick={hideDecryptedValue}
            >
              Sakrij sadržaj
            </button>
          </>
        )}
      </section>

      <hr />

      <nav>
        <Link to={`/secrets/${id}/edit`}>
          Izmijeni tajnu
        </Link>

        {' | '}

        <Link to="/secrets">
          Nazad na moje tajne
        </Link>
      </nav>

      <div>
        <button
          type="button"
          onClick={handleDelete}
          disabled={deleting}
        >
          {deleting ? 'Brisanje...' : 'Obriši tajnu'}
        </button>
      </div>
    </main>
  )
}