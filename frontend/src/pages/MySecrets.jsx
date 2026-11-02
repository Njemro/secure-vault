import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { listSecrets } from '../services/secretsApi.js'

export default function MySecrets() {
  const [secrets, setSecrets] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false

    async function fetchSecrets() {
      setLoading(true)
      setError('')

      try {
        const data = await listSecrets()

        if (!cancelled) {
          setSecrets(Array.isArray(data) ? data : [])
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || 'Greška prilikom učitavanja tajni.')
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    fetchSecrets()

    return () => {
      cancelled = true
    }
  }, [])

  if (loading) {
    return <p>Učitavanje tajni...</p>
  }

  return (
    <main className="secret-page">
      <header>
        <h1>Moje tajne</h1>
        <Link to="/secrets/new">+ Nova tajna</Link>
      </header>

      {error && (
        <p role="alert" style={{ color: 'red' }}>
          {error}
        </p>
      )}

      {!error && secrets.length === 0 && (
        <section>
          <p>Još uvijek nemaš sačuvanih tajni.</p>
          <Link to="/secrets/new">Kreiraj prvu tajnu</Link>
        </section>
      )}

      {secrets.length > 0 && (
        <ul>
          {secrets.map((secret) => (
            <li key={secret.id}>
              <Link to={`/secrets/${secret.id}`}>
                <strong>{secret.name}</strong>

                {secret.description && (
                  <p>{secret.description}</p>
                )}

                <small>
                  Algoritam: {secret.encryptionAlgorithm || 'Nije naveden'}
                </small>

                <br />

                <small>
                  Kreirano:{' '}
                  {secret.createdAt
                    ? new Date(secret.createdAt).toLocaleString()
                    : 'Nepoznato'}
                </small>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </main>
  )
}