import { useState, useEffect } from 'react'
import PageHeader from '../components/PageHeader.jsx'
import { listSharedSecrets } from '../services/secretsApi.js'

export default function SharedWithMe() {
  const [secrets, setSecrets] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false

    async function fetchData() {
      setLoading(true)
      setError(null)

      try {
        const data = await listSharedSecrets()

        if (!cancelled) {
          setSecrets(data || [])
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || 'Greška prilikom učitavanja podijeljenih tajni.')
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    fetchData()

    return () => {
      cancelled = true
    }
  }, [])

  if (loading) {
    return (
      <section>
        <PageHeader
          title="Shared With Me"
          subtitle="Secrets other users have shared with you."
        />
        <p>Loading shared secrets...</p>
      </section>
    )
  }

  if (error) {
    return (
      <section>
        <PageHeader
          title="Shared With Me"
          subtitle="Secrets other users have shared with you."
        />
        <p className="form__error">{error}</p>
      </section>
    )
  }

  if (secrets.length === 0) {
    return (
      <section>
        <PageHeader
          title="Shared With Me"
          subtitle="Secrets other users have shared with you."
        />
        <div className="card">
          <p>No shared secrets found.</p>
        </div>
      </section>
    )
  }

  return (
    <section>
      <PageHeader
        title="Shared With Me"
        subtitle="Secrets other users have shared with you."
      />

      <ul className="list">
        {secrets.map((secret) => (
          <li key={secret.id} className="list__item">
            <div className="list__row">
              <span className="list__name">{secret.name}</span>
              <span className="badge">shared</span>
            </div>

            <p className="list__meta">
              {secret.description || 'No description'} &middot; Shared{' '}
              {secret.createdAt
                ? new Date(secret.createdAt).toLocaleDateString()
                : 'Unknown'}
            </p>
          </li>
        ))}
      </ul>
    </section>
  )
}