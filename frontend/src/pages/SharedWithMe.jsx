import { useState, useEffect } from 'react'
import PageHeader from '../components/PageHeader.jsx'
import { useAuth } from '../context/AuthContext.jsx'
import { listSharedSecrets } from '../services/secretsApi.js'

export default function SharedWithMe() {
  const { token } = useAuth()
  const [secrets, setSecrets] = useState([])
  const [loading, setLoading] = useState(Boolean(token))
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!token) {
      const reset = () => {
        setSecrets([])
      }
      reset()
      return
    }
    const fetchData = async () => {
      setLoading(true)
      try {
        const data = await listSharedSecrets(token)
        setSecrets(data || [])
      } catch (err) {
        setError(err.message || 'Failed to load shared secrets')
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [token])

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
              {secret.description || 'No description'} &middot;
              Shared {new Date(secret.createdAt).toLocaleDateString()}
            </p>
          </li>
        ))}
      </ul>
    </section>
  )
}
