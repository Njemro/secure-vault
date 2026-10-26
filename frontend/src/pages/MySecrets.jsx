import { useState, useEffect } from 'react'
import PageHeader from '../components/PageHeader.jsx'
import { useAuth } from '../context/AuthContext.jsx'
import { listSecrets } from '../services/secretsApi.js'

export default function MySecrets() {
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
        const data = await listSecrets(token)
        setSecrets(data || [])
      } catch (err) {
        setError(err.message || 'Failed to load secrets')
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
          title="My Secrets"
          subtitle="Secrets you own. Content is encrypted client-side."
        />
        <p>Loading your secrets...</p>
      </section>
    )
  }

  if (error) {
    return (
      <section>
        <PageHeader
          title="My Secrets"
          subtitle="Secrets you own. Content is encrypted client-side."
        />
        <p className="form__error">{error}</p>
      </section>
    )
  }

  if (secrets.length === 0) {
    return (
      <section>
        <PageHeader
          title="My Secrets"
          subtitle="Secrets you own. Content is encrypted client-side."
        />
        <div className="card">
          <p>No secrets found. Create your first secret to get started.</p>
        </div>
      </section>
    )
  }

  return (
    <section>
      <PageHeader
        title="My Secrets"
        subtitle="Secrets you own. Content is encrypted client-side."
      />
      <ul className="list">
        {secrets.map((secret) => (
          <li key={secret.id} className="list__item">
            <div className="list__row">
              <span className="list__name">{secret.name}</span>
              <span className="badge">{secret.encryptionAlgorithm}</span>
            </div>
            <p className="list__meta">
              {secret.description || 'No description'} &middot;
              Created {new Date(secret.createdAt).toLocaleDateString()}
            </p>
          </li>
        ))}
      </ul>
    </section>
  )
}
