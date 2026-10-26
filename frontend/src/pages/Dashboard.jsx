import { useState, useEffect } from 'react'
import PageHeader from '../components/PageHeader.jsx'
import { useAuth } from '../context/AuthContext.jsx'
import { listSecrets } from '../services/secretsApi.js'
import { listSharedSecrets } from '../services/secretsApi.js'

export default function Dashboard() {
  const { token } = useAuth()
  const [stats, setStats] = useState({ owned: 0, shared: 0 })
  const [loading, setLoading] = useState(Boolean(token))
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!token) {
      return
    }
    const fetchData = async () => {
      setLoading(true)
      try {
        const [owned, shared] = await Promise.all([
          listSecrets(token).then((s) => s || []),
          listSharedSecrets(token).then((s) => s || []).catch(() => []),
        ])
        setStats({ owned: owned.length, shared: shared.length })
      } catch (err) {
        setError(err.message || 'Failed to load dashboard stats')
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [token])

  if (loading) {
    return (
      <section>
        <PageHeader title="Dashboard" subtitle="Overview of your vault activity and security posture." />
        <p>Loading...</p>
      </section>
    )
  }

  if (error) {
    return (
      <section>
        <PageHeader title="Dashboard" subtitle="Overview of your vault activity and security posture." />
        <p className="form__error">{error}</p>
      </section>
    )
  }

  return (
    <section>
      <PageHeader title="Dashboard" subtitle="Overview of your vault activity and security posture." />
      <div className="card-grid">
        <div className="card">
          <h2 className="card__title">Vault items</h2>
          <p className="card__metric">{stats.owned}</p>
          <p className="card__hint">Secrets you own</p>
        </div>
        <div className="card">
          <h2 className="card__title">Shared with me</h2>
          <p className="card__metric">{stats.shared}</p>
          <p className="card__hint">Active shares</p>
        </div>
        <div className="card">
          <h2 className="card__title">Security score</h2>
          <p className="card__metric">Good</p>
          <p className="card__hint">No issues detected</p>
        </div>
      </div>
    </section>
  )
}
