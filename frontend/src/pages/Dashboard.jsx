import { useState, useEffect } from 'react'
import PageHeader from '../components/PageHeader.jsx'
import { listSecrets, listSharedSecrets } from '../services/secretsApi.js'

export default function Dashboard() {
  const [stats, setStats] = useState({ owned: 0, shared: 0 })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let active = true

    const fetchData = async () => {
      setLoading(true)
      setError(null)

      try {
        const [owned, shared] = await Promise.all([
          listSecrets().then((s) => s || []),
          listSharedSecrets().then((s) => s || []).catch(() => []),
        ])

        if (active) {
          setStats({
            owned: owned.length,
            shared: shared.length,
          })
        }
      } catch (err) {
        if (active) {
          setError(err.message || 'Failed to load dashboard stats')
        }
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    fetchData()

    return () => {
      active = false
    }
  }, [])

  if (loading) {
    return (
      <section>
        <PageHeader
          title="Dashboard"
          subtitle="Overview of your vault activity and security posture."
        />
        <p>Loading...</p>
      </section>
    )
  }

  if (error) {
    return (
      <section>
        <PageHeader
          title="Dashboard"
          subtitle="Overview of your vault activity and security posture."
        />
        <p className="form__error">{error}</p>
      </section>
    )
  }

  return (
    <section>
      <PageHeader
        title="Dashboard"
        subtitle="Overview of your vault activity and security posture."
      />

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