import PageHeader from '../components/PageHeader.jsx'

export default function Dashboard() {
  return (
    <section>
      <PageHeader
        title="Dashboard"
        subtitle="Overview of your vault activity and security posture."
      />
      <div className="card-grid">
        <div className="card">
          <h2 className="card__title">Vault items</h2>
          <p className="card__metric">12</p>
          <p className="card__hint">Secrets stored (mock)</p>
        </div>
        <div className="card">
          <h2 className="card__title">Shared with me</h2>
          <p className="card__metric">3</p>
          <p className="card__hint">Active shares (mock)</p>
        </div>
        <div className="card">
          <h2 className="card__title">Security score</h2>
          <p className="card__metric">Good</p>
          <p className="card__hint">No issues detected (mock)</p>
        </div>
      </div>
    </section>
  )
}
