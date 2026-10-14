import PageHeader from '../components/PageHeader.jsx'
import { mockSecrets } from '../data/mockData.js'

export default function MySecrets() {
  return (
    <section>
      <PageHeader
        title="My Secrets"
        subtitle="Secrets you own. Content is encrypted client-side and shown here as mock data."
      />
      <ul className="list">
        {mockSecrets.map((secret) => (
          <li key={secret.id} className="list__item">
            <div className="list__row">
              <span className="list__name">{secret.name}</span>
              <span className="badge">{secret.type}</span>
            </div>
            <p className="list__meta">
              Updated {secret.updatedAt} &middot; Owner: you
            </p>
          </li>
        ))}
      </ul>
    </section>
  )
}
