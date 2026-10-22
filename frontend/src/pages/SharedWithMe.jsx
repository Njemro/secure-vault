import PageHeader from '../components/PageHeader.jsx'
import { mockSharedSecrets } from '../data/mockData.js'

export default function SharedWithMe() {
  return (
    <section>
      <PageHeader
        title="Shared With Me"
        subtitle="Secrets other users have shared with you (mock data)."
      />
      <ul className="list">
        {mockSharedSecrets.map((secret) => (
          <li key={secret.id} className="list__item">
            <div className="list__row">
              <span className="list__name">{secret.name}</span>
              <span className="badge">{secret.type}</span>
            </div>
            <p className="list__meta">Shared by {secret.sharedBy}</p>
          </li>
        ))}
      </ul>
    </section>
  )
}
