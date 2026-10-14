import PageHeader from '../components/PageHeader.jsx'

export default function SecuritySettings() {
  return (
    <section>
      <PageHeader
        title="Security Settings"
        subtitle="Placeholder for security-related controls. No real settings are wired up yet."
      />
      <div className="card-grid">
        <div className="card">
          <h2 className="card__title">Master password</h2>
          <p className="card__hint">
            Client-side only. It will be used to derive the key encryption key
            (KEK) and is never sent to the server.
          </p>
        </div>
        <div className="card">
          <h2 className="card__title">Encryption keys</h2>
          <p className="card__hint">
            RSA key pair generation and private-key protection will be managed
            here in a later step.
          </p>
        </div>
        <div className="card">
          <h2 className="card__title">Sessions &amp; MFA</h2>
          <p className="card__hint">
            Session management and multi-factor authentication are handled by
            the backend in a later step.
          </p>
        </div>
      </div>
    </section>
  )
}
