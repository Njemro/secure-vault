import PageHeader from '../components/PageHeader.jsx'
import { useAuth } from '../context/AuthContext.jsx'

export default function SecuritySettings() {
  const { user } = useAuth()

  return (
    <section>
      <PageHeader
        title="Security Settings"
        subtitle="Manage your account security and encryption keys."
      />

      <div className="card-grid">
        <div className="card">
          <h2 className="card__title">Master Password</h2>
          <p className="card__hint">
            Client-side only. Used to derive the key encryption key (KEK).
            Never sent to the server.
          </p>
        </div>

        <div className="card">
          <h2 className="card__title">Two-Factor Authentication (TOTP)</h2>
          <p className="card__hint">
            TOTP is managed by Keycloak and is used for two-factor
            authentication at login.
          </p>
        </div>

        <div className="card">
          <h2 className="card__title">Encryption Keys</h2>
          <p className="card__hint">
            The public key is stored on the server for sharing.
            The private key is encrypted client-side.
          </p>
          <p className="form__error">
            Key management UI not yet implemented.
          </p>
        </div>

        <div className="card">
          <h2 className="card__title">Sessions</h2>
          <p className="card__hint">
            Currently signed in as:{' '}
            <strong>{user?.preferred_username || '—'}</strong>
          </p>
        </div>
      </div>
    </section>
  )
}