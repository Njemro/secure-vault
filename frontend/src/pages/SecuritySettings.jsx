import { useState, useEffect } from 'react'
import PageHeader from '../components/PageHeader.jsx'
import { useAuth } from '../context/AuthContext.jsx'
import { enrollMfa, confirmMfa, disableMfa } from '../services/mfaApi.js'

export default function SecuritySettings() {
  const { token, user, checkMfaStatus } = useAuth()
  const [status, setStatus] = useState(null)
  const [loading, setLoading] = useState(Boolean(token))
  const [error, setError] = useState(null)
  const [enrollLoading, setEnrollLoading] = useState(false)
  const [provisioningUri, setProvisioningUri] = useState(null)
  const [secret, setSecret] = useState(null)
  const [confirmCode, setConfirmCode] = useState('')
  const [disableCode, setDisableCode] = useState('')
  const [stage, setStage] = useState('status')

  useEffect(() => {
    if (!token) {
      return
    }
    const fetchData = async () => {
      setLoading(true)
      try {
        const data = await checkMfaStatus()
        setStatus(data)
      } catch (err) {
        setError(err.message || 'Failed to load MFA status')
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [token, checkMfaStatus])

  const handleEnroll = async () => {
    setError(null)
    setEnrollLoading(true)
    try {
      const result = await enrollMfa(token)
      setProvisioningUri(result.provisioningUri)
      setSecret(result.secret)
      setStage('confirm')
    } catch (err) {
      setError(err.message || 'MFA enrollment failed')
    } finally {
      setEnrollLoading(false)
    }
  }

  const handleConfirm = async (e) => {
    e.preventDefault()
    setError(null)
    try {
      await confirmMfa(token, confirmCode)
      setStage('status')
      await checkMfaStatus().then((data) => setStatus(data))
    } catch (err) {
      setError(err.message || 'Confirmation failed')
    }
  }

  const handleDisable = async (e) => {
    e.preventDefault()
    setError(null)
    try {
      await disableMfa(token, disableCode)
      await checkMfaStatus().then((data) => setStatus(data))
    } catch (err) {
      setError(err.message || 'Disable failed')
    }
  }

  if (loading) {
    return (
      <section>
        <PageHeader title="Security Settings" subtitle="Manage your account security." />
        <p>Loading...</p>
      </section>
    )
  }

  const mfaEnabled = status?.mfaEnabled || false
  const mfaEnrolled = status?.mfaEnrolled || false

  return (
    <section>
      <PageHeader
        title="Security Settings"
        subtitle="Manage your account security, MFA, and encryption keys."
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
          <h2 className="card__title">Multi-Factor Authentication (TOTP)</h2>
          <p className="card__hint">
            {mfaEnabled
              ? 'MFA is enabled and enforced at login.'
              : mfaEnrolled
              ? 'MFA is enrolled but not yet enforced.'
              : 'MFA is not enabled.'}
          </p>
          {mfaEnabled ? (
            <form onSubmit={handleDisable} className="form">
              <div className="form__group">
                <label className="form__label">Disable MFA (verification code)</label>
                <input
                  className="form__input"
                  type="text"
                  value={disableCode}
                  onChange={(e) => setDisableCode(e.target.value)}
                  maxLength={6}
                  placeholder="123456"
                  required
                />
              </div>
              {error && <p className="form__error">{error}</p>}
              <button type="submit" className="btn btn--danger btn--full">
                Disable MFA
              </button>
            </form>
          ) : (
            <>
              <button
                type="button"
                className="btn btn--primary btn--full"
                onClick={handleEnroll}
                disabled={enrollLoading}
              >
                {enrollLoading ? 'Enrolling...' : 'Enable MFA'}
              </button>
              {stage === 'confirm' && (
                <div className="card" style={{ marginTop: '1rem' }}>
                  <h3 className="card__title">Enroll MFA</h3>
                  <p className="form__hint">
                    Scan the QR code with your authenticator app, or enter the
                    secret manually:
                  </p>
                  {provisioningUri && (
                    <p>
                      <strong>Provisioning URI:</strong> {provisioningUri}
                    </p>
                  )}
                  {secret && (
                    <p>
                      <strong>Secret (show once):</strong> {secret}
                    </p>
                  )}
                  <form onSubmit={handleConfirm} className="form">
                    <div className="form__group">
                      <label className="form__label">Verification Code</label>
                      <input
                        className="form__input"
                        type="text"
                        value={confirmCode}
                        onChange={(e) => setConfirmCode(e.target.value)}
                        maxLength={6}
                        placeholder="123456"
                        required
                      />
                    </div>
                    {error && <p className="form__error">{error}</p>}
                    <button type="submit" className="btn btn--primary btn--full">
                      Confirm & Enable
                    </button>
                  </form>
                </div>
              )}
            </>
          )}
        </div>

        <div className="card">
          <h2 className="card__title">Encryption Keys</h2>
          <p className="card__hint">
            RSA key pair management. Public key is stored on the server for
            sharing; the private key is encrypted client-side.
          </p>
          <p className="form__error">
            Key management UI not yet implemented.
          </p>
        </div>

        <div className="card">
          <h2 className="card__title">Sessions</h2>
          <p className="card__hint">
            Currently signed in as:{' '}
            <strong>{user?.username || '—'}</strong> ({user?.role || '—'}).
          </p>
        </div>
      </div>
    </section>
  )
}
