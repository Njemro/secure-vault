import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import PageHeader from '../components/PageHeader.jsx'
import {
  generateRsaKeyPair,
  exportPublicKeySpki,
  exportPrivateKeyPkcs8,
  generateSalt,
  deriveKek,
  encryptPrivateKey,
  bytesToBase64,
} from '../crypto/index.js'
import {
  register,
  loginWithKeycloak,
  registerKeys,
} from '../services/api.js'

const STEPS = {
  REGISTER: 'register',
  SETUP_KEYS: 'setup-keys',
  SUCCESS: 'success',
}

export default function Register() {
  const navigate = useNavigate()
  const [step, setStep] = useState(STEPS.REGISTER)
  const [form, setForm] = useState({
    username: '',
    email: '',
    keycloakPassword: '',
    masterPassword: '',
    confirmMasterPassword: '',
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [progress, setProgress] = useState(0)

  const updateField = (key, value) => {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  const handleRegister = async (e) => {
    e.preventDefault()
    setError(null)
    setLoading(true)
    setProgress(0)

    if (form.masterPassword !== form.confirmMasterPassword) {
      setError('Master passwords do not match')
      setLoading(false)
      return
    }

    try {
      setProgress(10)
      await register({
        username: form.username,
        email: form.email,
        keycloakPassword: form.keycloakPassword,
      })

      setProgress(30)
      const accessToken = await loginWithKeycloak(
        form.username,
        form.keycloakPassword
      )

      setProgress(50)
      const keyPair = await generateRsaKeyPair()
      const publicKeyBytes = await exportPublicKeySpki(keyPair.publicKey)
      const privateKeyBytes = await exportPrivateKeyPkcs8(keyPair.privateKey)

      const salt = generateSalt()
      const kek = await deriveKek(form.masterPassword, salt)
      const encryptedPrivateKeyEnvelope = await encryptPrivateKey(
        kek,
        privateKeyBytes
      )

      setProgress(70)
      await registerKeys(accessToken, {
        publicKey: bytesToBase64(publicKeyBytes),
        encryptedPrivateKey: bytesToBase64(
          encryptedPrivateKeyEnvelope.ciphertext
        ),
        privateKeyIv: bytesToBase64(encryptedPrivateKeyEnvelope.iv),
        kdfAlgorithm: 'PBKDF2-HMAC-SHA-256',
        kdfParameters: JSON.stringify({
          iterations: 600_000,
          hash: 'SHA-256',
          salt: bytesToBase64(salt),
        }),
      })

      setProgress(100)
      setStep(STEPS.SUCCESS)
    } catch (err) {
      setError(err.message || 'Registration failed')
      setLoading(false)
      setProgress(0)
    }
  }

  const isRegisterStep = step === STEPS.REGISTER
  const isSetupStep = step === STEPS.SETUP_KEYS
  const isSuccess = step === STEPS.SUCCESS

  return (
    <section className="page">
      <PageHeader
        title={
          isSuccess
            ? 'Account Created'
            : isSetupStep
            ? 'Set Up Encryption Keys'
            : 'Create Account'
        }
        subtitle={
          isSuccess
            ? 'Your Secure Vault account is ready.'
            : isSetupStep
            ? 'Derive your key encryption key and register your RSA key pair.'
            : 'Enter your account details. The master password stays client-side.'
        }
      />

      {isSuccess && (
        <div className="card">
          <div className="progress">
            <div className="progress__bar" style={{ width: '100%' }} />
          </div>
          <h2 className="card__title">Registration Complete</h2>
          <p className="card__hint">
            Your Keycloak account and local user record have been created, and
            your client-encrypted RSA key pair has been registered. You can now
            log in and use your vault.
          </p>
          <button
            type="button"
            className="btn btn--primary"
            onClick={() => navigate('/')}
          >
            Go to Dashboard
          </button>
        </div>
      )}

      {!isSuccess && (
        <>
          {error && (
            <div className="card card--error">
              <p className="card__error">{error}</p>
            </div>
          )}

          {isRegisterStep && (
            <form className="card" onSubmit={handleRegister}>
              <div className="form__group">
                <label className="form__label">Username</label>
                <input
                  className="form__input"
                  type="text"
                  value={form.username}
                  onChange={(e) => updateField('username', e.target.value)}
                  placeholder="e.g. alice"
                  required
                  autoComplete="username"
                />
              </div>
              <div className="form__group">
                <label className="form__label">Email</label>
                <input
                  className="form__input"
                  type="email"
                  value={form.email}
                  onChange={(e) => updateField('email', e.target.value)}
                  placeholder="e.g. alice@example.com"
                  required
                  autoComplete="email"
                />
              </div>
              <div className="form__group">
                <label className="form__label">
                  Keycloak Password (for logging in)
                </label>
                <input
                  className="form__input"
                  type="password"
                  value={form.keycloakPassword}
                  onChange={(e) =>
                    updateField('keycloakPassword', e.target.value)
                  }
                  placeholder="At least 8 characters"
                  required
                  autoComplete="new-password"
                />
                <p className="form__hint">
                  This is your Keycloak authentication password. It is separate
                  from your vault master password below.
                </p>
              </div>
              <div className="form__group">
                <label className="form__label">Master Password (vault encryption)</label>
                <input
                  className="form__input"
                  type="password"
                  value={form.masterPassword}
                  onChange={(e) => updateField('masterPassword', e.target.value)}
                  placeholder="Used to derive your key encryption key"
                  required
                  autoComplete="new-password"
                />
                <p className="form__hint">
                  Client-side only. Never sent to the server. Used to derive
                  the KEK that protects your private key.
                </p>
              </div>
              <div className="form__group">
                <label className="form__label">Confirm Master Password</label>
                <input
                  className="form__input"
                  type="password"
                  value={form.confirmMasterPassword}
                  onChange={(e) => updateField('confirmMasterPassword', e.target.value)}
                  placeholder="Repeat your master password"
                  required
                  autoComplete="new-password"
                />
              </div>
              <button
                type="submit"
                className="btn btn--primary btn--full"
                disabled={loading}
              >
                {loading ? 'Creating account...' : 'Create Account'}
              </button>
              <div className="progress">
                <div
                  className="progress__bar"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </form>
          )}

          {isSetupStep && (
            <div className="card">
              <h2 className="card__title">Key Setup in Progress</h2>
              <p className="card__hint">
                Your RSA key pair is being generated and your private key is
                being encrypted with your master password.
              </p>
              <div className="progress">
                <div className="progress__bar" style={{ width: `${progress}%` }} />
              </div>
            </div>
          )}
        </>
      )}
    </section>
  )
}
