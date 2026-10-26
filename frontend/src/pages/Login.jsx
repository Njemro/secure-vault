import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import PageHeader from '../components/PageHeader.jsx'

export default function Login() {
  const navigate = useNavigate()
  const { signIn, completeMfa, user } = useAuth()
  const [form, setForm] = useState({ username: '', password: '' })
  const [code, setCode] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [stage, setStage] = useState('login') // 'login' | 'mfa' | 'done'
  const [tempToken, setTempToken] = useState(null)

  const updateField = (key, value) => {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  const handleLogin = async (e) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
      const response = await signIn({ username: form.username, password: form.password })

      if (response.mfaRequired && !response.accessToken) {
        // MFA required: the backend issues a temp token. The login response
        // carries user metadata; the client must complete /api/auth/mfa/verify.
        setTempToken(response.accessToken || null)
        setStage('mfa')
      } else {
        setStage('done')
        if (user) {
          navigate('/my-secrets', { replace: true })
        }
      }
    } catch (err) {
      setError(err.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const handleVerifyMfa = async (e) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
      await completeMfa(tempToken, code)
      setStage('done')
      navigate('/my-secrets', { replace: true })
    } catch (err) {
      setError(err.message || 'Verification failed')
    } finally {
      setLoading(false)
    }
  }

  if (stage === 'done') {
    return null
  }

  return (
    <section className="page">
      <PageHeader
        title={stage === 'mfa' ? 'Two-Factor Verification' : 'Sign In'}
        subtitle={
          stage === 'mfa'
            ? 'Enter the verification code from your authenticator app.'
            : 'Sign in to your Secure Vault account.'
        }
      />

      {stage === 'login' && (
        <form onSubmit={handleLogin} className="form">
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
            <label className="form__label">Password</label>
            <input
              className="form__input"
              type="password"
              value={form.password}
              onChange={(e) => updateField('password', e.target.value)}
              placeholder="Your Keycloak password"
              required
              autoComplete="current-password"
            />
            <p className="form__hint">
              This is your Keycloak authentication password. It is separate from
              your vault master password, which is never sent to the server.
            </p>
          </div>
          {error && <p className="form__error">{error}</p>}
          <button type="submit" className="btn btn--primary btn--full" disabled={loading}>
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
          <p className="form__footer">
            Don&apos;t have an account?{' '}
            <a href="/register" className="form__link">
              Create account
            </a>
          </p>
        </form>
      )}

      {stage === 'mfa' && (
        <form onSubmit={handleVerifyMfa} className="form">
          <div className="form__group">
            <label className="form__label">Verification Code</label>
            <input
              className="form__input"
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              maxLength={6}
              placeholder="123456"
              required
              autoComplete="off"
            />
            <p className="form__hint">
              6-digit code from your authenticator app.
            </p>
          </div>
          {error && <p className="form__error">{error}</p>}
          <button type="submit" className="btn btn--primary btn--full" disabled={loading}>
            {loading ? 'Verifying...' : 'Verify Code'}
          </button>
          <p className="form__footer">
            <a href="/register" className="form__link">
              Don&apos;t have an account? Create account
            </a>
          </p>
        </form>
      )}
    </section>
  )
}