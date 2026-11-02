import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import './Login.css'
import { useAuth } from '../context/AuthContext'

export default function Login() {
  const { signIn } = useAuth()
  const [searchParams] = useSearchParams()

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const sessionExpired = searchParams.get('reason') === 'session-expired'

  async function handleLogin() {
    setLoading(true)
    setError('')

    try {
      await signIn()
    } catch (err) {
      console.error('Login failed:', err)
      setError('Prijava nije uspjela. Provjeri da li je Keycloak dostupan.')
      setLoading(false)
    }
  }

  return (
    <main className="login-page">
      <section className="login-card">
        <h1>Prijava u Secure Vault</h1>

        <p>Prijavi se preko sigurnog Keycloak sistema.</p>

        {sessionExpired && (
          <p role="alert" className="login-info">
            Tvoja sesija je istekla. Prijavi se ponovo da nastaviš koristiti
            Secure Vault.
          </p>
        )}

        {error && (
          <p role="alert" className="login-error">
            {error}
          </p>
        )}

        <button type="button" onClick={handleLogin} disabled={loading}>
          {loading ? 'Preusmjeravanje...' : 'Prijavi se'}
        </button>

        <p>
          Nemaš nalog? <Link to="/register">Registruj se</Link>
        </p>
      </section>
    </main>
  )
}