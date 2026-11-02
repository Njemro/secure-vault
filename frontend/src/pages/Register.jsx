import { useState } from 'react'
import { Link } from 'react-router-dom'
import './Register.css'
import { register } from '../services/api'
import keycloak from '../auth/keycloak'

export default function Register() {
  const [form, setForm] = useState({
    username: '',
    email: '',
    keycloakPassword: '',
    confirmPassword: '',
  })

  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  function handleChange(event) {
    const { name, value } = event.target

    setForm((current) => ({
      ...current,
      [name]: value,
    }))
  }

  async function handleSubmit(event) {
    event.preventDefault()

    if (loading) return

    setError('')

    const {
      username,
      email,
      keycloakPassword,
      confirmPassword,
    } = form

    if (
      !username.trim() ||
      !email.trim() ||
      !keycloakPassword ||
      !confirmPassword
    ) {
      setError('Popuni sva obavezna polja.')
      return
    }

    if (keycloakPassword !== confirmPassword) {
      setError('Lozinke za prijavu se ne poklapaju.')
      return
    }

    if (keycloakPassword.length < 8) {
      setError('Lozinka za prijavu mora imati najmanje 8 znakova.')
      return
    }

    setLoading(true)

    try {
      await register({
        username: username.trim(),
        email: email.trim(),
        keycloakPassword,
      })

      // Očisti lozinke iz React stanja.
      setForm((current) => ({
        ...current,
        keycloakPassword: '',
        confirmPassword: '',
      }))

      // Keycloak obavlja prijavu i eventualno podešavanje TOTP-a.
      await keycloak.login({
        loginHint: username.trim(),
        redirectUri: `${window.location.origin}/setup-keys`,
      })
    } catch (err) {
      console.error('Registration or login failed:', err)

      setError(
        err?.message ||
          'Registracija ili prijava nisu uspjele. Ako je nalog već kreiran, pokušaj prijavu preko stranice za prijavu.',
      )

      setLoading(false)
    }
  }

  return (
    <main className="register-page">
      <section className="register-card">
        <h1>Kreiraj Secure Vault nalog</h1>

        <p>
          Napravi nalog, podesi autentifikaciju i zaštiti svoje podatke.
        </p>

        <form onSubmit={handleSubmit}>
          <label htmlFor="username">Korisničko ime</label>
          <input
            id="username"
            name="username"
            type="text"
            autoComplete="username"
            value={form.username}
            onChange={handleChange}
            required
            disabled={loading}
          />

          <label htmlFor="email">Email</label>
          <input
            id="email"
            name="email"
            type="email"
            autoComplete="email"
            value={form.email}
            onChange={handleChange}
            required
            disabled={loading}
          />

          <label htmlFor="keycloakPassword">
            Lozinka za prijavu
          </label>
          <input
            id="keycloakPassword"
            name="keycloakPassword"
            type="password"
            autoComplete="new-password"
            value={form.keycloakPassword}
            onChange={handleChange}
            minLength={8}
            required
            disabled={loading}
            aria-describedby="login-password-help"
          />

          <small id="login-password-help">
            Koristi najmanje 8 znakova. Ova lozinka služi za prijavu na
            nalog.
          </small>

          <label htmlFor="confirmPassword">
            Potvrdi lozinku za prijavu
          </label>
          <input
            id="confirmPassword"
            name="confirmPassword"
            type="password"
            autoComplete="new-password"
            value={form.confirmPassword}
            onChange={handleChange}
            minLength={8}
            required
            disabled={loading}
          />

          {error && (
            <p className="register-error" role="alert">
              {error}
            </p>
          )}

          <button type="submit" disabled={loading}>
            {loading ? 'Registracija...' : 'Registruj se'}
          </button>
        </form>

        <p className="register-login-link">
          Već imaš nalog? <Link to="/login">Prijavi se</Link>
        </p>
      </section>
    </main>
  )
}