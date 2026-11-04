
import { useEffect, useState } from 'react'
import {
  getSecurityPolicy,
  updateSecurityPolicy,
} from '../services/securityPolicyApi.js'
import './AdminSecurityPolicies.css'

const initialPolicy = {
  minMasterPasswordLength: 12,
  secretRotationIntervalDays: 90,
  sessionInactivityTimeoutMinutes: 30,
  maxSessionDurationMinutes: 600,
}

export default function AdminSecurityPolicies() {
  const [policy, setPolicy] = useState(initialPolicy)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  useEffect(() => {
    let active = true

    async function loadPolicy() {
      try {
        setLoading(true)
        setError('')

        const data = await getSecurityPolicy()

        if (active) {
          setPolicy({
            minMasterPasswordLength: data.minMasterPasswordLength,
            secretRotationIntervalDays: data.secretRotationIntervalDays,
            sessionInactivityTimeoutMinutes:
              data.sessionInactivityTimeoutMinutes,
            maxSessionDurationMinutes:
              data.maxSessionDurationMinutes,
          })
        }
      } catch (err) {
        if (active) {
          setError(err.message || 'Učitavanje sigurnosnih politika nije uspjelo.')
        }
      } finally {
        if (active) setLoading(false)
      }
    }

    loadPolicy()

    return () => {
      active = false
    }
  }, [])

  function handleChange(event) {
    const { name, value } = event.target

    setPolicy(current => ({
      ...current,
      [name]: value === '' ? '' : Number(value),
    }))

    setSuccess('')
  }

  async function handleSubmit(event) {
    event.preventDefault()
    setError('')
    setSuccess('')

    const minLength = Number(policy.minMasterPasswordLength)
    const rotationDays = Number(policy.secretRotationIntervalDays)
    const inactivity = Number(policy.sessionInactivityTimeoutMinutes)
    const maxDuration = Number(policy.maxSessionDurationMinutes)

    if (
      !Number.isInteger(minLength) || minLength < 8 ||
      !Number.isInteger(rotationDays) || rotationDays < 1 ||
      !Number.isInteger(inactivity) || inactivity < 1 ||
      !Number.isInteger(maxDuration) || maxDuration < 1
    ) {
      setError('Unesene vrijednosti moraju biti cijeli pozitivni brojevi. Minimalna dužina mora biti najmanje 8.')
      return
    }

    if (maxDuration < inactivity) {
      setError('Maksimalno trajanje sesije ne može biti kraće od intervala neaktivnosti.')
      return
    }

    try {
      setSaving(true)

      const updated = await updateSecurityPolicy({
        minMasterPasswordLength: minLength,
        secretRotationIntervalDays: rotationDays,
        sessionInactivityTimeoutMinutes: inactivity,
        maxSessionDurationMinutes: maxDuration,
      })

      setPolicy({
        minMasterPasswordLength: updated.minMasterPasswordLength,
        secretRotationIntervalDays: updated.secretRotationIntervalDays,
        sessionInactivityTimeoutMinutes:
          updated.sessionInactivityTimeoutMinutes,
        maxSessionDurationMinutes: updated.maxSessionDurationMinutes,
      })

      setSuccess('Sigurnosne politike su uspješno sačuvane.')
    } catch (err) {
      setError(err.message || 'Čuvanje sigurnosnih politika nije uspjelo.')
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <main className="admin-policies">
        <p>Učitavanje sigurnosnih politika...</p>
      </main>
    )
  }

  if (error && !policy) {
    return (
      <main className="admin-policies">
        <p className="policy-message policy-message--error">{error}</p>
      </main>
    )
  }

  return (
    <main className="admin-policies">
      <header className="admin-policies__header">
        <div>
          <p className="admin-policies__eyebrow">ADMINISTRACIJA</p>
          <h1>Sigurnosne politike</h1>
          <p>
            Upravljanje pravilima za master lozinku, rotaciju tajni i trajanje sesije.
          </p>
        </div>
      </header>

      <form className="policy-form" onSubmit={handleSubmit}>
        <section className="policy-card">
          <div>
            <h2>Minimalna dužina master lozinke</h2>
            <p>
              Najmanji broj znakova koji master lozinka mora sadržavati
              prilikom prvog podešavanja trezora.
            </p>
          </div>

          <label className="policy-field">
            <span>Minimalan broj znakova</span>
            <input
              type="number"
              name="minMasterPasswordLength"
              min="8"
              step="1"
              required
              value={policy.minMasterPasswordLength}
              onChange={handleChange}
            />
          </label>
        </section>

        <section className="policy-card">
          <div>
            <h2>Obavezna rotacija tajni</h2>
            <p>
              Broj dana nakon kojeg se tajna smatra dospjelom za rotaciju.
            </p>
          </div>

          <label className="policy-field">
            <span>Interval rotacije (dana)</span>
            <input
              type="number"
              name="secretRotationIntervalDays"
              min="1"
              step="1"
              required
              value={policy.secretRotationIntervalDays}
              onChange={handleChange}
            />
          </label>
        </section>

        <section className="policy-card">
          <div>
            <h2>Istek sesije zbog neaktivnosti</h2>
            <p>
              Sesija se prekida ako korisnik ne izvrši API aktivnost
              tokom definisanog perioda.
            </p>
          </div>

          <label className="policy-field">
            <span>Period neaktivnosti (minuta)</span>
            <input
              type="number"
              name="sessionInactivityTimeoutMinutes"
              min="1"
              step="1"
              required
              value={policy.sessionInactivityTimeoutMinutes}
              onChange={handleChange}
            />
          </label>
        </section>

        <section className="policy-card">
          <div>
            <h2>Maksimalno trajanje sesije</h2>
            <p>
              Najduže vrijeme od početka sesije, bez obzira na aktivnost korisnika.
            </p>
          </div>

          <label className="policy-field">
            <span>Maksimalno trajanje (minuta)</span>
            <input
              type="number"
              name="maxSessionDurationMinutes"
              min="1"
              step="1"
              required
              value={policy.maxSessionDurationMinutes}
              onChange={handleChange}
            />
          </label>
        </section>

        {error && (
          <p className="policy-message policy-message--error" role="alert">
            {error}
          </p>
        )}

        {success && (
          <p className="policy-message policy-message--success" role="status">
            {success}
          </p>
        )}

        <div className="policy-actions">
          <button type="submit" disabled={saving}>
            {saving ? 'Čuvanje...' : 'Sačuvaj politike'}
          </button>
        </div>
      </form>
    </main>
  )
}