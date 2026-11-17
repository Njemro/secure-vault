import { useCallback, useEffect, useState } from 'react'
import PageHeader from '../components/PageHeader.jsx'
import {
  disableHoneypotDemo,
  enableHoneypotDemo,
  getHoneypotDemoStatus,
  getSecurityIncidents,
} from '../services/securityIncidentsApi.js'
import './AdminSecurityIncidents.css'

const formatDate = (value) => {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function formatMetadata(value) {
  if (!value) return '—'
  try {
    return JSON.stringify(JSON.parse(value), null, 2)
  } catch {
    return value
  }
}

export default function AdminSecurityIncidents() {
  const [incidents, setIncidents] = useState([])
  const [demoStatus, setDemoStatus] = useState(null)
  const [duration, setDuration] = useState('5')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const loadData = useCallback(async (showLoading = true) => {
    if (showLoading) setLoading(true)
    setError('')

    const [statusResult, incidentsResult] = await Promise.allSettled([
      getHoneypotDemoStatus(),
      getSecurityIncidents(),
    ])

    if (statusResult.status === 'fulfilled') {
      setDemoStatus(statusResult.value)
    } else {
      setError(statusResult.reason?.message || 'Nije moguće učitati status demonstracije.')
    }

    if (incidentsResult.status === 'fulfilled') {
      setIncidents(Array.isArray(incidentsResult.value) ? incidentsResult.value : [])
    } else {
      setError((current) => current
        ? `${current} ${incidentsResult.reason?.message || 'Nije moguće učitati incidente.'}`
        : incidentsResult.reason?.message || 'Nije moguće učitati incidente.')
    }

    if (showLoading) setLoading(false)
  }, [])

  useEffect(() => {
    let cancelled = false

    async function initialLoad() {
      const [statusResult, incidentsResult] = await Promise.allSettled([
        getHoneypotDemoStatus(),
        getSecurityIncidents(),
      ])

      if (cancelled) return

      if (statusResult.status === 'fulfilled') setDemoStatus(statusResult.value)
      else setError(statusResult.reason?.message || 'Nije moguće učitati status demonstracije.')

      if (incidentsResult.status === 'fulfilled') {
        setIncidents(Array.isArray(incidentsResult.value) ? incidentsResult.value : [])
      } else {
        setError((current) => current
          ? `${current} ${incidentsResult.reason?.message || 'Nije moguće učitati incidente.'}`
          : incidentsResult.reason?.message || 'Nije moguće učitati incidente.')
      }

      setLoading(false)
    }

    initialLoad()
    return () => { cancelled = true }
  }, [])

  async function handleEnable() {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const result = await enableHoneypotDemo(Number(duration))
      setDemoStatus(result)
      setNotice(`SQL Injection demonstracija je uključena na ${duration} minuta.`)
    } catch (err) {
      setError(err.message || 'Nije moguće uključiti demonstraciju.')
    } finally {
      setBusy(false)
    }
  }

  async function handleDisable() {
    if (!window.confirm('Da li sigurno želiš isključiti SQL Injection demonstraciju?')) return

    setBusy(true)
    setError('')
    setNotice('')
    try {
      await disableHoneypotDemo()
      setDemoStatus((current) => current
        ? { ...current, enabled: false, enabledUntil: null, enabledBy: null }
        : current)
      setNotice('SQL Injection demonstracija je isključena.')
    } catch (err) {
      setError(err.message || 'Nije moguće isključiti demonstraciju.')
    } finally {
      setBusy(false)
    }
  }

  const demoEnabled = demoStatus?.enabled === true

  return (
    <section className="admin-incidents-page">
      <PageHeader
        title="Sigurnosni incidenti"
        subtitle="Pregled detektovanih honeypot pristupa i kontrola izolovane SQL Injection demonstracije."
      />

      {error && <div className="admin-incidents-alert admin-incidents-alert--error" role="alert">{error}</div>}
      {notice && <div className="admin-incidents-alert admin-incidents-alert--success" role="status">{notice}</div>}

      <section className="admin-incidents-panel" aria-labelledby="honeypot-demo-title">
        <div className="admin-incidents-panel__heading">
          <div>
            <p className="admin-incidents-eyebrow">TESTNO OKRUŽENJE</p>
            <h2 id="honeypot-demo-title">SQL Injection demonstracija</h2>
            <p>Namjerno ranjivi endpoint radi isključivo nad izolovanom tabelom <code>honeypot_secrets</code>.</p>
          </div>
          <span className={`admin-incidents-state ${demoEnabled ? 'admin-incidents-state--on' : 'admin-incidents-state--off'}`}>
            {demoEnabled ? 'Uključena' : 'Isključena'}
          </span>
        </div>

        <div className="admin-incidents-demo-meta">
          <div>
            <span>Aktivirao</span>
            <strong>{demoStatus?.enabledBy || '—'}</strong>
          </div>
          <div>
            <span>Vrijeme isteka</span>
            <strong>{formatDate(demoStatus?.enabledUntil)}</strong>
          </div>
        </div>

        <div className="admin-incidents-demo-actions">
          <label className="admin-incidents-duration">
            Trajanje demonstracije
            <select value={duration} onChange={(event) => setDuration(event.target.value)} disabled={busy}>
              <option value="1">1 minut</option>
              <option value="5">5 minuta</option>
              <option value="10">10 minuta</option>
              <option value="15">15 minuta</option>
              <option value="30">30 minuta</option>
            </select>
          </label>
          <div className="admin-incidents-buttons">
            <button type="button" className="admin-incidents-button admin-incidents-button--primary" onClick={handleEnable} disabled={busy}>
              {busy ? 'Obrada...' : demoEnabled ? 'Produži demonstraciju' : 'Uključi demonstraciju'}
            </button>
            <button type="button" className="admin-incidents-button admin-incidents-button--danger" onClick={handleDisable} disabled={busy || !demoEnabled}>
              Isključi
            </button>
          </div>
        </div>

        <div className="admin-incidents-warning">
          <strong>Važno za testiranje:</strong> pristup honeytoken zapisu automatski suspenduje nalog koji je poslao zahtjev.
          Testirati sa posebnim aktivnim DEVELOPER nalogom, nikako sa administratorskim nalogom.
          Demonstracija se automatski isključuje nakon izabranog vremena.
        </div>

        <div className="admin-incidents-endpoint">
          <span>Testni endpoint</span>
          <code>GET /api/honeypot/demo/search?term=...</code>
          <span>Primjer testnog unosa (URL-encode vrijednost parametra):</span>
          <code>&apos; OR &apos;1&apos;=&apos;1&apos; -- </code>
        </div>
      </section>

      <section className="admin-incidents-list" aria-labelledby="incidents-list-title">
        <div className="admin-incidents-list__heading">
          <div>
            <h2 id="incidents-list-title">Evidencija incidenata</h2>
            <p>Prikazuje se posljednjih 100 sigurnosnih događaja.</p>
          </div>
          <button type="button" className="admin-incidents-button" onClick={() => loadData(true)} disabled={loading}>
            Osvježi
          </button>
        </div>

        <div className="admin-incidents-table-wrap">
          <table className="admin-incidents-table">
            <thead>
              <tr>
                <th>Vrijeme</th>
                <th>Događaj</th>
                <th>Korisnik</th>
                <th>IP adresa</th>
                <th>Detalji</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan="5" className="admin-incidents-empty">Učitavanje incidenata...</td></tr>
              ) : incidents.length === 0 ? (
                <tr><td colSpan="5" className="admin-incidents-empty">Nema evidentiranih sigurnosnih incidenata.</td></tr>
              ) : incidents.map((incident) => (
                <tr key={incident.id}>
                  <td className="admin-incidents-nowrap">{formatDate(incident.eventTime)}</td>
                  <td><span className="admin-incidents-event">{incident.eventType || '—'}</span></td>
                  <td>{incident.username || 'Nepoznat korisnik'}</td>
                  <td>{incident.sourceIp || '—'}</td>
                  <td><pre className="admin-incidents-metadata">{formatMetadata(incident.metadata)}</pre></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="admin-incidents-footnote">
          
        </p>
      </section>
    </section>
  )
}
