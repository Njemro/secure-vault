import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import { useVault } from '../context/VaultContext.jsx'
import {
  listSecrets,
  getSecret,
  shareSecret,
} from '../services/secretsApi.js'
import { getSecurityPolicy } from '../services/securityPolicyApi.js'
import { getSecretRotationInfo, formatRotationDate } from '../utils/secretRotation.js'
import {
  listDevelopers,
  getPublicKey,
} from '../services/usersApi.js'

export default function MySecrets() {
  const { user } = useAuth()
  const { unlocked, prepareSecretForSharing } = useVault()

  const [secrets, setSecrets] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [rotationIntervalDays, setRotationIntervalDays] = useState(null)

  const [sharingSecret, setSharingSecret] = useState(null)
  const [developers, setDevelopers] = useState([])
  const [selectedDevelopers, setSelectedDevelopers] = useState([])
  const [loadingDevelopers, setLoadingDevelopers] = useState(false)
  const [sharing, setSharing] = useState(false)
  const [shareError, setShareError] = useState('')
  const [shareSuccess, setShareSuccess] = useState('')

  const realmRoles = user?.realm_access?.roles || []
  const clientRoles = Object.values(user?.resource_access || {}).flatMap(
    (client) => client?.roles || []
  )

  const isTeamLead =
    realmRoles.includes('TEAM_LEAD') ||
    clientRoles.includes('TEAM_LEAD')

  useEffect(() => {
    let cancelled = false

    async function fetchSecrets() {
      setLoading(true)
      setError('')

      try {
        const [data, policy] = await Promise.all([listSecrets(), getSecurityPolicy()])

        if (!cancelled) {
          setSecrets(Array.isArray(data) ? data : [])
          setRotationIntervalDays(policy.secretRotationIntervalDays)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || 'Greška prilikom učitavanja tajni.')
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    fetchSecrets()

    return () => {
      cancelled = true
    }
  }, [])

  async function openShareModal(secret) {
    setSharingSecret(secret)
    setSelectedDevelopers([])
    setShareError('')
    setShareSuccess('')
    setDevelopers([])
    setLoadingDevelopers(true)

    try {
      const data = await listDevelopers()
      setDevelopers(Array.isArray(data) ? data : [])
    } catch (err) {
      setShareError(
        err.message || 'Greška prilikom učitavanja liste Developera.'
      )
    } finally {
      setLoadingDevelopers(false)
    }
  }

  function closeShareModal() {
    if (sharing) return

    setSharingSecret(null)
    setSelectedDevelopers([])
    setShareError('')
    setShareSuccess('')
  }

  function toggleDeveloper(developerId) {
    setSelectedDevelopers((current) =>
      current.includes(developerId)
        ? current.filter((id) => id !== developerId)
        : [...current, developerId]
    )
  }

  async function handleShare() {
    if (!sharingSecret) return

    if (!unlocked) {
      setShareError('Prvo otključaj trezor da bi mogao/la dijeliti tajne.')
      return
    }

    if (selectedDevelopers.length === 0) {
      setShareError('Izaberi najmanje jednog Developera.')
      return
    }

    setSharing(true)
    setShareError('')
    setShareSuccess('')

    try {
      // Učitavamo kompletne podatke tajne, uključujući owner encrypted DEK.
      const secretDetails = await getSecret(sharingSecret.id)

      if (!secretDetails?.encryptedDek || !secretDetails?.dekIv) {
        throw new Error(
          'Tajna ne sadrži potrebne podatke za dijeljenje.'
        )
      }

      const recipients = []

      for (const developerId of selectedDevelopers) {
        const publicKeyResponse = await getPublicKey(developerId)

        if (!publicKeyResponse?.publicKey) {
          throw new Error(
            `Javni ključ korisnika ${developerId} nije dostupan.`
          )
        }

        const encryptedDek = await prepareSecretForSharing(
          secretDetails,
          publicKeyResponse.publicKey
        )

        recipients.push({
          recipientId: developerId,
          encryptedDek,
        })
      }

      await shareSecret(sharingSecret.id, recipients)

      setShareSuccess('Tajna je uspješno podijeljena.')

      setSelectedDevelopers([])
    } catch (err) {
      setShareError(
        err.message || 'Greška prilikom dijeljenja tajne.'
      )
    } finally {
      setSharing(false)
    }
  }

  if (loading) {
    return <p>Učitavanje tajni...</p>
  }

  return (
    <main className="secret-page">
      <header>
        <h1>Moje tajne</h1>
        <Link to="/secrets/new">+ Nova tajna</Link>
      </header>

      {error && (
        <p role="alert" style={{ color: 'red' }}>
          {error}
        </p>
      )}

      {!error && secrets.length === 0 && (
        <section>
          <p>Još uvijek nemaš sačuvanih tajni.</p>
          <Link to="/secrets/new">Kreiraj prvu tajnu</Link>
        </section>
      )}

      {secrets.length > 0 && (
        <ul>
          {secrets.map((secret) => (
            <li key={secret.id}>
              <div>
                <Link to={`/secrets/${secret.id}`}>
                  <strong>{secret.name}</strong>

                  {secret.description && (
                    <p>{secret.description}</p>
                  )}

                  <small>
                    Algoritam:{' '}
                    {secret.encryptionAlgorithm || 'Nije naveden'}
                  </small>

                  <br />

                  {rotationIntervalDays != null && (() => {
                    const rotation = getSecretRotationInfo(secret, rotationIntervalDays)
                    return (
                      <p style={{ marginTop: '8px' }}>
                        <strong>Rotacija: </strong>
                        {rotation.status === 'overdue' ? (
                          <span style={{ color: '#b91c1c' }}>Potrebna rotacija — rok istekao</span>
                        ) : rotation.status === 'due-soon' ? (
                          <span style={{ color: '#b45309' }}>Uskoro potrebna rotacija — {rotation.daysRemaining} dana</span>
                        ) : rotation.status === 'active' ? (
                          <span style={{ color: '#15803d' }}>Aktivna — do {formatRotationDate(rotation.dueAt)}</span>
                        ) : 'Nije moguće odrediti rok'}
                      </p>
                    )
                  })()}

                  <small>
                    Kreirano:{' '}
                    {secret.createdAt
                      ? new Date(secret.createdAt).toLocaleString()
                      : 'Nepoznato'}
                  </small>
                </Link>

                {isTeamLead && (
                  <div style={{ marginTop: '10px' }}>
                    <button
                      type="button"
                      onClick={() => openShareModal(secret)}
                    >
                      Podijeli
                    </button>
                  </div>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}

      {sharingSecret && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="share-modal-title"
          className="card"
          style={{
            marginTop: '24px',
            padding: '20px',
            border: '1px solid #ccc',
            borderRadius: '8px',
          }}
        >
          <h2 id="share-modal-title">
            Podijeli tajnu: {sharingSecret.name}
          </h2>

          <p>
            Izaberi Developere sa kojima želiš podijeliti ovu tajnu.
          </p>

          {!unlocked && (
            <p role="alert" style={{ color: '#b45309' }}>
              Trezor je zaključan. Otključaj ga prije dijeljenja.
            </p>
          )}

          {loadingDevelopers ? (
            <p>Učitavanje Developera...</p>
          ) : developers.length === 0 ? (
            <p>Nema dostupnih Developera sa registrovanim ključevima.</p>
          ) : (
            <ul>
              {developers.map((developer) => (
                <li key={developer.id}>
                  <label>
                    <input
                      type="checkbox"
                      checked={selectedDevelopers.includes(developer.id)}
                      onChange={() => toggleDeveloper(developer.id)}
                      disabled={sharing}
                    />
                    {' '}
                    {developer.username}
                  </label>
                </li>
              ))}
            </ul>
          )}

          {shareError && (
            <p role="alert" style={{ color: 'red' }}>
              {shareError}
            </p>
          )}

          {shareSuccess && (
            <p role="status" style={{ color: 'green' }}>
              {shareSuccess}
            </p>
          )}

          <div
            style={{
              display: 'flex',
              gap: '10px',
              marginTop: '16px',
            }}
          >
            <button
              type="button"
              onClick={handleShare}
              disabled={
                sharing ||
                loadingDevelopers ||
                developers.length === 0 ||
                selectedDevelopers.length === 0 ||
                !unlocked
              }
            >
              {sharing ? 'Dijeljenje...' : 'Potvrdi dijeljenje'}
            </button>

            <button
              type="button"
              onClick={closeShareModal}
              disabled={sharing}
            >
              Zatvori
            </button>
          </div>
        </div>
      )}
    </main>
  )
}