import { useState, useEffect } from 'react'
import PageHeader from '../components/PageHeader.jsx'
import { useVault } from '../context/VaultContext.jsx'
import {
  listSharedSecrets,
  getSharedSecret,
} from '../services/secretsApi.js'

export default function SharedWithMe() {
  const { unlocked, decryptSharedSecret } = useVault()

  const [secrets, setSecrets] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [revealedSecrets, setRevealedSecrets] = useState({})
  const [loadingSecretId, setLoadingSecretId] = useState(null)
  const [secretError, setSecretError] = useState({})

  useEffect(() => {
    let cancelled = false

    async function fetchData() {
      setLoading(true)
      setError('')

      try {
        const data = await listSharedSecrets()

        if (!cancelled) {
          setSecrets(Array.isArray(data) ? data : [])
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err.message ||
              'Greška prilikom učitavanja podijeljenih tajni.'
          )
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    fetchData()

    return () => {
      cancelled = true
    }
  }, [])

  async function handleReveal(secret) {
    if (!unlocked) {
      setSecretError((current) => ({
        ...current,
        [secret.id]: 'Prvo otključaj trezor da bi mogao/la vidjeti tajnu.',
      }))
      return
    }

    setLoadingSecretId(secret.id)

    setSecretError((current) => ({
      ...current,
      [secret.id]: '',
    }))

    try {
      // Učitavamo detalje dijeljene tajne sa backend-a.
      const details = await getSharedSecret(secret.id)

      if (
        !details?.encryptedValue ||
        !details?.contentIv ||
        !details?.recipientEncryptedDek
      ) {
        throw new Error(
          'Nedostaju podaci potrebni za dešifrovanje tajne.'
        )
      }

      // DEK se odmotava privatnim ključem primaoca,
      // a zatim se dešifruje sadržaj tajne.
      const plaintext = await decryptSharedSecret({
        encryptedValue: details.encryptedValue,
        contentIv: details.contentIv,
        recipientEncryptedDek: details.recipientEncryptedDek,
      })

      setRevealedSecrets((current) => ({
        ...current,
        [secret.id]: plaintext,
      }))
    } catch (err) {
      setSecretError((current) => ({
        ...current,
        [secret.id]:
          err.message || 'Greška prilikom dešifrovanja tajne.',
      }))
    } finally {
      setLoadingSecretId(null)
    }
  }

  function hideSecret(secretId) {
    setRevealedSecrets((current) => {
      const updated = { ...current }
      delete updated[secretId]
      return updated
    })

    setSecretError((current) => ({
      ...current,
      [secretId]: '',
    }))
  }

  if (loading) {
    return (
      <section>
        <PageHeader
          title="Shared With Me"
          subtitle="Secrets other users have shared with you."
        />
        <p>Loading shared secrets...</p>
      </section>
    )
  }

  if (error) {
    return (
      <section>
        <PageHeader
          title="Shared With Me"
          subtitle="Secrets other users have shared with you."
        />
        <p className="form__error" role="alert">
          {error}
        </p>
      </section>
    )
  }

  if (secrets.length === 0) {
    return (
      <section>
        <PageHeader
          title="Shared With Me"
          subtitle="Secrets other users have shared with you."
        />
        <div className="card">
          <p>No shared secrets found.</p>
        </div>
      </section>
    )
  }

  return (
    <section>
      <PageHeader
        title="Shared With Me"
        subtitle="Secrets other users have shared with you."
      />

      {!unlocked && (
        <p className="form__error">
          Trezor je zaključan. Otključaj ga da bi mogao/la
          dešifrovati podijeljene tajne.
        </p>
      )}

      <ul className="list">
        {secrets.map((secret) => {
          const isRevealed = Object.prototype.hasOwnProperty.call(
            revealedSecrets,
            secret.id
          )

          const isLoading = loadingSecretId === secret.id

          return (
            <li key={secret.id} className="list__item">
              <div className="list__row">
                <span className="list__name">
                  {secret.name}
                </span>

                <span className="badge">shared</span>
              </div>

              <p className="list__meta">
                {secret.description || 'No description'}
                {' · Shared '}
                {secret.createdAt
                  ? new Date(secret.createdAt).toLocaleDateString()
                  : 'Unknown'}
              </p>

              {isRevealed && (
                <div
                  className="card"
                  style={{
                    marginTop: '12px',
                    padding: '12px',
                    overflowWrap: 'anywhere',
                  }}
                >
                  <strong>Dešifrovani sadržaj:</strong>

                  <pre
                    style={{
                      whiteSpace: 'pre-wrap',
                      overflowWrap: 'anywhere',
                      marginTop: '8px',
                    }}
                  >
                    {revealedSecrets[secret.id]}
                  </pre>
                </div>
              )}

              {secretError[secret.id] && (
                <p className="form__error" role="alert">
                  {secretError[secret.id]}
                </p>
              )}

              <div style={{ marginTop: '12px' }}>
                {isRevealed ? (
                  <button
                    type="button"
                    onClick={() => hideSecret(secret.id)}
                  >
                    Sakrij tajnu
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => handleReveal(secret)}
                    disabled={isLoading || !unlocked}
                  >
                    {isLoading
                      ? 'Dešifrovanje...'
                      : 'Prikaži tajnu'}
                  </button>
                )}
              </div>
            </li>
          )
        })}
      </ul>
    </section>
  )
}