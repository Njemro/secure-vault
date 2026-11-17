import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  useRef,
} from 'react'

import { useAuth } from './AuthContext.jsx'
import { getMyKeys } from '../services/usersApi.js'
import { reportDecryptionFailure } from '../services/api.js'

import {
  deriveKek,
  generateDek,
  encryptBytes,
  decryptBytes,
  wrapDek,
  unwrapDek,
  decryptPrivateKey,
  importPrivateKeyPkcs8,
  unwrapDekForRecipient as cryptoUnwrapDekForRecipient,
  importPublicKeySpki,
  wrapDekForRecipient as cryptoWrapDekForRecipient,
  base64ToBytes,
  bytesToBase64,
} from '../crypto/index.js'

const VaultContext = createContext(null)

export function VaultProvider({ children }) {
  const { authenticated } = useAuth()

  const [kek, setKek] = useState(null)
  const [privateKey, setPrivateKey] = useState(null)
  const [publicKey, setPublicKey] = useState(null)
  const [vaultKeys, setVaultKeys] = useState(null)

  const [unlocked, setUnlocked] = useState(false)
  const [loading, setLoading] = useState(false)

  const [status, setStatus] = useState('checking')
  const [error, setError] = useState(null)

  const statusRequestId = useRef(0)

  // Briše ključeve iz memorije aplikacije.
  const clearVault = useCallback(() => {
    setKek(null)
    setPrivateKey(null)
    setPublicKey(null)
    setVaultKeys(null)
    setUnlocked(false)
  }, [])

  useEffect(() => {
    const handleSessionExpired = () => {
      clearVault()
    }

    window.addEventListener(
      'secure-vault:session-expired',
      handleSessionExpired,
    )

    return () => {
      window.removeEventListener(
        'secure-vault:session-expired',
        handleSessionExpired,
      )
    }
  }, [clearVault])

  // Briše samo materijal za otključavanje, a čuva podatke o trezoru.
  const clearUnlockedMaterial = useCallback(() => {
    setKek(null)
    setPrivateKey(null)
    setUnlocked(false)
  }, [])

  /**
   * Provjera da li korisnik ima registrovane ključeve.
   */
  const refreshVaultStatus = useCallback(async () => {
    const requestId = ++statusRequestId.current

    if (!authenticated) {
      clearVault()
      setError(null)
      setStatus('checking')
      return 'checking'
    }



    try {
      const keys = await getMyKeys()

      if (requestId !== statusRequestId.current) {
        return null
      }

      if (
        !keys?.encryptedPrivateKey ||
        !keys?.privateKeyIv ||
        !keys?.kdfParameters
      ) {
        clearVault()
        setStatus('needs-setup')
        return 'needs-setup'
      }

      clearUnlockedMaterial()
      setVaultKeys(keys)
      setPublicKey(keys.publicKey || null)
      setStatus('locked')

      return 'locked'
    } catch (err) {
      if (requestId !== statusRequestId.current) {
        return null
      }

      if (err.status === 404) {
        clearVault()
        setStatus('needs-setup')
        return 'needs-setup'
      }

      console.error('Vault status check failed:', err)

      setError(
        err.message || 'Nije moguće provjeriti stanje trezora.',
      )

      setStatus('error')
      return 'error'
    }
  }, [authenticated, clearVault, clearUnlockedMaterial])

  /**
   * Poziva se nakon uspješne registracije ključeva.
   */
  const completeVaultSetup = useCallback((keys) => {
    statusRequestId.current += 1

    clearVault()

    setPublicKey(keys?.publicKey || null)
    setVaultKeys(keys || null)
    setError(null)
    setStatus('locked')
  }, [clearVault])

  /**
   * Otključavanje trezora.
   */
  const unlock = useCallback(async (masterPassword) => {
    if (!masterPassword) {
      throw new Error('Unesi master lozinku.')
    }

    if (!authenticated) {
      throw new Error('Nisi prijavljen.')
    }

    const requestId = ++statusRequestId.current

    setLoading(true)
    setError(null)

    try {
      const keys = await getMyKeys()

      if (requestId !== statusRequestId.current) {
        throw new Error('Zahtjev za otključavanje je poništen.')
      }

      setStatus('checking')
      setError(null)

      if (
        !keys?.encryptedPrivateKey ||
        !keys?.privateKeyIv ||
        !keys?.kdfParameters
      ) {
        throw new Error(
          'Podaci za otključavanje trezora nisu potpuni.',
        )
      }

      const parameters =
        typeof keys.kdfParameters === 'string'
          ? JSON.parse(keys.kdfParameters)
          : keys.kdfParameters

      const iterations = Number(parameters.iterations)

      if (
        !parameters.salt ||
        !Number.isSafeInteger(iterations) ||
        iterations <= 0
      ) {
        throw new Error('Neispravni KDF parametri.')
      }

      if (
        keys.kdfAlgorithm &&
        keys.kdfAlgorithm !== 'PBKDF2-HMAC-SHA-256'
      ) {
        throw new Error(
          'Nepodržan algoritam za izvođenje ključa.',
        )
      }

      const salt = base64ToBytes(parameters.salt)

      if (!salt.length) {
        throw new Error('Salt nije ispravan.')
      }

      const derivedKek = await deriveKek(
        masterPassword,
        salt,
        iterations,
      )

      let decryptedPrivateKey

      try {
        decryptedPrivateKey = await decryptPrivateKey(
          derivedKek,
          {
            ciphertext: base64ToBytes(keys.encryptedPrivateKey),
            iv: base64ToBytes(keys.privateKeyIv),
          },
        )
      } catch {
        const error = new Error('Pogrešna master lozinka.')
        error.code = 'DECRYPTION_FAILED'
        throw error
      }

      let importedPrivateKey

      try {
        importedPrivateKey = await importPrivateKeyPkcs8(
          decryptedPrivateKey,
        )
      } finally {
        // Ukloni privremene bajtove privatnog ključa iz memorije.
        decryptedPrivateKey?.fill?.(0)
      }

      if (requestId !== statusRequestId.current) {
        throw new Error('Zahtjev za otključavanje je poništen.')
      }

      setKek(derivedKek)
      setPrivateKey(importedPrivateKey)
      setPublicKey(keys.publicKey || null)
      setVaultKeys(keys)
      setUnlocked(true)
      setStatus('unlocked')
      setError(null)

      return true
    } catch (err) {
      if (err?.code === 'DECRYPTION_FAILED') {
        // Fire-and-forget: the report contains no password, key or plaintext.
        reportDecryptionFailure()
      }
      if (requestId === statusRequestId.current) {
        clearUnlockedMaterial()
        setStatus('locked')
      }

      throw err
    } finally {
      setLoading(false)
    }
  }, [authenticated, clearUnlockedMaterial])

  /**
   * Zaključavanje trezora.
   */
  const lock = useCallback(() => {
    statusRequestId.current += 1

    clearUnlockedMaterial()
    setStatus(vaultKeys ? 'locked' : 'needs-setup')
    setError(null)
  }, [clearUnlockedMaterial, vaultKeys])

  /**
   * Šifrovanje nove tajne.
   */
  const encryptSecret = useCallback(
    async (plaintextValue) => {
      if (!kek || !unlocked) {
        throw new Error('Trezor nije otključan.')
      }

      const dek = await generateDek()

      const valueEnvelope = await encryptBytes(
        dek,
        new TextEncoder().encode(plaintextValue),
      )

      const wrappedDek = await wrapDek(kek, dek)

      return {
        encryptedValue: bytesToBase64(valueEnvelope.ciphertext),
        contentIv: bytesToBase64(valueEnvelope.iv),
        encryptedDek: bytesToBase64(wrappedDek.ciphertext),
        dekIv: bytesToBase64(wrappedDek.iv),
        encryptionAlgorithm: 'AES-256-GCM',
        _dek: dek,
      }
    },
    [kek, unlocked],
  )

  /**
   * Dešifrovanje vlastite tajne.
   */
  const decryptSecret = useCallback(
    async ({ encryptedValue, contentIv, encryptedDek, dekIv }) => {
      if (!kek || !unlocked) {
        throw new Error('Trezor nije otključan.')
      }

      try {
        const dek = await unwrapDek(kek, {
          iv: base64ToBytes(dekIv),
          ciphertext: base64ToBytes(encryptedDek),
        })

        const plaintext = await decryptBytes(dek, {
          iv: base64ToBytes(contentIv),
          ciphertext: base64ToBytes(encryptedValue),
        })

        return new TextDecoder().decode(plaintext)
      } catch (error) {
        reportDecryptionFailure()
        throw error
      }
    },
    [kek, unlocked],
  )

  /**
   * Omotavanje DEK-a za primaoca.
   */
  const wrapDekForRecipient = useCallback(
    async (recipientPublicKeySpki, dek) => {
      if (!unlocked) {
        throw new Error('Trezor nije otključan.')
      }

      const recipientPublicKey = await importPublicKeySpki(
        base64ToBytes(recipientPublicKeySpki),
      )

      const wrapped = await cryptoWrapDekForRecipient(
        recipientPublicKey,
        dek,
      )

      return bytesToBase64(wrapped)
    },
    [unlocked],
  )

  /**
   * Priprema DEK postojeće tajne za dijeljenje sa primaocem.
   * DEK se prvo odmotava vlasnikovim KEK-om, a zatim
   * omotava javnim RSA ključem primaoca.
   */
  const prepareSecretForSharing = useCallback(
    async (secret, recipientPublicKeySpki) => {
      if (!kek || !unlocked) {
        throw new Error('Trezor nije otključan.')
      }

      if (!secret?.encryptedDek || !secret?.dekIv) {
        throw new Error('Nedostaju podaci za otključavanje DEK-a tajne.')
      }

      if (!recipientPublicKeySpki) {
        throw new Error('Javni ključ primaoca nije dostupan.')
      }

      // Odmotavanje DEK-a vlasnikovim KEK-om.
      const dek = await unwrapDek(kek, {
        iv: base64ToBytes(secret.dekIv),
        ciphertext: base64ToBytes(secret.encryptedDek),
      })

      // Učitavanje javnog ključa primaoca.
      const recipientPublicKey = await importPublicKeySpki(
        base64ToBytes(recipientPublicKeySpki)
      )

      // Omotavanje DEK-a javnim ključem primaoca.
      const recipientWrappedDek = await cryptoWrapDekForRecipient(
        recipientPublicKey,
        dek
      )

      return bytesToBase64(recipientWrappedDek)
    },
    [kek, unlocked]
  )

  /**
   * Odmotavanje DEK-a za trenutnog korisnika.
   */
  const unwrapSharedDek = useCallback(
    async (wrappedDek) => {
      if (!privateKey || !unlocked) {
        throw new Error('Trezor nije otključan.')
      }

      return cryptoUnwrapDekForRecipient(
        privateKey,
        base64ToBytes(wrappedDek),
      )
    },
    [privateKey, unlocked],
  )

  /**
   * Dešifrovanje dijeljene tajne.
   */
  const decryptSharedSecret = useCallback(
    async ({ encryptedValue, contentIv, recipientEncryptedDek }) => {
      if (!privateKey || !unlocked) {
        throw new Error('Trezor nije otključan.')
      }

      try {
        const dek = await cryptoUnwrapDekForRecipient(
          privateKey,
          base64ToBytes(recipientEncryptedDek),
        )

        const plaintext = await decryptBytes(dek, {
          iv: base64ToBytes(contentIv),
          ciphertext: base64ToBytes(encryptedValue),
        })

        return new TextDecoder().decode(plaintext)
      } catch (error) {
        reportDecryptionFailure()
        throw error
      }
    },
    [privateKey, unlocked],
  )

  useEffect(() => {
    if (!authenticated) return

    const timeoutId = window.setTimeout(() => {
      refreshVaultStatus()
    }, 0)

    return () => {
      window.clearTimeout(timeoutId)
    }
  }, [authenticated, refreshVaultStatus])

  const value = {
    kek,
    privateKey,
    publicKey,
    vaultKeys,
    unlocked,
    loading,
    status,
    error,

    unlock,
    lock,
    clearVault,
    refreshVaultStatus,
    completeVaultSetup,

    encryptSecret,
    decryptSecret,
    wrapDekForRecipient,
    prepareSecretForSharing,
    unwrapSharedDek,
    decryptSharedSecret,
  }

  return (
    <VaultContext.Provider value={value}>
      {children}
    </VaultContext.Provider>
  )
}

export function useVault() {
  const context = useContext(VaultContext)

  if (!context) {
    throw new Error('useVault must be used within a VaultProvider')
  }

  return context
}