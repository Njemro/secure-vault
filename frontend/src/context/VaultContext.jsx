import { createContext, useContext, useState, useCallback } from 'react'
import {
  deriveKek,
  generateSalt,
  generateDek,
  encryptBytes,
  decryptBytes,
  wrapDek,
  unwrapDek,
  bytesToBase64,
  base64ToBytes,
  PBKDF2_DEFAULT_ITERATIONS,
} from '../crypto/index.js'

const VaultContext = createContext(null)

/**
 * Vault context: manages the master password and derived KEK in memory.
 *
 * The master password never leaves the browser. It is held in memory only
 * for the duration of the session and is used to derive the KEK that wraps
 * each secret's DEK.
 */
export function VaultProvider({ children }) {
  const [masterPassword, setMasterPassword] = useState(null)
  const [kek, setKek] = useState(null)
  const [salt, setSalt] = useState(null)
  const [kdfParameters, setKdfParameters] = useState(null)
  const [unlocked, setUnlocked] = useState(false)

  const unlock = useCallback(async (password) => {
    const derivedSalt = generateSalt()
    const derivedKek = await deriveKek(password, derivedSalt, PBKDF2_DEFAULT_ITERATIONS)
    setMasterPassword(password)
    setSalt(derivedSalt)
    setKek(derivedKek)
    setUnlocked(true)
    return { salt: derivedSalt, kek: derivedKek }
  }, [])

  const lock = useCallback(() => {
    setMasterPassword(null)
    setSalt(null)
    setKdfParameters(null)
    setKek(null)
    setUnlocked(false)
  }, [])

  // Encrypt a secret value: generate DEK, encrypt value with DEK, wrap DEK with KEK.
  const encryptSecret = useCallback(
    async (plaintextValue) => {
      if (!kek) throw new Error('Vault is not unlocked')
      const dek = await generateDek()
      const valueEnvelope = await encryptBytes(dek, new TextEncoder().encode(plaintextValue))
      const wrappedDek = await wrapDek(kek, dek)
      return {
        encryptedValue: bytesToBase64(valueEnvelope.ciphertext),
        contentIv: bytesToBase64(valueEnvelope.iv),
        encryptedDek: bytesToBase64(wrappedDek.ciphertext),
        dekIv: bytesToBase64(wrappedDek.iv),
        encryptionAlgorithm: 'AES-256-GCM',
        // Internal: raw DEK bytes for sharing (not sent to server)
        _dek: dek,
      }
    },
    [kek]
  )

  // Decrypt a secret value using the KEK.
  const decryptSecret = useCallback(
    async ({ encryptedValue, contentIv, encryptedDek, dekIv }) => {
      if (!kek) throw new Error('Vault is not unlocked')
      const dekEnvelope = {
        iv: base64ToBytes(dekIv),
        ciphertext: base64ToBytes(encryptedDek),
      }
      const dek = await unwrapDek(kek, dekEnvelope)
      const valueEnvelope = {
        iv: base64ToBytes(contentIv),
        ciphertext: base64ToBytes(encryptedValue),
      }
      const plaintext = await decryptBytes(dek, valueEnvelope)
      return new TextDecoder().decode(plaintext)
    },
    [kek]
  )

  // Wrap a DEK for a recipient using their RSA public key.
  const wrapDekForRecipient = useCallback(
    async (recipientPublicKeySpki, dek) => {
      const { importPublicKeySpki, wrapDekForRecipient: wrapForRecipient } = await import(
        '../crypto/index.js'
      )
      const pubKey = await importPublicKeySpki(base64ToBytes(recipientPublicKeySpki))
      const wrapped = await wrapForRecipient(pubKey, dek)
      return bytesToBase64(wrapped)
    },
    []
  )

  const value = {
    masterPassword,
    kek,
    salt,
    kdfParameters,
    unlocked,
    unlock,
    lock,
    encryptSecret,
    decryptSecret,
    wrapDekForRecipient,
  }

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>
}

export function useVault() {
  const ctx = useContext(VaultContext)
  if (!ctx) {
    throw new Error('useVault must be used within a VaultProvider')
  }
  return ctx
}