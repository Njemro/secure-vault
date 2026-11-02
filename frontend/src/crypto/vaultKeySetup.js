import {
  PBKDF2_DEFAULT_ITERATIONS,
  PBKDF2_HASH,
  generateSalt,
  deriveKek,
  generateRsaKeyPair,
  exportPublicKeySpki,
  exportPrivateKeyPkcs8,
  encryptPrivateKey,
  bytesToBase64,
} from './index.js'

/**
 * Generiše RSA ključni par i šifruje privatni ključ
 * pomoću ključa izvedenog iz master lozinke.
 *
 * Master lozinka se ne šalje backendu.
 */
export async function createVaultKeyMaterial(masterPassword) {
  if (typeof masterPassword !== 'string' || masterPassword.length < 12) {
    throw new Error('Master lozinka mora imati najmanje 12 znakova.')
  }

  const salt = generateSalt()
  const kek = await deriveKek(
    masterPassword,
    salt,
    PBKDF2_DEFAULT_ITERATIONS,
  )

  const keyPair = await generateRsaKeyPair()

  const publicKeyBytes = await exportPublicKeySpki(keyPair.publicKey)
  const privateKeyBytes = await exportPrivateKeyPkcs8(keyPair.privateKey)

  const encryptedPrivateKey = await encryptPrivateKey(kek, privateKeyBytes)

  return {
    publicKey: bytesToBase64(publicKeyBytes),
    encryptedPrivateKey: bytesToBase64(encryptedPrivateKey.ciphertext),
    privateKeyIv: bytesToBase64(encryptedPrivateKey.iv),
    kdfAlgorithm: 'PBKDF2-HMAC-SHA-256',
    kdfParameters: JSON.stringify({
      iterations: PBKDF2_DEFAULT_ITERATIONS,
      hash: PBKDF2_HASH,
      salt: bytesToBase64(salt),
      cipher: 'AES-GCM',
    }),
  }
}