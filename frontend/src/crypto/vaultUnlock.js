import {
  deriveKek,
  decryptPrivateKey,
  importPrivateKeyPkcs8,
  base64ToBytes,
} from './index.js'

export async function unlockVaultWithPassword(masterPassword, keyRecord) {
  if (!masterPassword) {
    throw new Error('Unesi master lozinku.')
  }

  if (!keyRecord?.encryptedPrivateKey || !keyRecord?.privateKeyIv) {
    throw new Error('Nedostaju podaci za otključavanje trezora.')
  }

  if (keyRecord.kdfAlgorithm !== 'PBKDF2-HMAC-SHA-256') {
    throw new Error('Nepodržan algoritam za izvođenje ključa.')
  }

  let parameters

  try {
    parameters =
      typeof keyRecord.kdfParameters === 'string'
        ? JSON.parse(keyRecord.kdfParameters)
        : keyRecord.kdfParameters
  } catch {
    throw new Error('Parametri za otključavanje nisu ispravni.')
  }

  const iterations = Number(parameters?.iterations)

  if (
    !Number.isSafeInteger(iterations) ||
    iterations < 1 ||
    iterations > 5_000_000 ||
    parameters?.hash !== 'SHA-256' ||
    !parameters?.salt
  ) {
    throw new Error('Parametri za izvođenje ključa nisu ispravni.')
  }

  try {
    const salt = base64ToBytes(parameters.salt)

    if (salt.length !== 16) {
      throw new Error('Neispravan salt.')
    }

    const kek = await deriveKek(
      masterPassword,
      salt,
      iterations,
    )

    const privateKeyBytes = await decryptPrivateKey(kek, {
      iv: base64ToBytes(keyRecord.privateKeyIv),
      ciphertext: base64ToBytes(keyRecord.encryptedPrivateKey),
    })

    const privateKey = await importPrivateKeyPkcs8(privateKeyBytes)

    return privateKey
  } catch {
    const error = new Error(
      'Otključavanje nije uspjelo. Provjeri master lozinku ili integritet podataka.',
    )
    // A stable machine-readable code is used by VaultContext to report only
    // the fact of a failed client-side decryption; no password/key is sent.
    error.code = 'DECRYPTION_FAILED'
    throw error
  }
}