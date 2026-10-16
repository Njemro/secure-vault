// Public surface of the Secure Vault client-side crypto module.
//
// All functions are byte-oriented and run entirely in the browser via the Web
// Crypto API. The master password is supplied per call and is never stored.
// See README.md for formats, parameters, and limitations.

export {
  PBKDF2_DEFAULT_ITERATIONS,
  PBKDF2_HASH,
  SALT_BYTES,
  IV_BYTES,
  AES_KEY_BITS,
  RSA_MODULUS_BITS,
} from './constants.js'

export { deriveKek, generateSalt } from './kek.js'

export {
  generateDek,
  encryptBytes,
  decryptBytes,
  exportDek,
  importDek,
  wrapDek,
  unwrapDek,
  encryptPrivateKey,
  decryptPrivateKey,
} from './aesGcm.js'

export {
  generateRsaKeyPair,
  exportPublicKeySpki,
  importPublicKeySpki,
  exportPrivateKeyPkcs8,
  importPrivateKeyPkcs8,
  wrapDekForRecipient,
  unwrapDekForRecipient,
} from './rsa.js'

export { bytesToBase64, base64ToBytes } from './encoding.js'
