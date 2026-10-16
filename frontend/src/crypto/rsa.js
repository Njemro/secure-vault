// RSA-OAEP (SHA-256) key handling for secret sharing.
//
// Only the small DEK is ever RSA-wrapped - never the full secret, which stays
// AES-GCM encrypted. Public keys are exchanged as SPKI DER bytes; private keys
// are handled as PKCS#8 DER bytes that the caller encrypts with the KEK before
// storage (see encryptPrivateKey in aesGcm.js).

import {
  RSA_HASH,
  RSA_MODULUS_BITS,
  RSA_OAEP_NAME,
  RSA_PUBLIC_EXPONENT,
} from './constants.js'
import { exportDek, importDek } from './aesGcm.js'

// Generate a 2048-bit RSA-OAEP (SHA-256) key pair.
export async function generateRsaKeyPair() {
  return globalThis.crypto.subtle.generateKey(
    {
      name: RSA_OAEP_NAME,
      modulusLength: RSA_MODULUS_BITS,
      publicExponent: RSA_PUBLIC_EXPONENT,
      hash: RSA_HASH,
    },
    true, // extractable so public/private bytes can be exported
    ['encrypt', 'decrypt'],
  )
}

// Export a public key as SPKI DER bytes (X.509 SubjectPublicKeyInfo).
export async function exportPublicKeySpki(publicKey) {
  return new Uint8Array(
    await globalThis.crypto.subtle.exportKey('spki', publicKey),
  )
}

// Import SPKI DER bytes as an RSA-OAEP public key (for wrapping a DEK).
export async function importPublicKeySpki(spkiDer) {
  return globalThis.crypto.subtle.importKey(
    'spki',
    spkiDer,
    { name: RSA_OAEP_NAME, hash: RSA_HASH },
    true,
    ['encrypt'],
  )
}

// Export a private key as PKCS#8 DER bytes (for the caller to KEK-encrypt).
export async function exportPrivateKeyPkcs8(privateKey) {
  return new Uint8Array(
    await globalThis.crypto.subtle.exportKey('pkcs8', privateKey),
  )
}

// Import PKCS#8 DER bytes as an RSA-OAEP private key (for unwrapping).
export async function importPrivateKeyPkcs8(pkcs8Der) {
  return globalThis.crypto.subtle.importKey(
    'pkcs8',
    pkcs8Der,
    { name: RSA_OAEP_NAME, hash: RSA_HASH },
    true,
    ['decrypt'],
  )
}

// Wrap (encrypt) a DEK for a recipient using their RSA-OAEP public key.
// @returns {Promise<Uint8Array>} the RSA-wrapped DEK.
export async function wrapDekForRecipient(recipientPublicKey, dek) {
  const dekBytes = await exportDek(dek)
  return new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: RSA_OAEP_NAME },
      recipientPublicKey,
      dekBytes,
    ),
  )
}

// Unwrap a recipient-wrapped DEK with the matching RSA-OAEP private key.
// @returns {Promise<CryptoKey>} a usable AES-256-GCM DEK.
export async function unwrapDekForRecipient(recipientPrivateKey, wrappedDek) {
  const rawBytes = await globalThis.crypto.subtle.decrypt(
    { name: RSA_OAEP_NAME },
    recipientPrivateKey,
    wrappedDek,
  )
  return importDek(new Uint8Array(rawBytes))
}
