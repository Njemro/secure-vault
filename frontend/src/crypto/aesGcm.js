// AES-256-GCM operations: DEK generation, byte encryption, DEK wrap/unwrap
// with the KEK, and private-key byte protection.
//
// Every encryption draws a fresh 12-byte IV. Nothing in this module persists
// any key material, plaintext, or password - the caller supplies keys/passwords
// when needed and owns all storage decisions.

import {
  AES_GCM_NAME,
  AES_KEY_BITS,
  GCM_TAG_BITS,
  IV_BYTES,
} from './constants.js'

// The byte envelope returned by every AES-GCM encryption.
//
//   { iv: Uint8Array(12), ciphertext: Uint8Array(...) }
//
// `iv` is the 12-byte nonce used for this encryption (not secret).
// `ciphertext` contains the ciphertext with the 128-bit GCM authentication tag
// APPENDED (Web Crypto returns tag+ciphertext as a single buffer). Decrypting
// requires both fields, so store/transport them together.

// Generate a fresh random AES-256 data-encryption key (DEK).
// Extractable so it can be exported, wrapped, and re-wrapped for sharing.
export async function generateDek() {
  return globalThis.crypto.subtle.generateKey(
    { name: AES_GCM_NAME, length: AES_KEY_BITS },
    true, // extractable: required for wrapping / export
    ['encrypt', 'decrypt'],
  )
}

// Encrypt arbitrary bytes with an AES-GCM key under a fresh IV.
// @returns {Promise<{iv: Uint8Array, ciphertext: Uint8Array}>}
export async function encryptBytes(key, plaintext) {
  const iv = new Uint8Array(IV_BYTES)
  globalThis.crypto.getRandomValues(iv)

  const ciphertext = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: AES_GCM_NAME, iv, tagLength: GCM_TAG_BITS },
      key,
      plaintext,
    ),
  )

  return { iv, ciphertext }
}

// Decrypt a byte envelope produced by encryptBytes.
// Rejects if the key is wrong or if iv/ciphertext/tag was tampered with
// (GCM is authenticated, so any modification fails verification).
// @returns {Promise<Uint8Array>} the original plaintext bytes.
export async function decryptBytes(key, envelope) {
  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: AES_GCM_NAME, iv: envelope.iv, tagLength: GCM_TAG_BITS },
    key,
    envelope.ciphertext,
  )
  return new Uint8Array(plaintext)
}

// Export a DEK to its raw 32 bytes (needed before wrapping it).
export async function exportDek(dek) {
  return new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', dek))
}

// Import raw DEK bytes back into an AES-256-GCM key.
// Extractable so the DEK can be re-exported for sharing workflows.
export async function importDek(rawBytes) {
  return globalThis.crypto.subtle.importKey(
    'raw',
    rawBytes,
    { name: AES_GCM_NAME, length: AES_KEY_BITS },
    true,
    ['encrypt', 'decrypt'],
  )
}

// Wrap (encrypt) a DEK with the KEK so the owner keeps access to the DEK
// without the backend ever seeing the master password or the plaintext DEK.
// @returns {Promise<{iv: Uint8Array, ciphertext: Uint8Array}>}
export async function wrapDek(kek, dek) {
  const dekBytes = await exportDek(dek)
  return encryptBytes(kek, dekBytes)
}

// Unwrap (decrypt) a KEK-wrapped DEK back into a usable AES key.
// Rejects on a wrong master password (KEK mismatch).
export async function unwrapDek(kek, envelope) {
  const rawBytes = await decryptBytes(kek, envelope)
  return importDek(rawBytes)
}

// Encrypt the user's exported private-key bytes with the KEK.
// The plaintext private key must never be persisted by this module - the
// caller decides where (if anywhere) the envelope is stored.
// @returns {Promise<{iv: Uint8Array, ciphertext: Uint8Array}>}
export async function encryptPrivateKey(kek, privateKeyBytes) {
  return encryptBytes(kek, privateKeyBytes)
}

// Decrypt private-key bytes previously encrypted with the KEK.
// @returns {Promise<Uint8Array>} raw private-key bytes (e.g. PKCS#8 DER) for
// the caller to import. Never persisted by this module.
export async function decryptPrivateKey(kek, envelope) {
  return decryptBytes(kek, envelope)
}
