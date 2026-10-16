// Master password -> KEK derivation (PBKDF2-HMAC-SHA-256).
//
// The KEK is a client-side secret: it is derived from the master password,
// which is never sent to or stored on the backend. The returned KEK is
// NON-extractable, so its raw bytes can never be read out of the browser.

import {
  AES_GCM_NAME,
  AES_KEY_BITS,
  PBKDF2_DEFAULT_ITERATIONS,
  PBKDF2_HASH,
  PBKDF2_NAME,
  SALT_BYTES,
} from './constants.js'

// Generate a cryptographically random salt of `bytes` length (default 16).
// The salt is NOT secret; it is stored with the account/verifier.
export function generateSalt(bytes = SALT_BYTES) {
  const salt = new Uint8Array(bytes)
  globalThis.crypto.getRandomValues(salt)
  return salt
}

// Derive a non-extractable AES-256 KEK from a master password + salt.
//
// @param {string}   masterPassword - the client-side master password.
// @param {Uint8Array} salt         - random salt from generateSalt().
// @param {number}   [iterations]   - PBKDF2 iteration count; defaults to
//                                    PBKDF2_DEFAULT_ITERATIONS. Lower values
//                                    are for tests/benchmarks only.
// @returns {Promise<CryptoKey>} non-extractable AES-GCM key usable to wrap/unwrap.
export async function deriveKek(
  masterPassword,
  salt,
  iterations = PBKDF2_DEFAULT_ITERATIONS,
) {
  const passwordBytes = new TextEncoder().encode(masterPassword)

  const keyMaterial = await globalThis.crypto.subtle.importKey(
    'raw',
    passwordBytes,
    { name: PBKDF2_NAME, hash: PBKDF2_HASH },
    false,
    ['deriveKey'],
  )

  return globalThis.crypto.subtle.deriveKey(
    { name: PBKDF2_NAME, hash: PBKDF2_HASH, salt, iterations },
    keyMaterial,
    { name: AES_GCM_NAME, length: AES_KEY_BITS },
    false, // non-extractable
    ['encrypt', 'decrypt'],
  )
}
