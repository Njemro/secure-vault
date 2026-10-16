// Cryptographic parameters for the Secure Vault client.
//
// Everything here is a thin, explicit wrapper around the browser Web Crypto
// API (crypto.subtle). No custom primitives are defined. See README.md in
// this folder for the public-key format, envelope structure, and limitations.

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA-256  (master password -> KEK)
// ---------------------------------------------------------------------------
export const PBKDF2_NAME = 'PBKDF2'
export const PBKDF2_HASH = 'SHA-256'

// Default iteration count. 600000 is the OWASP 2023 recommendation for
// PBKDF2-HMAC-SHA-256. It must be benchmarked against the target hardware and
// can be overridden per call; the count is intentionally NOT hard-coded into
// the derive function so it stays configurable (and migratable) over time.
export const PBKDF2_DEFAULT_ITERATIONS = 600_000

// Salt size in bytes. 128-bit random salt, stored alongside the verifier.
export const SALT_BYTES = 16

// ---------------------------------------------------------------------------
// AES-256-GCM  (KEK -> wrapped DEK / wrapped private key, DEK -> secret)
// ---------------------------------------------------------------------------
export const AES_KEY_BITS = 256
export const AES_GCM_NAME = 'AES-GCM'

// 96-bit IV/nonce. The GCM standard-recommended size; a fresh IV is drawn for
// every encryption and never reused with the same key.
export const IV_BYTES = 12

// 128-bit authentication tag (appended to the ciphertext by Web Crypto).
export const GCM_TAG_BITS = 128

// ---------------------------------------------------------------------------
// RSA-OAEP  (sharing: wrap a DEK for a recipient)
// ---------------------------------------------------------------------------
export const RSA_OAEP_NAME = 'RSA-OAEP'
export const RSA_HASH = 'SHA-256'
export const RSA_MODULUS_BITS = 2048
// Standard public exponent 65537.
export const RSA_PUBLIC_EXPONENT = new Uint8Array([0x01, 0x00, 0x01])
