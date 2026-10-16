// Base64 conversion helpers - USE ONLY AT JSON/API BOUNDARIES.
//
// The crypto module is byte-oriented (Uint8Array in / Uint8Array out).
// Binary fields such as IVs, ciphertext, salts, SPKI/PKCS#8 keys, and wrapped
// DEKs must be converted to Base64 strings only when serializing into JSON or
// sending over HTTP. Convert back to bytes before feeding them to any function
// in this module.
//
// These helpers intentionally define NO payload shape / API contract - they are
// a plain, symmetric bytes<->Base64 codec. The actual request/response schemas
// are decided separately at integration time.

export function bytesToBase64(bytes) {
  let binary = ''
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i])
  }
  return globalThis.btoa(binary)
}

export function base64ToBytes(base64) {
  const binary = globalThis.atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}
