// Tests for AES-256-GCM byte encryption, DEK wrap/unwrap with the KEK, and
// private-key byte protection. Node built-in test runner + Web Crypto.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { IV_BYTES } from './constants.js'
import { generateSalt, deriveKek } from './kek.js'
import {
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

const TEST_ITERATIONS = 1000

async function testKek() {
  return deriveKek('master-password', generateSalt(), TEST_ITERATIONS)
}

test('generateDek returns a 256-bit AES-GCM key', async () => {
  const dek = await generateDek()
  assert.equal(dek.algorithm.name, 'AES-GCM')
  assert.equal(dek.algorithm.length, 256)
})

test('encrypt/decrypt round trip returns original bytes', async () => {
  const dek = await generateDek()
  const plaintext = new Uint8Array([1, 2, 3, 4, 250, 251, 252, 253])

  const envelope = await encryptBytes(dek, plaintext)
  const recovered = await decryptBytes(dek, envelope)

  assert.deepEqual(recovered, plaintext)
})

test('envelope contains a fresh 12-byte IV and distinct ciphertext each call', async () => {
  const dek = await generateDek()
  const plaintext = new TextEncoder().encode('same input twice')

  const a = await encryptBytes(dek, plaintext)
  const b = await encryptBytes(dek, plaintext)

  assert.equal(a.iv.length, IV_BYTES)
  assert.equal(IV_BYTES, 12)

  // Fresh IV per encryption => IVs differ and ciphertexts differ.
  assert.notDeepEqual(a.iv, b.iv)
  assert.notDeepEqual(a.ciphertext, b.ciphertext)

  // Both still decrypt to the same plaintext.
  assert.deepEqual(await decryptBytes(dek, a), plaintext)
  assert.deepEqual(await decryptBytes(dek, b), plaintext)
})

test('decrypt with wrong DEK fails', async () => {
  const dekA = await generateDek()
  const dekB = await generateDek()
  const plaintext = new TextEncoder().encode('cross-key')

  const envelope = await encryptBytes(dekA, plaintext)
  await assert.rejects(() => decryptBytes(dekB, envelope))
})

test('tampered ciphertext fails authentication', async () => {
  const dek = await generateDek()
  const plaintext = new TextEncoder().encode('integrity check')
  const envelope = await encryptBytes(dek, plaintext)

  const tampered = Uint8Array.from(envelope.ciphertext)
  tampered[0] ^= 0xff

  await assert.rejects(
    () => decryptBytes(dek, { iv: envelope.iv, ciphertext: tampered }),
  )
})

test('tampered IV fails authentication', async () => {
  const dek = await generateDek()
  const plaintext = new TextEncoder().encode('iv integrity')
  const envelope = await encryptBytes(dek, plaintext)

  const badIv = Uint8Array.from(envelope.iv)
  badIv[0] ^= 0xff

  await assert.rejects(
    () => decryptBytes(dek, { iv: badIv, ciphertext: envelope.ciphertext }),
  )
})

test('export/import DEK round trip preserves key material', async () => {
  const dek = await generateDek()
  const raw = await exportDek(dek)
  assert.equal(raw.length, 32) // AES-256

  const reimported = await importDek(raw)
  const plaintext = new TextEncoder().encode('reimported key works')
  const envelope = await encryptBytes(dek, plaintext)

  assert.deepEqual(await decryptBytes(reimported, envelope), plaintext)
})

test('wrap/unwrap DEK with KEK round trip', async () => {
  const kek = await testKek()
  const dek = await generateDek()
  const originalRaw = await exportDek(dek)

  const wrapped = await wrapDek(kek, dek)
  const unwrapped = await unwrapDek(kek, wrapped)
  const unwrappedRaw = await exportDek(unwrapped)

  assert.deepEqual(unwrappedRaw, originalRaw)
})

test('unwrap DEK with wrong master-password KEK fails', async () => {
  const rightKek = await deriveKek('right', generateSalt(), TEST_ITERATIONS)
  const wrongKek = await deriveKek('wrong', generateSalt(), TEST_ITERATIONS)
  const dek = await generateDek()

  const wrapped = await wrapDek(rightKek, dek)
  await assert.rejects(() => unwrapDek(wrongKek, wrapped))
})

test('encrypt/decrypt private-key bytes round trip', async () => {
  const kek = await testKek()
  const privateKeyBytes = new Uint8Array(32).fill(7) // stand-in PKCS#8 DER

  const envelope = await encryptPrivateKey(kek, privateKeyBytes)
  const recovered = await decryptPrivateKey(kek, envelope)

  assert.deepEqual(recovered, privateKeyBytes)
})

test('decrypt private-key bytes with wrong KEK fails', async () => {
  const kek = await testKek()
  const otherKek = await deriveKek('other', generateSalt(), TEST_ITERATIONS)
  const privateKeyBytes = new Uint8Array(16).fill(9)

  const envelope = await encryptPrivateKey(kek, privateKeyBytes)
  await assert.rejects(() => decryptPrivateKey(otherKek, envelope))
})
