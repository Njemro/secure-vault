// Tests for master-password -> KEK derivation (PBKDF2-HMAC-SHA-256).
// Runs on Node's built-in test runner + Web Crypto (no test framework added).

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  PBKDF2_DEFAULT_ITERATIONS,
  SALT_BYTES,
} from './constants.js'
import { deriveKek, generateSalt } from './kek.js'
import { encryptBytes, decryptBytes } from './aesGcm.js'

// A low iteration count keeps these tests fast; the production default is
// asserted separately (we never run 600k iterations in a unit test).
const TEST_ITERATIONS = 1000

test('default iteration count is explicit and documented (600000)', () => {
  assert.equal(PBKDF2_DEFAULT_ITERATIONS, 600_000)
})

test('generateSalt returns a fresh 16-byte salt each call', () => {
  const a = generateSalt()
  const b = generateSalt()

  assert.ok(a instanceof Uint8Array)
  assert.equal(a.length, SALT_BYTES)
  assert.equal(SALT_BYTES, 16)

  // Salts must be random, so two calls must not collide.
  assert.notDeepEqual(a, b)
})

test('generateSalt honors a custom length', () => {
  assert.equal(generateSalt(32).length, 32)
})

test('KEK round trip: same password+salt encrypts and decrypts', async () => {
  const salt = generateSalt()
  const kek = await deriveKek('correct horse battery staple', salt, TEST_ITERATIONS)

  const plaintext = new TextEncoder().encode('secret bytes to protect')
  const envelope = await encryptBytes(kek, plaintext)
  const recovered = await decryptBytes(kek, envelope)

  assert.deepEqual(recovered, plaintext)
})

test('two KEK derivations with same inputs are interchangeable', async () => {
  const salt = generateSalt()
  const kek1 = await deriveKek('pw', salt, TEST_ITERATIONS)
  const kek2 = await deriveKek('pw', salt, TEST_ITERATIONS)

  const plaintext = new TextEncoder().encode('shared verifier')
  const envelope = await encryptBytes(kek1, plaintext)
  const recovered = await decryptBytes(kek2, envelope)

  assert.deepEqual(recovered, plaintext)
})

test('wrong password produces a KEK that fails to decrypt', async () => {
  const salt = generateSalt()
  const correctKek = await deriveKek('right-password', salt, TEST_ITERATIONS)
  const wrongKek = await deriveKek('wrong-password', salt, TEST_ITERATIONS)

  const plaintext = new TextEncoder().encode('protected value')
  const envelope = await encryptBytes(correctKek, plaintext)

  await assert.rejects(
    () => decryptBytes(wrongKek, envelope),
    /OperationError|operation-specific|The operation failed/,
  )
})

test('different salt produces a different KEK (fails decryption)', async () => {
  const salt1 = generateSalt()
  const salt2 = generateSalt()
  const kek1 = await deriveKek('pw', salt1, TEST_ITERATIONS)
  const kek2 = await deriveKek('pw', salt2, TEST_ITERATIONS)

  const plaintext = new TextEncoder().encode('salt matters')
  const envelope = await encryptBytes(kek1, plaintext)

  await assert.rejects(() => decryptBytes(kek2, envelope))
})
