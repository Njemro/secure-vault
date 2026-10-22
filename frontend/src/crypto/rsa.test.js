// Tests for RSA-OAEP (SHA-256) key generation, SPKI/PKCS#8 export/import, and
// DEK wrapping/unwrapping for a recipient. Node built-in test runner + Web Crypto.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { RSA_MODULUS_BITS } from './constants.js'
import { generateDek, exportDek, encryptBytes, decryptBytes } from './aesGcm.js'
import {
  generateRsaKeyPair,
  exportPublicKeySpki,
  importPublicKeySpki,
  exportPrivateKeyPkcs8,
  importPrivateKeyPkcs8,
  wrapDekForRecipient,
  unwrapDekForRecipient,
} from './rsa.js'

test('generateRsaKeyPair creates a 2048-bit RSA-OAEP SHA-256 pair', async () => {
  const { publicKey, privateKey } = await generateRsaKeyPair()

  assert.equal(publicKey.algorithm.name, 'RSA-OAEP')
  assert.equal(publicKey.algorithm.modulusLength, RSA_MODULUS_BITS)
  assert.equal(publicKey.algorithm.hash.name, 'SHA-256')
  assert.equal(privateKey.algorithm.name, 'RSA-OAEP')
})

test('public key exports to SPKI DER and re-imports', async () => {
  const { publicKey } = await generateRsaKeyPair()

  const spki = await exportPublicKeySpki(publicKey)
  assert.ok(spki instanceof Uint8Array)
  assert.ok(spki.length > 0)

  // SPKI DER for a 2048-bit key is ~294 bytes.
  const reimported = await importPublicKeySpki(spki)
  assert.equal(reimported.algorithm.name, 'RSA-OAEP')
  assert.equal(reimported.usages.includes('encrypt'), true)
})

test('wrap DEK for recipient (SPKI) then unwrap with private key', async () => {
  const { publicKey, privateKey } = await generateRsaKeyPair()
  const dek = await generateDek()
  const dekRaw = await exportDek(dek)

  // Simulate recipient fetching our public key over the wire as SPKI DER.
  const spki = await exportPublicKeySpki(publicKey)
  const recipientPublicKey = await importPublicKeySpki(spki)

  const wrappedDek = await wrapDekForRecipient(recipientPublicKey, dek)
  const unwrappedDek = await unwrapDekForRecipient(privateKey, wrappedDek)
  const unwrappedRaw = await exportDek(unwrappedDek)

  assert.deepEqual(unwrappedRaw, dekRaw)

  // The unwrapped DEK still decrypts data originally encrypted by the DEK.
  const secret = new TextEncoder().encode('shared secret value')
  const secretEnvelope = await encryptBytes(dek, secret)
  assert.deepEqual(await decryptBytes(unwrappedDek, secretEnvelope), secret)
})

test('unwrap with a different private key fails', async () => {
  const alice = await generateRsaKeyPair()
  const bob = await generateRsaKeyPair()
  const dek = await generateDek()

  const wrappedDek = await wrapDekForRecipient(alice.publicKey, dek)
  await assert.rejects(() => unwrapDekForRecipient(bob.privateKey, wrappedDek))
})

test('private key exports to PKCS#8 DER and re-imports for unwrapping', async () => {
  const { publicKey, privateKey } = await generateRsaKeyPair()
  const dek = await generateDek()

  const wrappedDek = await wrapDekForRecipient(publicKey, dek)

  // Simulate: export private key -> (caller would store it) -> re-import.
  const pkcs8 = await exportPrivateKeyPkcs8(privateKey)
  assert.ok(pkcs8 instanceof Uint8Array)
  assert.ok(pkcs8.length > 0)

  const reimportedPrivateKey = await importPrivateKeyPkcs8(pkcs8)
  const unwrappedDek = await unwrapDekForRecipient(reimportedPrivateKey, wrappedDek)

  assert.deepEqual(await exportDek(unwrappedDek), await exportDek(dek))
})

test('RSA wrap fails if ciphertext is tampered', async () => {
  const { publicKey, privateKey } = await generateRsaKeyPair()
  const dek = await generateDek()

  const wrappedDek = await wrapDekForRecipient(publicKey, dek)
  const tampered = Uint8Array.from(wrappedDek)
  tampered[tampered.length - 1] ^= 0xff

  await assert.rejects(() => unwrapDekForRecipient(privateKey, tampered))
})
