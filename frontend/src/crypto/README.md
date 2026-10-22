# Client-Side Crypto Module

All cryptographic operations run in the browser via the **Web Crypto API**
(`crypto.subtle`). No third-party crypto libraries, no custom primitives.

The module is **byte-oriented**: functions take `Uint8Array`/`CryptoKey` in and
return `Uint8Array`/`CryptoKey` (or small envelope objects) out. Base64 is only
for JSON/API boundaries (`encoding.js`) and defines **no** payload contract.

## Files

| File            | Responsibility                                                        |
| --------------- | --------------------------------------------------------------------- |
| `constants.js`  | Algorithm parameters (iteration count, key sizes, IV/salt sizes, etc.)|
| `kek.js`        | Salt generation, master password → KEK derivation (PBKDF2)            |
| `aesGcm.js`     | DEK generation, AES-GCM encrypt/decrypt, DEK wrap/unwrap, private-key bytes |
| `rsa.js`        | RSA-OAEP keypair, SPKI/PKCS#8 export/import, wrap DEK for recipient   |
| `encoding.js`   | Base64 helpers — **API boundary only**, no payload shape              |
| `index.js`      | Public surface (re-exports)                                           |
| `*.test.js`     | `node:test` unit tests                                                |

## Operations

### 1. KEK derivation (PBKDF2-HMAC-SHA-256)

```js
import { deriveKek, generateSalt } from './crypto/index.js'

const salt = generateSalt()              // 16 random bytes (stored, NOT secret)
const kek = await deriveKek(masterPassword, salt)   // non-extractable AES-256 key
```

- The master password **never leaves the browser**.
- The returned KEK is **non-extractable** — its raw bytes cannot be read out.
- Default iteration count: **600 000** (OWASP 2023 recommendation). It is a
  parameter, **not** hard-coded into `deriveKek`, so it stays configurable and
  migratable. Benchmark before changing it.

### 2. DEK generation

```js
const dek = await generateDek()   // fresh AES-256-GCM key (extractable)
```

Each secret has its own random DEK. Extractable so it can be exported/wrapped.

### 3. AES-GCM encryption of bytes

```js
const envelope = await encryptBytes(key, plaintext)   // { iv, ciphertext }
const recovered = await decryptBytes(key, envelope)
```

- Key: AES-**256**-GCM, **12-byte** fresh IV per encryption (never reused),
  **128-bit** authentication tag.
- Envelope shape: `{ iv: Uint8Array(12), ciphertext: Uint8Array }`.
  `ciphertext` includes the GCM tag **appended** (Web Crypto behavior). Store
  and transport `iv` and `ciphertext` together.
- `decryptBytes` **rejects** on a wrong key or on any tampering with
  `iv` / `ciphertext` / tag.

### 4. DEK wrap / unwrap with the KEK

```js
const wrapped = await wrapDek(kek, dek)          // AES-GCM(KEK, raw DEK bytes)
const dek2    = await unwrapDek(kek, wrapped)
```

The backend stores the wrapped DEK — never the master password, KEK, or the
plaintext DEK. Wrong master password ⇒ `unwrapDek` rejects.

### 5. RSA-OAEP keypair & recipient wrapping

```js
const { publicKey, privateKey } = await generateRsaKeyPair()
const spki = await exportPublicKeySpki(publicKey)          // SPKI DER bytes
const pub  = await importPublicKeySpki(spki)

const wrappedDek = await wrapDekForRecipient(pub, dek)     // RSA-OAEP(DEK)
const dek3 = await unwrapDekForRecipient(privateKey, wrappedDek)
```

- **2048-bit** RSA-OAEP, hash **SHA-256**, public exponent **65537**.
- **Only the DEK is RSA-wrapped** — never the full secret (RSA is not used for
  bulk data).
- Sharing flow: owner decrypts the wrapped DEK with their KEK, then
  `wrapDekForRecipient(recipientPublicKey, dek)`; the original AES-GCM
  encrypted secret is unchanged.

### 6. Private-key byte protection

```js
import { exportPrivateKeyPkcs8, importPrivateKeyPkcs8 } from './crypto/index.js'
import { encryptPrivateKey, decryptPrivateKey } from './crypto/index.js'

const pkcs8 = await exportPrivateKeyPkcs8(privateKey)     // PKCS#8 DER bytes
const env   = await encryptPrivateKey(kek, pkcs8)         // AES-GCM(KEK, bytes)
const plain = await decryptPrivateKey(kek, env)           // → PKCS#8 DER bytes
const priv  = await importPrivateKeyPkcs8(plain)
```

The private key is only decrypted in the browser when needed and is never
persisted by this module.

## Algorithm parameters

| Parameter               | Value                          | Where                     |
| ----------------------- | ------------------------------ | ------------------------- |
| KEK derivation          | PBKDF2-HMAC-SHA-256            | `constants.js`            |
| PBKDF2 iterations       | **600 000** default (config.)  | `PBKDF2_DEFAULT_ITERATIONS` |
| Salt size               | **16 bytes** (128-bit)         | `SALT_BYTES`              |
| DEK / secret encryption | AES-256-GCM                    | `AES_KEY_BITS` = 256      |
| IV / nonce size         | **12 bytes** (96-bit), fresh   | `IV_BYTES`                |
| GCM tag length          | **128 bits**                   | `GCM_TAG_BITS`            |
| RSA keypair             | RSA-OAEP, SHA-256, 2048-bit    | `RSA_MODULUS_BITS`        |
| RSA public exponent     | 65537                          | `RSA_PUBLIC_EXPONENT`     |
| Public-key format       | **SPKI DER** (X.509)           | `exportPublicKeySpki`     |
| Private-key format      | **PKCS#8 DER**                 | `exportPrivateKeyPkcs8`   |

## Public-key format

Public keys are exchanged as **SPKI DER** (`exportKey('spki', ...)` /
`importKey('spki', ...)`), i.e. a DER-encoded X.509 `SubjectPublicKeyInfo`.
Private keys use **PKCS#8 DER**. Base64 is applied only when these DER bytes
enter JSON — decode back to bytes before importing.

## Limitations / notes

- **Scope**: this module covers crypto primitives only. It does **not** define
  API payloads, storage, session handling, or the full zero-knowledge login
  flow — those belong to integration code.
- **Iteration count** must be benchmarked for target hardware before it is
  frozen; treat `PBKDF2_DEFAULT_ITERATIONS` as a documented, adjustable value.
- **RSA-OAEP-SHA256 message limit**: max plaintext = `modulusBytes − 2·hashLen − 2`
  = `256 − 64 − 2 = 190 bytes`. A 32-byte DEK fits comfortably; do not exceed it.
- **Master password / private key / KEK / plaintext DEK are never persisted**
  by this module; callers own all storage and must follow the security rules.
- **GCM IVs** are drawn fresh per encryption; never reuse an IV with a key.

