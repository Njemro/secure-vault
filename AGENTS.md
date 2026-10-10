# Secure Vault — AI Agent Instructions

## 1. Project Overview

Secure Vault is a university project for secure storage and sharing of secrets such as:

* passwords
* API keys
* certificates
* other sensitive credentials

The primary security goal is a zero-knowledge architecture.

The backend must never receive or store:

* plaintext master passwords
* plaintext secrets
* KEKs
* plaintext DEKs

All secret encryption and decryption must happen on the client/browser.

---

## 2. Technology Stack

### Frontend

* React
* JavaScript
* ESLint
* Browser Web Crypto API

### Gateway

* Spring Cloud Gateway
* Java
* Maven
* Redis for rate limiting/security tracking

### Backend

* Spring Boot
* Java
* Maven
* REST API

### Database

* MySQL
* MySQL Workbench is only a database management tool, not the database server.

### Security / Infrastructure

* Redis
* Keycloak for OIDC
* Docker / Docker Compose
* HTTPS in deployment

Architecture:

React SPA
↓
HTTPS
↓
Spring Cloud Gateway
↓
Spring Boot API
↓
MySQL

Gateway and backend may use Redis.

Spring Boot communicates with Keycloak for OIDC.

---

## 3. Architectural Boundaries

### React

Responsible for:

* user interface
* client-side cryptography
* master password handling
* secret encryption/decryption
* RSA key generation
* private key protection
* communicating with the backend

### Spring Cloud Gateway

Responsible for:

* routing
* rate limiting
* IP blocking
* suspicious request detection
* request filtering
* forwarding requests to backend

The Gateway must not contain business logic that belongs to the backend.

### Spring Boot Backend

Responsible for:

* authentication
* authorization
* RBAC
* MFA/TOTP
* OIDC integration
* vault CRUD
* secret sharing metadata
* security policies
* audit logging
* honeypot detection
* session management

The backend must not decrypt user secrets.

### MySQL

Stores:

* users
* encrypted secret data
* encrypted DEKs
* encrypted private keys
* public keys
* secret shares
* audit records
* security policies
* security metadata

Never store plaintext secrets.

---

# 4. Cryptography Rules

## Never implement custom cryptography

Always use established cryptographic libraries and browser/platform APIs.

For browser cryptography prefer the Web Crypto API.

Do not invent encryption algorithms, key derivation algorithms, random number generators, or cryptographic protocols.

---

## Master Password

The master password is a client-side secret.

It must never be sent to the backend.

The master password is processed using a password-based KDF.

Initial implementation:

PBKDF2-HMAC-SHA-256

The exact iteration count must be chosen based on benchmarking and security requirements.

The KDF produces a 256-bit key called:

KEK = Key Encryption Key

The salt is not secret and may be stored by the backend.

---

## Secret Encryption

Every secret must have its own randomly generated symmetric key:

DEK = Data Encryption Key

The DEK must be generated using a cryptographically secure random generator.

Use:

AES-256-GCM

The plaintext secret is encrypted with the DEK.

Conceptually:

plaintext secret
↓
AES-GCM(DEK)
↓
encrypted secret

Every AES-GCM encryption must use a fresh unique IV/nonce.

Never reuse an IV with the same AES-GCM key.

---

## DEK Protection

The DEK must be encrypted using the KEK.

Conceptually:

DEK
↓
AES-GCM(KEK)
↓
encrypted DEK

The IV used for encrypting the DEK must be different from the IV used for encrypting the secret.

IVs are not secret and may be stored with the corresponding ciphertext.

---

# 5. Secret Sharing

A user does not need to know the recipient when a secret is initially created.

Sharing happens later.

Example:

User A owns a secret.

The database contains:

Secret
├── encryptedSecret
├── secretIV
└── encryptedDEK

When A wants to share the secret with B:

1. Browser obtains B's public RSA key.
2. A's browser derives the KEK from A's master password.
3. A's browser decrypts the encrypted DEK.
4. A's browser encrypts the DEK using B's RSA public key.
5. The encrypted DEK for B is sent to the backend.
6. The original encrypted secret remains unchanged.

Use:

RSA-OAEP

Do not encrypt the complete secret using RSA.

RSA is used only to wrap the small DEK.

Conceptually:

```
          ┌── RSA-OAEP(B public key) ──> encrypted DEK for B
          │
```

DEK ──────────┤
│
└── remains the key for AES-GCM encrypted secret

B later:

B private key
↓
decrypt encrypted DEK
↓
DEK
↓
AES-GCM decrypt encrypted secret
↓
plaintext secret

---

# 6. Private RSA Key

Every user generates an RSA key pair on the client.

The public key may be stored on the server.

The private key must never be stored in plaintext on the server.

If the private key is persisted on the backend, it must first be encrypted client-side.

The encrypted private key may then be stored by the backend.

The private key must only be decrypted in the browser when required.

Do not put private keys in:

* source code
* Git
* logs
* plaintext database columns
* localStorage unless there is a clearly justified secure design

Prefer secure browser mechanisms where appropriate.

---

# 7. Database Model

Initial conceptual entities:

## users

* id
* username
* email
* authentication-related fields
* role
* kdf_salt
* public_key
* encrypted_private_key
* MFA/TOTP fields
* status
* created_at
* updated_at

## secrets

* id
* owner_id
* name
* encrypted_secret
* secret_iv
* encrypted_dek
* dek_iv
* created_at
* updated_at

## secret_shares

* id
* secret_id
* recipient_id
* encrypted_dek_for_recipient
* created_at
* revoked_at/status

Do not assume this schema is final.

Before implementing major database changes, explain the proposed design and identify security implications.

---

# 8. Authentication

Authentication may use:

* username/password
* TOTP MFA
* OIDC / Keycloak

Do not confuse authentication credentials with the vault master password.

The vault master password must remain client-side.

Session security should include:

* HttpOnly cookies where appropriate
* Secure cookies in HTTPS
* appropriate SameSite configuration
* session/token rotation
* configurable session lifetime
* session revocation

Never store authentication tokens in localStorage unless explicitly justified.

---

# 9. Roles

The application has three main roles:

* ADMIN
* TEAM_LEAD
* DEVELOPER

The backend must enforce authorization.

Frontend role checks are only for UI purposes and must never be treated as security boundaries.

---

# 10. Admin Security Policies

Admin should eventually be able to configure policies such as:

* minimum master password length
* secret rotation interval
* session duration
* other security-related policies

Do not hardcode security policies when the requirements specify that they are configurable.

---

# 11. API Gateway Security

Spring Cloud Gateway should eventually provide:

* rate limiting
* Redis-backed counters
* IP blocking
* suspicious request detection
* request filtering
* routing

Examples of suspicious behavior:

* excessive failed login attempts
* repeated failed decrypt-related operations
* suspicious request sequences
* repeated use of expired session tokens
* abnormal request frequency

Gateway security must complement, not replace, backend authorization.

---

# 12. Audit Log

Every important security-sensitive action must be logged.

Examples:

* registration
* successful login
* failed login
* MFA failure
* secret creation
* secret read
* secret update
* secret deletion
* secret sharing
* share revocation
* role changes
* policy changes
* session creation
* session revocation
* suspicious activity
* IP blocking
* honeypot access

Never log:

* plaintext secrets
* master passwords
* KEKs
* plaintext DEKs
* private keys

Audit records should use a cryptographic hash chain.

Conceptually:

Record N:
previousHash + complete canonical record
↓
SHA-256
↓
hash

Record N+1 uses Record N's hash as previousHash.

Modifying an old record must make the chain validation fail.

---

# 13. Honeypot

The project should contain fake/honeypot secrets.

Normal users must never see them through the normal application interface.

If a honeypot is accessed:

1. record an audit event
2. freeze the active user
3. revoke active sessions
4. alert/notify the administrator
5. preserve evidence in the audit system

A specially vulnerable SQL injection demonstration endpoint may exist for the university security demonstration.

It must:

* be disabled by default
* be isolated from normal application functionality
* only be enabled explicitly by an administrator
* never be used by normal production endpoints

Never introduce SQL injection vulnerabilities into normal application code.

---

# 14. Coding Rules

Prefer simple, readable code.

Use clear names.

Avoid unnecessary abstractions.

Do not introduce libraries unless there is a good reason.

Before adding a dependency:

1. explain why it is needed
2. check whether the existing stack already provides the functionality
3. consider the security implications

Follow the existing project formatting and linting configuration.

Do not silently change the architecture.

If a requested implementation conflicts with the architecture, explain the conflict before making major changes.

---

# 15. Testing

Every security-sensitive feature should have tests.

Important areas:

* authentication
* authorization
* MFA
* secret CRUD
* encryption/decryption
* sharing
* key wrapping
* session management
* rate limiting
* IP blocking
* audit hash-chain validation
* honeypot detection

Crypto tests must verify complete round trips.

Example:

plaintext
→ encrypt
→ decrypt
→ original plaintext

Also test that modified ciphertext or authentication data fails verification.

---

# 16. AI Agent Behavior

Before making a major architectural change:

1. Explain the proposed change.
2. Explain affected files.
3. Explain security implications.
4. Wait for confirmation if the change is destructive or architectural.

Do not delete files or rewrite large parts of the project without explicit confirmation.

Do not modify security-critical code merely to make tests pass.

Never weaken security controls to solve an implementation problem.

When uncertain about a security decision, stop and explain the uncertainty instead of guessing.

---

# 17. Development Workflow

Work incrementally.

Preferred order:

1. project structure
2. Docker infrastructure
3. Spring Boot backend skeleton
4. React frontend skeleton
5. MySQL integration
6. Redis integration
7. authentication
8. crypto proof of concept
9. vault CRUD
10. RSA key management
11. secret sharing
12. MFA/TOTP
13. RBAC
14. Spring Cloud Gateway security
15. audit log
16. honeypot
17. OIDC / Keycloak integration
18. security testing
19. documentation

Do not attempt to implement the entire project in one task.

After each meaningful task:

* run relevant tests
* run linting where applicable
* report changed files
* report test results
* mention any remaining security concerns
