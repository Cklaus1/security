# Secrets Architecture: dotenvx + AWS KMS + OpenBao

How three tools solve different parts of the secrets problem, and how they work together.

---

## The Problem

Every application needs secrets (API keys, database credentials, tokens). These secrets must be:

1. **Stored safely** — not in plaintext in git
2. **Distributed to teammates** — devs need secrets to work locally
3. **Deployed to production** — the running app needs the real values
4. **Protected at runtime** — an attacker on the machine shouldn't get everything

No single tool solves all four. Here's how each tool handles each layer.

---

## What Each Tool Does

### dotenvx — Encrypt secrets in git

dotenvx encrypts `.env` files using ECIES (Elliptic Curve public-key cryptography). The encrypted file is safe to commit. The private key is stored separately.

```
.env (committed to git):
  DOTENV_PUBLIC_KEY="04a9c2b..."
  DATABASE_URL="encrypted:BAh7CEk..."
  STRIPE_KEY="encrypted:Rk3mVx..."

.env.keys (never committed):
  DOTENV_PRIVATE_KEY=3c8e9a7...
```

**Solves**: storing secrets in git, sharing encrypted files across the team, CI/CD access.

**Doesn't solve**: protecting the private key at runtime. If an attacker gets shell access, they find `DOTENV_PRIVATE_KEY` in process.env or `.env.keys` on disk.

### AWS KMS — Hardware-backed key management

AWS KMS stores encryption keys in FIPS 140-2 Level 3 hardware security modules (HSMs). The key never leaves the HSM. You send data to KMS, it encrypts/decrypts server-side, and returns the result.

```
Your app → API call → AWS KMS (key lives in HSM) → returns plaintext
                       ▲
                       │ authenticated by IAM role
                       │ (no secret needed on the machine)
```

**Solves**: protecting the master key. Even with root shell access, the attacker can't extract the key from the HSM. They can only make API calls while they have access to the IAM role, which you can revoke remotely.

**Doesn't solve**: developer workflow, .env file management, local development.

### OpenBao — Self-hosted secrets server

OpenBao (open-source fork of HashiCorp Vault) is a centralized secrets server. Applications authenticate and fetch secrets at runtime.

```
App → authenticates (IAM, Kubernetes, AppRole) → OpenBao server → returns secret
```

It includes a Transit secrets engine that works like KMS — encrypt/decrypt via API without exposing the key.

**Solves**: centralized secret management, audit logging, dynamic secrets, secret rotation, multi-cloud.

**Doesn't solve**: developer workflow with .env files (different paradigm).

---

## How They Work Together

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Developer Workflow                     │
│                                                          │
│  .env (encrypted values)  ──committed to──►  Git repo    │
│  .env.keys (private key)  ──never committed              │
│                                                          │
│  dotenvx encrypt    encrypts values with public key      │
│  dotenvx run        decrypts and injects into process    │
│                                                          │
│  Developers share .env.keys out-of-band or via           │
│  DOTENV_PRIVATE_KEY env var                              │
└─────────────────────────────────────────────────────────┘
          │
          │  In production, the private key is NOT
          │  stored on disk or in env vars.
          │  Instead:
          ▼
┌─────────────────────────────────────────────────────────┐
│                   Production Runtime                     │
│                                                          │
│  Option A: AWS KMS                                       │
│  ┌───────────────────────────────────────────────┐       │
│  │ dotenvx reads encrypted .env                  │       │
│  │     ↓                                         │       │
│  │ Calls AWS KMS Decrypt API                     │       │
│  │     ↓                                         │       │
│  │ KMS decrypts the private key (or values       │       │
│  │ directly) using hardware HSM                  │       │
│  │     ↓                                         │       │
│  │ Auth: IAM role attached to EC2/ECS/Lambda     │       │
│  │ (no secret needed on the machine)             │       │
│  └───────────────────────────────────────────────┘       │
│                                                          │
│  Option B: OpenBao                                       │
│  ┌───────────────────────────────────────────────┐       │
│  │ dotenvx reads encrypted .env                  │       │
│  │     ↓                                         │       │
│  │ Calls OpenBao Transit decrypt endpoint        │       │
│  │     ↓                                         │       │
│  │ OpenBao decrypts using its internal key       │       │
│  │     ↓                                         │       │
│  │ Auth: Kubernetes auth, AppRole, or            │       │
│  │ AWS IAM auth method                           │       │
│  └───────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────┘
```

### Data Flow: Developer encrypts a secret

```
1. Developer adds plaintext value to .env:
   STRIPE_KEY=sk_live_abc123

2. Runs: dotenvx encrypt
   - Generates ECIES keypair (or uses existing)
   - Encrypts value with public key
   - Writes public key to .env
   - Writes private key to .env.keys

3. .env now contains:
   DOTENV_PUBLIC_KEY="04a9c2b..."
   STRIPE_KEY="encrypted:BAh7CEk..."

4. Developer commits .env to git (safe — values are encrypted)
5. Developer shares .env.keys with team out-of-band
```

### Data Flow: Local development

```
1. Developer has .env (from git) and .env.keys (shared out-of-band)

2. Runs: dotenvx run -- node app.js
   - Reads .env, finds encrypted values
   - Reads private key from .env.keys
   - Decrypts values in memory
   - Injects into process.env
   - Spawns node app.js with decrypted env

3. App runs with real secrets in process.env
```

### Data Flow: Production with AWS KMS

```
1. One-time setup:
   - Create a KMS key in AWS console
   - Encrypt the DOTENV_PRIVATE_KEY with KMS:
     aws kms encrypt \
       --key-id alias/dotenvx-prod \
       --plaintext fileb://<(echo -n "3c8e9a7...") \
       --output text --query CiphertextBlob > encrypted-private-key.b64
   - Store encrypted-private-key.b64 as env var or in S3
   - Attach IAM role to your EC2/ECS/Lambda with kms:Decrypt permission

2. At runtime:
   - dotenvx reads encrypted .env from the deployed code
   - Reads the KMS-encrypted private key from env var
   - Calls KMS Decrypt API to unwrap the private key
   - Uses the unwrapped private key to decrypt .env values
   - Injects into process.env
   - The raw private key existed only in memory, briefly

3. If attacker gets shell:
   - Sees encrypted .env — can't read values
   - Sees KMS-encrypted private key blob — can't decrypt without IAM role
   - Can call KMS API if they have the IAM role — but this is logged in CloudTrail
   - You can revoke the IAM role remotely to cut off access
```

### Data Flow: Production with OpenBao

```
1. One-time setup:
   - Deploy OpenBao server on hardened internal machine
   - Enable Transit secrets engine:
     bao secrets enable transit
     bao write transit/keys/dotenvx-prod type=aes256-gcm96
   - Store the dotenvx private key encrypted via Transit:
     bao write transit/encrypt/dotenvx-prod \
       plaintext=$(echo -n "3c8e9a7..." | base64)
   - Configure auth method (Kubernetes, AppRole, AWS IAM)
   - Write policy allowing decrypt only

2. At runtime:
   - dotenvx reads encrypted .env
   - Authenticates to OpenBao (auto-auth via agent or direct)
   - Calls Transit decrypt endpoint to unwrap the private key
   - Uses unwrapped private key to decrypt .env values
   - Injects into process.env

3. If attacker gets shell:
   - OpenBao tokens are short-lived (expire in hours)
   - All access is audit-logged
   - You can revoke the token/lease remotely
   - Attacker can't extract the Transit key from OpenBao
```

---

## Security Comparison by Deployment Model

| Attack Scenario | dotenvx alone | dotenvx + AWS KMS | dotenvx + OpenBao |
|----------------|---------------|--------------------|--------------------|
| Attacker gets git repo | Sees ciphertext only | Sees ciphertext only | Sees ciphertext only |
| Attacker reads CI logs | Encrypted values are opaque | Same | Same |
| Attacker gets shell on server | Finds private key in env/disk | Finds KMS-encrypted blob (useless without IAM) | Finds expired or revocable token |
| Attacker reads process.env | Sees decrypted values (unavoidable) | Same — values must be in memory for the app | Same |
| Attacker exfiltrates database dump | N/A | N/A | N/A |
| Attacker compromises CI/CD | Can extract DOTENV_PRIVATE_KEY from secrets | Can extract KMS-encrypted key (needs IAM to use) | Can extract short-lived token |
| You detect breach, respond | Rotate private key, re-encrypt all files | Revoke IAM role instantly, rotate key | Revoke token/lease instantly, rotate key |

---

## When to Use What

### dotenvx alone
- Small teams, early-stage startups
- No compliance requirements
- Want simple workflow with zero infrastructure
- Private key as env var in CI/CD is acceptable risk

### dotenvx + AWS KMS
- Running on AWS
- Need to protect the private key from server compromise
- Want audit trail (CloudTrail)
- Need compliance (SOC2, HIPAA, PCI)
- Don't want to manage additional infrastructure

### dotenvx + OpenBao
- Multi-cloud or on-premise
- Need dynamic secrets (database credentials that rotate automatically)
- Need secret leasing (secrets that auto-expire)
- Want centralized policy engine across all services
- Have team capacity to operate OpenBao cluster
- Data sovereignty requirements (secrets can't leave your network)

### dotenvx + OpenBao + AWS KMS
- OpenBao uses AWS KMS for auto-unseal (OpenBao's own master key protected by HSM)
- dotenvx uses OpenBao Transit for private key decryption
- Three layers: dotenvx encrypts files, OpenBao manages the private key, KMS protects OpenBao's master key

```
.env (encrypted) → dotenvx → OpenBao Transit → AWS KMS (auto-unseal)
     layer 1          layer 2        layer 3
   file encryption   key management  HSM protection
```

---

## Implementation Status

| Integration | Status | What's needed |
|-------------|--------|---------------|
| dotenvx alone | Production-ready | Nothing — works today |
| dotenvx + AWS KMS | Not yet implemented | Add KMS decrypt path in `findPrivateKey.js`, new `--kms` flag or `DOTENV_KMS_KEY_ARN` env var |
| dotenvx + OpenBao | Not yet implemented | Add OpenBao Transit API call in `findPrivateKey.js`, new `--vault-addr` and `--vault-transit-key` options |
| OpenBao auto-unseal with KMS | Production-ready in OpenBao | OpenBao config: `seal "awskms" { kms_key_id = "..." }` |

The dotenvx changes required are relatively small — `findPrivateKey.js` currently checks process.env and `.env.keys` file. Adding a KMS/OpenBao code path means: if `DOTENV_KMS_KEY_ARN` or `DOTENV_VAULT_ADDR` is set, call the respective API to decrypt the private key instead of reading it from disk.

---

## Cost Comparison

| | dotenvx alone | + AWS KMS | + OpenBao |
|---|---------------|-----------|-----------|
| Software | Free | Free | Free |
| Infrastructure | None | ~$1/month per key | 3-5 servers for HA cluster |
| API calls | None | $0.03 per 10k calls | Self-hosted (included) |
| Operations | None | None (AWS managed) | Significant (upgrades, monitoring, unseal) |
| Total for small team | $0 | ~$1/month | $200-500/month (infra) + engineer time |
