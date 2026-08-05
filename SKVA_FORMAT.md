# SKVA v1 File Format

This document defines `SKVA`, an encrypted, stream-based backup format for a single file.

SKVA is designed to be self-contained and long-term recoverable. The file carries everything needed to decrypt it: cryptographic parameters, per-recipient key material, and a human-readable recovery note embedded in the header. A technically competent reader with the right password can reconstruct the decryption procedure from the file alone, without access to the original software or this specification.

The format supports one or more recipients. Each recipient has a password-derived asymmetric keypair; the file encryption key (FEK) is wrapped independently per recipient, so any single valid password is sufficient for decryption.

- [SKVA v1 File Format](#skva-v1-file-format)
  - [1. Cryptographic Profile](#1-cryptographic-profile)
  - [2. Scope](#2-scope)
  - [3. Extension and Identification](#3-extension-and-identification)
  - [4. Binary Wire Layout](#4-binary-wire-layout)
  - [5. Header JSON Schema](#5-header-json-schema)
    - [5.1 Example Header](#51-example-header)
    - [5.2 Required Fields](#52-required-fields)
    - [5.3 `kdf` Object](#53-kdf-object)
    - [5.4 `kem` Object](#54-kem-object)
    - [5.5 `fek` Object](#55-fek-object)
    - [5.6 `payload` Object](#56-payload-object)
    - [5.7 Optional Fields](#57-optional-fields)
  - [6. Chunk and Payload Rules](#6-chunk-and-payload-rules)
  - [7. Encrypt Flow](#7-encrypt-flow)
  - [8. Decrypt Flow](#8-decrypt-flow)
  - [9. Security Considerations](#9-security-considerations)
    - [9.1 Tamper Verification](#91-tamper-verification)
    - [9.2 Password Recommendation](#92-password-recommendation)


## 1. Cryptographic Profile

SKVA v1 uses:

- `argon2id` for password-based key derivation
- `ml_kem1024_p384` for per-recipient shared-secret encapsulation
- `chacha20poly1305` for FEK wrapping and authenticated chunk encryption

Recipient public keys are used for encryption and may be stored in the file or supplied externally. Recipient passwords are used for decryption and initial recipient key setup, not for direct payload encryption.

FEK means File Encryption Key (32 bytes, symmetric key used for payload encryption).

## 2. Scope

Designed for:

- one encrypted backup payload per `.skva` file with one or more recipients
- sequential streaming encrypt/decrypt
- deterministic decoding rules and strict validation
- asymmetric encryption where recipient public keys are available at backup time and recipient passwords are used only for recovery and initial setup

Not designed for:

- multi-file containers
- random-access chunk table
- optional/heuristic cryptographic fallback behavior

## 3. Extension and Identification

- Recommended file extension: `.skva`
- Canonical identification: binary magic bytes in the file prefix

The extension is advisory only.

## 4. Binary Wire Layout

All offsets are zero-based.

| Offset                                           |                    Length | Name                      | Type                | Description                               |
| ------------------------------------------------ | ------------------------: | ------------------------- | ------------------- | ----------------------------------------- |
| 0                                                |                         4 | `magic`                   | ASCII               | Must equal `SKVA`                         |
| 4                                                |                         1 | `version`                 | `uint8`             | Must equal `1`                            |
| 5                                                |                         4 | `header_length`           | `uint32` big-endian | Length of UTF-8 JSON header in bytes      |
| 9                                                |           `header_length` | `header_json`             | bytes               | UTF-8 encoded JSON header                 |
| 9 + `header_length`                              |                         4 | `header_extension_length` | `uint32` big-endian | Length of optional header extension bytes |
| 13 + `header_length`                             | `header_extension_length` | `header_extension`        | bytes               | Opaque optional header extension area     |
| 13 + `header_length` + `header_extension_length` |           remaining bytes | `cipher_payload`          | bytes               | Concatenated encrypted chunks             |

`header_extension` is reserved for optional implementation-defined header-side data. It may be used for header authentication, tampering detection, health checks, extension metadata, or other out-of-band purposes. Its internal format and semantics are out of scope for SKVA v1. Decoders must use `header_extension_length` to locate the payload and may ignore `header_extension` entirely.

## 5. Header JSON Schema

Header is a UTF-8 JSON object.

### 5.1 Example Header

```json
{
  "format": "skva",
  "version": 1,
  "recovery_note": {
    "algorithm": "Basic file format: magic + version + header length + UTF-8 JSON header + header extension length + header extension bytes + encrypted chunks. For each recipient entry: run Argon2id with recorded parameters and that entry's password to recover the deterministic ML-KEM private seed, derive the recipient private key, use ML-KEM decapsulation to recover a shared secret, unwrap FEK with chacha20poly1305 using that shared secret, then decrypt chunks sequentially.",
    "chunk_nonce_format": "uint88_be(chunk_index) || eof_flag_u8",
    "chunk_encrypted": "chacha20poly1305(FEK, nonce_i, aad=empty).encrypt(plaintext_chunk)",
    "fek_encrypted": "chacha20poly1305(kem.shared_secret, fek_nonce, aad=empty).encrypt(FEK)"
  },
  "recipients": [
    {
      "recipient_id": "ops-primary",
      "kdf": {
        "algorithm": "argon2id",
        "salt_b64": "BASE64_ARGON2_SALT_RECIPIENT_1",
        "time_cost": 3,
        "memory_cost_kib": 65536,
        "parallelism": 1,
        "derived_key_bytes": 32
      },
      "kem": {
        "algorithm": "ml_kem1024_p384",
        "ciphertext_b64": "BASE64_KEM_CIPHERTEXT_RECIPIENT_1",
        "public_key_b64": "BASE64_OPTIONAL_PUBLIC_KEY_RECIPIENT_1",
        "public_key_sha256_b64": "BASE64_OPTIONAL_FINGERPRINT_RECIPIENT_1"
      },
      "fek": {
        "algorithm": "chacha20poly1305",
        "nonce_b64": "BASE64_12B_WRAP_NONCE_RECIPIENT_1",
        "encrypted_fek_b64": "BASE64_WRAPPED_FEK_RECIPIENT_1"
      }
    },
    {
      "recipient_id": "ops-backup",
      "kdf": {
        "algorithm": "argon2id",
        "salt_b64": "BASE64_ARGON2_SALT_RECIPIENT_2",
        "time_cost": 3,
        "memory_cost_kib": 65536,
        "parallelism": 1,
        "derived_key_bytes": 32
      },
      "kem": {
        "algorithm": "ml_kem1024_p384",
        "ciphertext_b64": "BASE64_KEM_CIPHERTEXT_RECIPIENT_2",
        "public_key_b64": "BASE64_OPTIONAL_PUBLIC_KEY_RECIPIENT_2",
        "public_key_sha256_b64": "BASE64_OPTIONAL_FINGERPRINT_RECIPIENT_2"
      },
      "fek": {
        "algorithm": "chacha20poly1305",
        "nonce_b64": "BASE64_12B_WRAP_NONCE_RECIPIENT_2",
        "encrypted_fek_b64": "BASE64_WRAPPED_FEK_RECIPIENT_2"
      }
    }
  ],
  "payload": {
    "algorithm": "chacha20poly1305",
    "plaintext_chunk_bytes": 65536
  },
  "meta": {
    "original_filename": "data-archive.zip",
    "original_size_bytes": 734003200,
    "created_at": "2026-07-27T12:00:00Z"
  }
}
```

### 5.2 Required Fields

- `format`: string, must be `"skva"`
- `version`: number, must be `1`
- `recovery_note`: object, free-form recovery description
- `recipients`: array, length >= 1
- `payload`: object

Each `recipients[]` entry must contain:

- `recipient_id`: string identifier
- `kdf`: object
- `kem`: object
- `fek`: object

The format must remain decodable from required structured fields (`recipients`, `payload`).

`recovery_note` has no required internal keys, but it must be informative enough for a technically competent reader to reconstruct the decryption procedure from the header.

### 5.3 `kdf` Object

This object is required inside each `recipients[]` entry.

- `algorithm`: string, must be `"argon2id"`
- `salt_b64`: base64-encoded salt, decoded length 16 bytes
- `time_cost`: integer > 0
- `memory_cost_kib`: integer > 0
- `parallelism`: integer > 0
- `derived_key_bytes`: integer > 0

The KDF object describes how to recover deterministic ML-KEM private seed material from that recipient entry's password and re-derive the same recipient private key later.

Mechanism:

- run Argon2id with the recorded parameters and salt
- interpret the output as the deterministic ML-KEM private seed input for `ml_kem1024_p384`
- apply the same deterministic seed-to-key procedure used when the long-lived recipient keypair was originally established
- if the derived seed/private key does not match the keypair used during encryption, FEK recovery fails

### 5.4 `kem` Object

This object is required inside each `recipients[]` entry.

- `algorithm`: string, must be `"ml_kem1024_p384"`
- `ciphertext_b64`: base64 KEM ciphertext that encapsulates a per-recipient shared secret
- `public_key_b64`: optional base64 encoding of the raw recipient public key bytes used for encapsulation, to aid backup recovery
- `public_key_sha256_b64`: optional base64 SHA-256 digest of the raw recipient public key bytes, exactly 32 bytes after decoding, for key selection safety

The `kem` object identifies the KEM profile used to recover the per-recipient shared secret. The file does not carry the recipient private key. It carries only the KEM ciphertext and the KDF descriptor needed to re-derive the deterministic ML-KEM private seed and recipient private key from that recipient entry's password.

### 5.5 `fek` Object

This object is required inside each `recipients[]` entry.

- `algorithm`: string, must be `"chacha20poly1305"`
- `nonce_b64`: base64 nonce for FEK wrapping, decoded length must be 12 bytes
- `encrypted_fek_b64`: base64 encrypted FEK bytes (ciphertext + 16-byte tag)

FEK wrapping uses `chacha20poly1305(shared_secret, fek_nonce).encrypt(FEK)` with empty AAD.

### 5.6 `payload` Object

- `algorithm`: string, must be `"chacha20poly1305"`
- `plaintext_chunk_bytes`: integer maximum plaintext bytes per chunk

Concise implementation view: `P_i = plaintext_chunk`, then `C_i = chacha20poly1305(FEK, nonce_i).encrypt(P_i)`, and `|C_i| = |P_i| + 16`.

The full 12-byte nonce for each chunk is constructed as:

- 11-byte big-endian chunk counter
- 1-byte EOF marker (`0x00` for non-final chunks, `0x01` for the final chunk)

### 5.7 Optional Fields

- `meta`: small non-sensitive metadata object

Recommended `meta` fields:

- `original_filename`: original filename before encryption
- `original_size_bytes`: original plaintext file size in bytes
- `created_at`: creation timestamp


## 6. Chunk and Payload Rules

Payload is a concatenation of encrypted chunks.

For decrypted chunk plaintext `P_i`:

- `P_i` contains only plaintext chunk data
- for non-final chunks, `|P_i|` must equal `plaintext_chunk_bytes`
- for the final chunk, `|P_i|` must be in range `1..plaintext_chunk_bytes`
- encrypted chunk `C_i` is produced by `chacha20poly1305(FEK, nonce_i).encrypt(P_i)`
- `|C_i| = |P_i| + 16`

Chunk size terminology:

- `plaintext_chunk_bytes` always refers to plaintext bytes in one chunk
- non-final encrypted chunk size is fixed: `encrypted_chunk_size_bytes = plaintext_chunk_bytes + 16`
- the final encrypted chunk may be shorter than non-final encrypted chunks, because the final data chunk may be shorter

Nonce derivation:

- the nonce for chunk `i` is `nonce_i = uint88_be(i) || eof_flag_u8`
- the first 11 nonce bytes are the big-endian chunk counter
- the final nonce byte is the EOF marker
- the format supports at most `2^88` chunks per file

Chunk order and final-chunk signaling are enforced by the authenticated nonce construction (`uint88_be(i)` and `eof_flag_u8` inside `nonce_i`).

Final chunk marker rules:

- the final physical chunk must use `eof_flag_u8 = 0x01`
- non-final chunks must use `eof_flag_u8 = 0x00`

Tag handling:

- each encrypted chunk includes one 16-byte Poly1305 authentication tag
- successful authentication is defined by valid tag verification under the specified key and nonce with empty AAD

## 7. Encrypt Flow

Inputs:

- plaintext input stream
- ciphertext output stream
- recipient list, each entry providing:
  - `recipient_id`
  - KDF descriptor (`salt_b64`, `time_cost`, `memory_cost_kib`, `parallelism`, `derived_key_bytes`)
- `plaintext_chunk_bytes`
   - recipient `ml_kem1024_p384` public key originally derived using the KDF descriptor parameters
- optional metadata

Steps:

1. Generate a random FEK (32 bytes).
2. For each recipient entry:
    - run ML-KEM encapsulation with fresh randomness against that recipient public key
    - store the resulting KEM ciphertext in `recipient.kem.ciphertext_b64`
    - generate a random FEK-wrap nonce (`12` bytes) into `recipient.fek.nonce_b64`
    - wrap FEK as `recipient.fek.encrypted_fek_b64 = chacha20poly1305(kem.shared_secret, recipient.fek.nonce_b64).encrypt(FEK)`
3. Build and write wire prefix + header JSON.
4. Write `header_extension_length` and optional `header_extension` bytes. When no extension data is present, `header_extension_length = 0` and no `header_extension` bytes follow.
5. Stream plaintext in chunks of up to `plaintext_chunk_bytes` plaintext bytes.
6. For each chunk `i`, build `P_i = plaintext_chunk`, derive `nonce_i` with the EOF marker set only on the final chunk, encrypt with `chacha20poly1305` using empty AAD, and write `ciphertext || 16-byte tag`.

## 8. Decrypt Flow

Inputs:

- ciphertext input stream
- plaintext output stream
- one provided recipient password

Steps:

1. Read and validate wire prefix.
2. Read header bytes, parse JSON, validate schema.
3. Read `header_extension_length`, then read and skip `header_extension` bytes.
4. Iterate `recipients[]` entries in order until FEK unwrap succeeds:
    - run Argon2id with `recipient.kdf` and the provided password to recover deterministic ML-KEM private seed material
    - derive the `ml_kem1024_p384` private key for that recipient entry
    - decapsulate `recipient.kem.ciphertext_b64` to recover the per-recipient shared secret
    - unwrap FEK from `recipient.fek.encrypted_fek_b64` using `recipient.fek.nonce_b64` and empty AAD
5. If no recipient entry yields a valid FEK, reject.
6. Iterate chunk index `i` from `0` upward until physical EOF.
7. For each non-final chunk, read fixed encrypted length `plaintext_chunk_bytes + 16`, derive `nonce_i` with the EOF marker cleared, decrypt with `chacha20poly1305` using empty AAD, and write plaintext chunk data.
8. Treat the EOF remainder as the final chunk candidate, decrypt it with the EOF marker set, and require successful authentication.
9. Close output stream.

## 9. Security Considerations

### 9.1 Tamper Verification

Authenticated encryption with `chacha20poly1305` protects:

- chunk reordering or injection (chunk index and EOF marker are part of the authenticated nonce)
- chunk payload tampering (authenticated ciphertext)

The EOF marker in the nonce additionally protects EOF integrity (end-of-file truncation is detected).

Payload authentication does not cover descriptive header metadata. Changes to descriptive header fields may leave payload authentication unaffected, although changes to decryption-relevant fields will typically still cause decryption failure because the wrong inputs are used.

The header stores only decoding metadata and must never contain plaintext secrets such as recipient passwords or an unencrypted FEK.

### 9.2 Password Recommendation

Recommended baseline per recipient password: Diceware passphrase with at least 6 words.