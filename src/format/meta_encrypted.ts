import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import {
  SKVA_CIPHER_NAME,
  SKVA_META_ENCRYPTED_HKDF_INFO,
  SKVA_META_ENCRYPTED_KEY_BYTES,
  SKVA_META_ENCRYPTED_KEY_DERIVATION_NAME,
  SKVA_META_ENCRYPTED_PADDING_BYTES,
  SKVA_NONCE_BYTES,
  SKVA_TAG_BYTES,
} from "../constants.js";
import { SkvaError, skvaAssert } from "../errors.js";
import type { SkvaMetaEncryptedHeader } from "../types.js";
import { decodeBase64, encodeBase64 } from "../utils/base64.js";
import { isRecord } from "./json_header.js";

/**
 * Encrypts a metadata object into a `meta_encrypted` header object.
 * The JSON plaintext is padded with trailing spaces to a multiple of 64 bytes to hide its exact length.
 * Must be called at most once per FEK, because the nonce is fixed to zero.
 */
export function encryptMetaEncrypted(
  meta: Record<string, unknown>,
  fek: Uint8Array,
): SkvaMetaEncryptedHeader {
  skvaAssert(
    isRecord(meta),
    "ERR_INVALID_ARGUMENT",
    "meta_encrypted must be an object.",
  );

  let json: string;
  try {
    json = JSON.stringify(meta);
  } catch (error) {
    throw new SkvaError(
      "ERR_INVALID_ARGUMENT",
      "meta_encrypted must be JSON-serializable.",
      { cause: error },
    );
  }

  const plaintext = padWithSpaces(new TextEncoder().encode(json));
  const key = deriveMetaEncryptedKey(fek);
  try {
    const ciphertext = chacha20poly1305(key, zeroNonce()).encrypt(plaintext);
    return {
      algorithm: SKVA_CIPHER_NAME,
      key_derivation: SKVA_META_ENCRYPTED_KEY_DERIVATION_NAME,
      ciphertext_b64: encodeBase64(ciphertext),
    };
  } finally {
    key.fill(0); // Clear derived key from memory
    plaintext.fill(0);
  }
}

/**
 * Decrypts a `meta_encrypted` header object with the FEK and returns the metadata object.
 * Throws when the object is malformed, fails authentication, or does not decrypt to a JSON object.
 */
export function decryptMetaEncrypted(
  meta_encrypted: unknown,
  fek: Uint8Array,
): Record<string, unknown> {
  skvaAssert(
    isRecord(meta_encrypted),
    "ERR_HEADER_SCHEMA_INVALID",
    "meta_encrypted must be an object.",
  );
  skvaAssert(
    meta_encrypted.algorithm === SKVA_CIPHER_NAME,
    "ERR_HEADER_SCHEMA_INVALID",
    "meta_encrypted.algorithm must be 'chacha20poly1305'.",
  );
  skvaAssert(
    meta_encrypted.key_derivation === SKVA_META_ENCRYPTED_KEY_DERIVATION_NAME,
    "ERR_HEADER_SCHEMA_INVALID",
    "meta_encrypted.key_derivation must be 'hkdf_sha256'.",
  );
  skvaAssert(
    typeof meta_encrypted.ciphertext_b64 === "string",
    "ERR_HEADER_SCHEMA_INVALID",
    "meta_encrypted.ciphertext_b64 must be a string.",
  );
  const ciphertext = decodeBase64(
    meta_encrypted.ciphertext_b64,
    "meta_encrypted.ciphertext_b64",
  );
  skvaAssert(
    ciphertext.length > SKVA_TAG_BYTES,
    "ERR_HEADER_SCHEMA_INVALID",
    "meta_encrypted.ciphertext_b64 must contain ciphertext and tag.",
  );

  const key = deriveMetaEncryptedKey(fek);
  let plaintext: Uint8Array;
  try {
    plaintext = chacha20poly1305(key, zeroNonce()).decrypt(ciphertext);
  } catch (error) {
    throw new SkvaError(
      "ERR_AEAD_AUTH_FAILED",
      "meta_encrypted authentication failed.",
      { cause: error },
    );
  } finally {
    key.fill(0); // Clear derived key from memory
  }

  let value: unknown;
  try {
    value = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(plaintext),
    );
  } catch (error) {
    throw new SkvaError(
      "ERR_HEADER_JSON_INVALID",
      "meta_encrypted plaintext is not valid UTF-8 JSON.",
      { cause: error },
    );
  }
  skvaAssert(
    isRecord(value),
    "ERR_HEADER_JSON_INVALID",
    "meta_encrypted plaintext must be a JSON object.",
  );
  return value;
}

function deriveMetaEncryptedKey(fek: Uint8Array): Uint8Array {
  return hkdf(
    sha256,
    fek,
    undefined,
    new TextEncoder().encode(SKVA_META_ENCRYPTED_HKDF_INFO),
    SKVA_META_ENCRYPTED_KEY_BYTES,
  );
}

function zeroNonce(): Uint8Array {
  return new Uint8Array(SKVA_NONCE_BYTES);
}

// Trailing spaces are JSON whitespace, so the padded plaintext still parses as-is.
function padWithSpaces(bytes: Uint8Array): Uint8Array {
  const padded_length =
    Math.ceil(bytes.length / SKVA_META_ENCRYPTED_PADDING_BYTES) *
    SKVA_META_ENCRYPTED_PADDING_BYTES;
  const padded = new Uint8Array(padded_length).fill(0x20);
  padded.set(bytes);
  bytes.fill(0);
  return padded;
}
