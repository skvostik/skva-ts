import {
  SKVA_CIPHER_NAME,
  SKVA_KDF_NAME,
  SKVA_KEM_NAME,
  SKVA_RECOVERY_NOTE,
  SKVA_TAG_BYTES,
} from "../constants.js";
import { SkvaError, skvaAssert } from "../errors.js";
import type { SkvaJsonHeader, SkvaRecipientFekWrapper } from "../types.js";
import { decodeBase64 } from "../utils/base64.js";

/**
 * Encodes a SKVA header object to UTF-8 JSON bytes.
 */
export function serializeSkvaJsonHeader(header: SkvaJsonHeader): Uint8Array {
  validateSkvaJsonHeader(header);
  const json = JSON.stringify(header);
  return new TextEncoder().encode(json);
}

export function parseSkvaJsonHeaderBytes(
  header_bytes: Uint8Array,
): SkvaJsonHeader {
  let raw_value: unknown;
  try {
    const json = new TextDecoder("utf-8", { fatal: true }).decode(header_bytes);
    raw_value = JSON.parse(json);
  } catch {
    throw new SkvaError(
      "ERR_HEADER_JSON_INVALID",
      "Header JSON is not valid UTF-8 JSON.",
    );
  }

  validateSkvaJsonHeader(raw_value);
  return raw_value as SkvaJsonHeader;
}

/**
 * Validates the SKVA header schema and semantic constraints.
 */
export function validateSkvaJsonHeader(
  raw_value: unknown,
): asserts raw_value is SkvaJsonHeader {
  skvaAssert(
    isRecord(raw_value),
    "ERR_HEADER_SCHEMA_INVALID",
    "Header must be a JSON object.",
  );

  skvaAssert(
    raw_value.format === "skva",
    "ERR_HEADER_SCHEMA_INVALID",
    "Header format must be 'skva'.",
  );
  skvaAssert(
    raw_value.version === 1,
    "ERR_HEADER_SCHEMA_INVALID",
    "Header version must be 1.",
  );

  skvaAssert(
    Array.isArray(raw_value.recipients) && raw_value.recipients.length > 0,
    "ERR_HEADER_SCHEMA_INVALID",
    "recipients must be a non-empty array.",
  );
  for (let i = 0; i < raw_value.recipients.length; i += 1) {
    const recipient = raw_value.recipients[i];
    skvaAssert(
      isRecord(recipient),
      "ERR_HEADER_SCHEMA_INVALID",
      `recipients[${i}] must be an object.`,
    );
    assertNonEmptyString(
      recipient.recipient_id,
      `recipients[${i}].recipient_id`,
    );

    const kdf = getRecord(recipient, "kdf");
    skvaAssert(
      kdf.algorithm === SKVA_KDF_NAME,
      "ERR_HEADER_SCHEMA_INVALID",
      `recipients[${i}].kdf.algorithm must be 'argon2id'.`,
    );
    assertPositiveInteger(kdf.time_cost, `recipients[${i}].kdf.time_cost`);
    assertPositiveInteger(
      kdf.memory_cost_kib,
      `recipients[${i}].kdf.memory_cost_kib`,
    );
    assertPositiveInteger(kdf.parallelism, `recipients[${i}].kdf.parallelism`);
    assertPositiveInteger(
      kdf.derived_key_bytes,
      `recipients[${i}].kdf.derived_key_bytes`,
    );
    assertNonEmptyString(kdf.salt_b64, `recipients[${i}].kdf.salt_b64`);
    const salt = decodeBase64(
      String(kdf.salt_b64),
      `recipients[${i}].kdf.salt_b64`,
    );
    skvaAssert(
      salt.length === 16,
      "ERR_HEADER_SCHEMA_INVALID",
      `recipients[${i}].kdf.salt_b64 must decode to 16 bytes.`,
    );

    const kem = getRecord(recipient, "kem");
    skvaAssert(
      kem.algorithm === SKVA_KEM_NAME,
      "ERR_HEADER_SCHEMA_INVALID",
      `recipients[${i}].kem.algorithm must be 'ml_kem1024_p384'.`,
    );
    assertNonEmptyString(
      kem.ciphertext_b64,
      `recipients[${i}].kem.ciphertext_b64`,
    );
    decodeBase64(
      String(kem.ciphertext_b64),
      `recipients[${i}].kem.ciphertext_b64`,
    );
    if (kem.public_key_b64 !== undefined) {
      skvaAssert(
        typeof kem.public_key_b64 === "string",
        "ERR_HEADER_SCHEMA_INVALID",
        `recipients[${i}].kem.public_key_b64 must be a string when present.`,
      );
      const key = decodeBase64(
        kem.public_key_b64,
        `recipients[${i}].kem.public_key_b64`,
      );
      skvaAssert(
        key.length > 0,
        "ERR_HEADER_SCHEMA_INVALID",
        `recipients[${i}].kem.public_key_b64 must decode to non-empty bytes.`,
      );
    }
    if (kem.public_key_sha256_b64 !== undefined) {
      skvaAssert(
        typeof kem.public_key_sha256_b64 === "string",
        "ERR_HEADER_SCHEMA_INVALID",
        `recipients[${i}].kem.public_key_sha256_b64 must be a string when present.`,
      );
      const digest = decodeBase64(
        kem.public_key_sha256_b64,
        `recipients[${i}].kem.public_key_sha256_b64`,
      );
      skvaAssert(
        digest.length === 32,
        "ERR_HEADER_SCHEMA_INVALID",
        `recipients[${i}].kem.public_key_sha256_b64 must decode to 32 bytes.`,
      );
    }

    const fek = getRecord(recipient, "fek");
    skvaAssert(
      fek.algorithm === SKVA_CIPHER_NAME,
      "ERR_HEADER_SCHEMA_INVALID",
      `recipients[${i}].fek.algorithm must be 'chacha20poly1305'.`,
    );
    assertNonEmptyString(fek.nonce_b64, `recipients[${i}].fek.nonce_b64`);
    assertNonEmptyString(
      fek.encrypted_fek_b64,
      `recipients[${i}].fek.encrypted_fek_b64`,
    );
    const wrap_nonce = decodeBase64(
      String(fek.nonce_b64),
      `recipients[${i}].fek.nonce_b64`,
    );
    skvaAssert(
      wrap_nonce.length === 12,
      "ERR_HEADER_SCHEMA_INVALID",
      `recipients[${i}].fek.nonce_b64 must decode to 12 bytes.`,
    );
    const wrapped_fek = decodeBase64(
      String(fek.encrypted_fek_b64),
      `recipients[${i}].fek.encrypted_fek_b64`,
    );
    skvaAssert(
      wrapped_fek.length > SKVA_TAG_BYTES,
      "ERR_HEADER_SCHEMA_INVALID",
      `recipients[${i}].fek.encrypted_fek_b64 must contain ciphertext and tag.`,
    );
  }

  const payload = getRecord(raw_value, "payload");
  skvaAssert(
    payload.algorithm === SKVA_CIPHER_NAME,
    "ERR_HEADER_SCHEMA_INVALID",
    "payload.algorithm must be 'chacha20poly1305'.",
  );
  assertPositiveInteger(
    payload.plaintext_chunk_bytes,
    "payload.plaintext_chunk_bytes",
  );

  if (raw_value.meta !== undefined) {
    skvaAssert(
      isRecord(raw_value.meta),
      "ERR_HEADER_SCHEMA_INVALID",
      "meta must be an object when present.",
    );
  }
}

/**
 * Builds a spec-compliant SKVA header.
 */
export function createSkvaJsonHeader(input: {
  recipients: SkvaRecipientFekWrapper[];
  plaintext_chunk_bytes: number;
  meta?: Record<string, unknown>;
}): SkvaJsonHeader {
  const header: SkvaJsonHeader = {
    format: "skva",
    version: 1,
    recovery_note: SKVA_RECOVERY_NOTE,
    recipients: input.recipients,
    payload: {
      algorithm: SKVA_CIPHER_NAME,
      plaintext_chunk_bytes: input.plaintext_chunk_bytes,
    },
    ...(input.meta ? { meta: input.meta } : {}),
  };

  validateSkvaJsonHeader(header);
  return header;
}

function assertPositiveInteger(value: unknown, field_name: string): void {
  skvaAssert(
    Number.isInteger(value) && Number(value) > 0,
    "ERR_HEADER_SCHEMA_INVALID",
    `${field_name} must be an integer > 0.`,
  );
}

function assertNonEmptyString(value: unknown, field_name: string): void {
  skvaAssert(
    typeof value === "string" && value.trim().length > 0,
    "ERR_HEADER_SCHEMA_INVALID",
    `${field_name} must be a non-empty string.`,
  );
}

function getRecord(
  source: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  const value = source[key];
  skvaAssert(
    isRecord(value),
    "ERR_HEADER_SCHEMA_INVALID",
    `${key} must be an object.`,
  );
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
