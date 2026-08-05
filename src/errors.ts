export type SkvaErrorCode =
  | "ERR_INVALID_ARGUMENT"
  | "ERR_MAGIC_MISMATCH"
  | "ERR_UNSUPPORTED_VERSION"
  | "ERR_HEADER_LENGTH_INVALID"
  | "ERR_HEADER_JSON_INVALID"
  | "ERR_HEADER_SCHEMA_INVALID"
  | "ERR_BASE64_INVALID"
  | "ERR_KDF_DERIVATION_FAILED"
  | "ERR_KEM_FAILED"
  | "ERR_FEK_WRAP_FAILED"
  | "ERR_FEK_UNWRAP_FAILED"
  | "ERR_NO_RECIPIENT_MATCH"
  | "ERR_CHUNK_SIZE_INVALID"
  | "ERR_CHUNK_COUNT_EXCEEDS_NONCE_CAPACITY"
  | "ERR_CHACHA_ENCRYPT_FAILED"
  | "ERR_AEAD_AUTH_FAILED"
  | "ERR_STREAM_TRUNCATED";

/**
 * Typed SKVA error used across parsing, validation, cryptographic, and stream stages.
 */
export class SkvaError extends Error {
  readonly code: SkvaErrorCode;

  constructor(code: SkvaErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "SkvaError";
    this.code = code;
  }
}

/**
 * Throws a typed SKVA error when the provided condition is falsy.
 */
export function skvaAssert(condition: unknown, code: SkvaErrorCode, message: string): asserts condition {
  if (!condition) {
    throw new SkvaError(code, message);
  }
}
