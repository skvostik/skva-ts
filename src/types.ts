/**
 * Argon2id KDF parameters carried in the SKVA header and used for deterministic recipient key recovery.
 */
export interface SkvaKdfHeader {
  algorithm: "argon2id";
  salt_b64: string;
  time_cost: number;
  memory_cost_kib: number;
  parallelism: number;
  derived_key_bytes: number;
}

/**
 * KEM metadata describing the encapsulated shared secret used to wrap the FEK for a recipient.
 */
export interface SkvaKemHeader {
  algorithm: "ml_kem1024_p384";
  ciphertext_b64: string;
  public_key_b64?: string;
  public_key_sha256_b64?: string;
}

/**
 * FEK wrapping metadata for a recipient entry.
 */
export interface SkvaFekHeader {
  algorithm: "chacha20poly1305";
  nonce_b64: string;
  encrypted_fek_b64: string;
}

/**
 * Parsed recipient entry that includes the wrapped FEK and the KEM/KDF metadata needed to recover it.
 */
export interface SkvaRecipientFekWrapper {
  recipient_id: string;
  kdf: SkvaKdfHeader;
  kem: SkvaKemHeader;
  fek: SkvaFekHeader;
}

/**
 * Payload metadata stored in the JSON header for the encrypted chunk stream.
 */
export interface SkvaPayloadHeader {
  algorithm: "chacha20poly1305";
  plaintext_chunk_bytes: number;
}

/**
 * Parsed SKVA header object as defined by the SKVA format specification.
 */
export interface SkvaJsonHeader {
  format: "skva";
  version: 1;
  recovery_note?: unknown;
  recipients: SkvaRecipientFekWrapper[];
  payload: SkvaPayloadHeader;
  meta?: Record<string, unknown>;
}

/**
 * Binary header information parsed from the SKVA stream prefix.
 */
export interface SkvaBinaryHeader {
  magic: "SKVA";
  version: number;
  header_length: number;
  header_bytes: Uint8Array;
  header_extension_length: number;
  header_extension_bytes: Uint8Array;
}

/**
 * A recipient descriptor used as input to encryption.
 */
export interface SkvaRecipient {
  recipient_id?: string;
  public_key: Uint8Array;
  kdf: SkvaKdfHeader;
}

/**
 * Callback invoked with cumulative processed byte counts while streaming encryption or decryption progresses.
 */
export type SkvaProgressCallback = (processedBytes: number) => void;

/**
 * Input for streaming SKVA encryption.
 */
export interface SkvaEncryptOptions {
  recipients: SkvaRecipient[];
  meta?: Record<string, unknown>;
  plaintext_chunk_bytes?: number;
  header_extension_bytes?: Uint8Array;
  on_progress?: SkvaProgressCallback;
}

/**
 * Input for streaming SKVA decryption.
 */
export interface SkvaDecryptOptions {
  password: string;
  recipient_id?: string;
  on_progress?: SkvaProgressCallback;
}
