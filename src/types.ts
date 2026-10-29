import type { SkvaError } from "./errors.js";

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
 * Encrypted metadata stored in the JSON header, decryptable with a key derived from the FEK.
 */
export interface SkvaMetaEncryptedHeader {
  algorithm: "chacha20poly1305";
  key_derivation: "hkdf_sha256";
  ciphertext_b64: string;
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
  /**
   * Left unset when parsing a header whose `meta` is not an object.
   */
  meta?: Record<string, unknown>;
  /**
   * Left unset when parsing a header whose `meta_encrypted` is malformed; decryption reports the reason as
   * `meta_encrypted_error`.
   */
  meta_encrypted?: SkvaMetaEncryptedHeader;
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
  /**
   * Metadata object encrypted into the header's `meta_encrypted` field, readable only by recipients.
   */
  meta_encrypted?: Record<string, unknown>;
  plaintext_chunk_bytes?: number;
  header_extension_bytes?: Uint8Array;
  /**
   * When true, the encrypt result includes a copy of the generated FEK that the caller must zero after use.
   * Defaults to false.
   */
  return_fek?: boolean;
  on_progress?: SkvaProgressCallback;
}

/**
 * Input for SKVA decryption: either a recipient password, optionally limited to one `recipient_id`, or the FEK itself.
 */
export type SkvaDecryptOptions = {
  on_progress?: SkvaProgressCallback;
} & (
  | { password: string; recipient_id?: string; fek?: never }
  | { fek: Uint8Array; password?: never; recipient_id?: never }
);

/**
 * An opened SKVA stream whose header is decrypted and whose payload is not read yet.
 */
export interface SkvaDecryptStream {
  /**
   * Parsed JSON header of the input stream.
   */
  json_header: SkvaJsonHeader;
  /**
   * Binary header (wire prefix and header extension) of the input stream.
   */
  binary_header: SkvaBinaryHeader;
  /**
   * Plaintext `meta` from the header, copied here for convenience.
   */
  meta?: Record<string, unknown>;
  /**
   * Decrypted `meta_encrypted` object, present when the header contains `meta_encrypted` and it decrypted successfully.
   */
  meta_encrypted?: Record<string, unknown>;
  /**
   * Why `meta_encrypted` could not be decrypted, present instead of `meta_encrypted` when it is malformed or fails
   * authentication. The payload can still be decrypted.
   */
  meta_encrypted_error?: SkvaError;
  /**
   * Decrypts the payload into the output stream. Can be called only once, and not after `close`.
   */
  decrypt_payload(output: WritableStream<Uint8Array>): Promise<void>;
  /**
   * Zeroes the FEK and releases the input stream. Waits for a running `decrypt_payload`. Safe to call more than once.
   */
  close(): Promise<void>;
}
