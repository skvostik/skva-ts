import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import {
  SKVA_MAX_CHUNKS,
  SKVA_NONCE_BYTES,
  SKVA_NONCE_COUNTER_BYTES,
  SKVA_TAG_BYTES,
} from "../constants.js";
import { SkvaError, skvaAssert } from "../errors.js";
import { ByteReader } from "../stream/byte_reader.js";
import { SkvaProgressCallback } from "../types.js";

/**
 * Builds a 12-byte nonce from the chunk index and EOF marker.
 */
function buildChunkNonce(
  chunk_index: bigint,
  is_final: boolean,
): Uint8Array {
  skvaAssert(
    chunk_index >= 0n && chunk_index < SKVA_MAX_CHUNKS,
    "ERR_CHUNK_COUNT_EXCEEDS_NONCE_CAPACITY",
    "Chunk index exceeds nonce counter capacity.",
  );

  const nonce = new Uint8Array(SKVA_NONCE_BYTES);
  let current_chunk_index = chunk_index;
  for (let i = SKVA_NONCE_COUNTER_BYTES - 1; i >= 0; i -= 1) {
    nonce[i] = Number(current_chunk_index & 0xffn);
    current_chunk_index >>= 8n;
  }

  nonce[SKVA_NONCE_BYTES - 1] = is_final ? 0x01 : 0x00;
  return nonce;
}

/**
 * Encrypts one plaintext chunk using the FEK and a derived nonce.
 */
function encryptChunk(
  plaintext_chunk: Uint8Array,
  fek: Uint8Array,
  chunk_index: bigint,
  is_final: boolean,
): Uint8Array {
  const nonce = buildChunkNonce(chunk_index, is_final);
  try {
    return chacha20poly1305(fek, nonce).encrypt(plaintext_chunk);
  } catch (error) {
    /* c8 ignore next */
    throw new SkvaError(
      "ERR_CHACHA_ENCRYPT_FAILED",
      "ChaCha20-Poly1305 chunk encryption failed.",
      { cause: error },
    );
  }
}

/**
 * Decrypts one encrypted chunk using the FEK and a derived nonce.
 */
function decryptChunk(
  encrypted_chunk: Uint8Array,
  fek: Uint8Array,
  chunk_index: bigint,
  is_final: boolean,
): Uint8Array {
  const nonce = buildChunkNonce(chunk_index, is_final);
  try {
    return chacha20poly1305(fek, nonce).decrypt(encrypted_chunk);
  } catch (error) {
    throw new SkvaError(
      "ERR_AEAD_AUTH_FAILED",
      "Chunk authentication failed during decryption.",
      { cause: error },
    );
  }
}

async function readNextChunk(
  reader: ByteReader,
  plaintext_chunk_bytes: number,
): Promise<Uint8Array | null> {
  const chunk = await reader.readBytes(plaintext_chunk_bytes);
  if (!chunk || chunk.length === 0) {
    return null;
  }
  return chunk;
}

export async function encryptPayloadChunksStream(
  reader: ByteReader,
  writer: WritableStreamDefaultWriter<Uint8Array>,
  fek: Uint8Array,
  plaintext_chunk_bytes: number,
  on_progress?: SkvaProgressCallback,
): Promise<void> {
  let chunk_index = 0n;
  let processed_bytes = 0;
  let current_chunk = await readNextChunk(reader, plaintext_chunk_bytes);

  while (current_chunk !== null) {
    const next_chunk = await readNextChunk(reader, plaintext_chunk_bytes);
    const is_final = next_chunk === null;
    const encrypted_chunk = encryptChunk(
      current_chunk,
      fek,
      chunk_index,
      is_final,
    );

    await writer.write(encrypted_chunk);
    processed_bytes += current_chunk.length;
    on_progress?.(processed_bytes);

    chunk_index += 1n;
    current_chunk = next_chunk;
  }
}

export async function decryptPayloadChunksStream(
  reader: ByteReader,
  writer: WritableStreamDefaultWriter<Uint8Array>,
  fek: Uint8Array,
  plaintext_chunk_bytes: number,
  on_progress?: SkvaProgressCallback,
): Promise<void> {
  const encrypted_chunk_bytes = plaintext_chunk_bytes + SKVA_TAG_BYTES;

  let chunk_index = 0n;
  let processed_bytes = 0;
  let current_chunk = await readNextChunk(reader, encrypted_chunk_bytes);

  while (current_chunk !== null) {
    const next_chunk = await readNextChunk(reader, encrypted_chunk_bytes);
    const is_final = next_chunk === null;
    const encrypted_chunk = decryptChunk(
      current_chunk,
      fek,
      chunk_index,
      is_final,
    );

    await writer.write(encrypted_chunk);
    processed_bytes += current_chunk.length;
    on_progress?.(processed_bytes);

    chunk_index += 1n;
    current_chunk = next_chunk;
  }
}
