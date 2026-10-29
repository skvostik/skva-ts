import type {
  SkvaBinaryHeader,
  SkvaDecryptOptions,
  SkvaEncryptOptions,
  SkvaJsonHeader,
} from "./types.js";
import type { SkvaError } from "./errors.js";
import {
  createBufferingWritable,
  bytesToReadableStream,
} from "./stream/adapters.js";
import { skvaEncryptStream } from "./encrypt.js";
import { skvaDecryptStream } from "./decrypt.js";
import { parseSkvaBinaryHeaderStream } from "./format/binary_header.js";

/**
 * Encrypts plaintext bytes into a complete SKVA byte sequence and returns the serialized bytes plus the parsed headers
 * and, when `options.return_fek` is true, a copy of the generated FEK.
 */
export async function skvaEncryptBytes(
  plaintext: Uint8Array,
  options: SkvaEncryptOptions,
): Promise<{
  bytes: Uint8Array;
  json_header: SkvaJsonHeader;
  binary_header: SkvaBinaryHeader;
  fek?: Uint8Array;
}> {
  const { writable, get_bytes } = createBufferingWritable();
  const { json_header, binary_header, fek } = await skvaEncryptStream(
    bytesToReadableStream(plaintext),
    writable,
    options,
  );

  return {
    bytes: get_bytes(),
    json_header,
    binary_header,
    ...(fek ? { fek } : {}),
  };
}

/**
 * Decrypts an in-memory SKVA byte sequence back to plaintext bytes and returns the recovered payload plus the parsed headers
 * and, when present, the decrypted `meta_encrypted` object or `meta_encrypted_error`.
 */
export async function skvaDecryptBytes(
  skva_bytes: Uint8Array,
  options: SkvaDecryptOptions,
): Promise<{
  bytes: Uint8Array;
  json_header: SkvaJsonHeader;
  binary_header: SkvaBinaryHeader;
  meta_encrypted?: Record<string, unknown>;
  meta_encrypted_error?: SkvaError;
}> {
  const { writable, get_bytes } = createBufferingWritable();
  const result = await skvaDecryptStream(
    bytesToReadableStream(skva_bytes),
    writable,
    options,
  );
  return { bytes: get_bytes(), ...result };
}

/**
 * Parses the SKVA binary header and JSON metadata from a stream without decrypting the payload.
 */
export async function skvaReadHeaderStream(
  stream: ReadableStream<Uint8Array>,
): Promise<{ json_header: SkvaJsonHeader; binary_header: SkvaBinaryHeader }> {
  const { json_header, binary_header, reader } =
    await parseSkvaBinaryHeaderStream(stream);
  reader.releaseLock();
  return { json_header, binary_header };
}

/**
 * Parses the SKVA binary header and JSON metadata from in-memory bytes without decrypting the payload.
 */
export async function skvaReadHeaderBytes(
  skva_bytes: Uint8Array,
): Promise<{ json_header: SkvaJsonHeader; binary_header: SkvaBinaryHeader }> {
  return skvaReadHeaderStream(bytesToReadableStream(skva_bytes));
}
