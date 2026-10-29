import {
  SKVA_CHACHA20POLY1305_MAX_PLAINTEXT_BYTES,
  SKVA_DEFAULT_PLAINTEXT_CHUNK_SIZE_BYTES,
  SKVA_FEK_BYTES,
} from "./constants.js";
import { skvaAssert } from "./errors.js";
import { encryptPayloadChunksStream } from "./format/chunk.js";
import { encryptMetaEncrypted } from "./format/meta_encrypted.js";
import {
  createSkvaJsonHeader,
  serializeSkvaJsonHeader,
} from "./format/json_header.js";
import {
  buildSkvaBinaryHeader,
  serializeSkvaBinaryHeaderBytes,
} from "./format/binary_header.js";
import { createByteReader } from "./stream/byte_reader.js";
import type {
  SkvaEncryptOptions,
  SkvaBinaryHeader,
  SkvaJsonHeader,
} from "./types.js";
import { wrapFekForRecipient } from "./recipient.js";

/**
 * Encrypts a plaintext stream into SKVA wire format and writes the result to the provided writable stream.
 * The function returns the parsed JSON header and binary header that were emitted with the payload,
 * When `options.return_fek` is true, it also returns a copy of the generated FEK so callers can wrap it in their
 * own envelope (e.g. for key escrow). The returned FEK grants full access to the payload; callers should zero it
 * with `fek.fill(0)` when done.
 */
export async function skvaEncryptStream(
  input: ReadableStream<Uint8Array>,
  output: WritableStream<Uint8Array>,
  options: SkvaEncryptOptions,
): Promise<{
  json_header: SkvaJsonHeader;
  binary_header: SkvaBinaryHeader;
  fek?: Uint8Array;
}> {
  const plaintext_chunk_bytes =
    options.plaintext_chunk_bytes ?? SKVA_DEFAULT_PLAINTEXT_CHUNK_SIZE_BYTES;
  const header_extension_bytes =
    options.header_extension_bytes ?? new Uint8Array();

  skvaAssert(
    Number.isInteger(plaintext_chunk_bytes) && plaintext_chunk_bytes > 0,
    "ERR_CHUNK_SIZE_INVALID",
    "plaintext_chunk_bytes must be an integer > 0.",
  );
  skvaAssert(
    plaintext_chunk_bytes <= SKVA_CHACHA20POLY1305_MAX_PLAINTEXT_BYTES,
    "ERR_CHUNK_SIZE_INVALID",
    `plaintext_chunk_bytes must be <= ${SKVA_CHACHA20POLY1305_MAX_PLAINTEXT_BYTES}.`,
  );
  skvaAssert(
    options.recipients.length > 0,
    "ERR_HEADER_SCHEMA_INVALID",
    "At least one recipient is required.",
  );

  const fek = crypto.getRandomValues(new Uint8Array(SKVA_FEK_BYTES));
  const recipients = options.recipients.map((recipient_input) =>
    wrapFekForRecipient(recipient_input, fek),
  );

  const meta_encrypted =
    options.meta_encrypted !== undefined
      ? encryptMetaEncrypted(options.meta_encrypted, fek)
      : undefined;

  const json_header = createSkvaJsonHeader({
    recipients,
    plaintext_chunk_bytes: plaintext_chunk_bytes,
    meta: options.meta,
    meta_encrypted,
  });
  const json_header_bytes = serializeSkvaJsonHeader(json_header);

  const binary_header = buildSkvaBinaryHeader(
    json_header_bytes,
    header_extension_bytes,
  );
  const binary_header_bytes = serializeSkvaBinaryHeaderBytes(binary_header);

  const reader = createByteReader(input.getReader());
  const writer = output.getWriter();

  try {
    await writer.write(binary_header_bytes);
    await encryptPayloadChunksStream(
      reader,
      writer,
      fek,
      plaintext_chunk_bytes,
      options.on_progress,
    );

    await writer.close();
    // Return a copy because the original FEK is zeroed in the finally block.
    return {
      json_header,
      binary_header,
      ...(options.return_fek ? { fek: fek.slice() } : {}),
    };
  } finally {
    fek.fill(0); // Clear FEK from memory
    reader.releaseLock();
    writer.releaseLock();
  }
}
