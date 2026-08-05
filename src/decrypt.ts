import { decryptPayloadChunksStream } from "./format/chunk.js";
import type {
  SkvaBinaryHeader,
  SkvaDecryptOptions,
  SkvaJsonHeader,
} from "./types.js";
import { parseSkvaBinaryHeaderStream } from "./format/binary_header.js";
import { tryUnwrapFekFromRecipients } from "./recipient.js";

/**
 * Decrypts a SKVA stream into plaintext bytes and writes the recovered payload to the provided writable stream.
 * The function returns the parsed JSON header and binary header from the input stream.
 */
export async function skvaDecryptStream(
  input: ReadableStream<Uint8Array>,
  output: WritableStream<Uint8Array>,
  options: SkvaDecryptOptions,
): Promise<{ json_header: SkvaJsonHeader; binary_header: SkvaBinaryHeader }> {
  const { json_header, binary_header, reader } =
    await parseSkvaBinaryHeaderStream(input);
  const writer = output.getWriter();

  try {
    const { fek } = await tryUnwrapFekFromRecipients(
      json_header.recipients,
      options.password,
      options.recipient_id,
    );
    try {
      await decryptPayloadChunksStream(
        reader,
        writer,
        fek,
        json_header.payload.plaintext_chunk_bytes,
        options.on_progress,
      );
    } finally {
      fek.fill(0);
    }
    await writer.close();
    return { json_header, binary_header };
  } finally {
    reader.releaseLock();
    writer.releaseLock();
  }
}
