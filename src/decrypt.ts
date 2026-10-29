import { decryptPayloadChunksStream } from "./format/chunk.js";
import { decryptMetaEncrypted } from "./format/meta_encrypted.js";
import type { SkvaError } from "./errors.js";
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
 * When the header contains `meta_encrypted`, it also returns the decrypted metadata object, or
 * `meta_encrypted_error` if it could not be decrypted; the payload is decrypted either way.
 */
export async function skvaDecryptStream(
  input: ReadableStream<Uint8Array>,
  output: WritableStream<Uint8Array>,
  options: SkvaDecryptOptions,
): Promise<{
  json_header: SkvaJsonHeader;
  binary_header: SkvaBinaryHeader;
  meta_encrypted?: Record<string, unknown>;
  meta_encrypted_error?: SkvaError;
}> {
  const { json_header, binary_header, reader } =
    await parseSkvaBinaryHeaderStream(input);
  const writer = output.getWriter();

  try {
    const { fek } = await tryUnwrapFekFromRecipients(
      json_header.recipients,
      options.password,
      options.recipient_id,
    );
    let meta_encrypted_result: MetaEncryptedResult;
    try {
      meta_encrypted_result = readMetaEncrypted(json_header, fek);
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
    return { json_header, binary_header, ...meta_encrypted_result };
  } finally {
    reader.releaseLock();
    writer.releaseLock();
  }
}

type MetaEncryptedResult = {
  meta_encrypted?: Record<string, unknown>;
  meta_encrypted_error?: SkvaError;
};

// meta_encrypted is optional, so a failure to decrypt it is reported instead of stopping payload decryption.
function readMetaEncrypted(
  json_header: SkvaJsonHeader,
  fek: Uint8Array,
): MetaEncryptedResult {
  if (json_header.meta_encrypted === undefined) {
    return {};
  }
  try {
    return {
      meta_encrypted: decryptMetaEncrypted(json_header.meta_encrypted, fek),
    };
  } catch (error) {
    return { meta_encrypted_error: error as SkvaError };
  }
}
