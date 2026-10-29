import { SKVA_FEK_BYTES } from "./constants.js";
import { skvaAssert } from "./errors.js";
import type { SkvaError } from "./errors.js";
import { decryptPayloadChunksStream } from "./format/chunk.js";
import { decryptMetaEncrypted } from "./format/meta_encrypted.js";
import type {
  SkvaDecryptOptions,
  SkvaDecryptStream,
  SkvaJsonHeader,
} from "./types.js";
import { parseSkvaBinaryHeaderStream } from "./format/binary_header.js";
import { tryUnwrapFekFromRecipients } from "./recipient.js";

/**
 * Reads the header of a SKVA stream, unlocks it with the password or FEK, and decrypts `meta_encrypted`,
 * without reading the payload. Throws on a wrong password or an invalid header.
 * The returned object decrypts the payload with `decrypt_payload` and must be closed with `close`.
 */
export async function skvaOpenDecryptStream(
  input: ReadableStream<Uint8Array>,
  options: SkvaDecryptOptions,
): Promise<SkvaDecryptStream> {
  const { json_header, binary_header, reader } =
    await parseSkvaBinaryHeaderStream(input);

  let fek: Uint8Array;
  try {
    fek = await resolveFek(json_header, options);
  } catch (error) {
    reader.releaseLock();
    throw error;
  }
  let payload_promise: Promise<void> | undefined;
  let released = false;
  const release = (): void => {
    if (released) {
      return;
    }
    released = true;
    fek.fill(0); // Clear FEK from memory
    reader.releaseLock();
  };

  // The reader still holds payload bytes that were read together with the header, so the payload must be
  // decrypted through it rather than from the input stream.
  const decryptPayload = async (
    output: WritableStream<Uint8Array>,
  ): Promise<void> => {
    try {
      const writer = output.getWriter();
      try {
        await decryptPayloadChunksStream(
          reader,
          writer,
          fek,
          json_header.payload.plaintext_chunk_bytes,
          options.on_progress,
        );
        await writer.close();
      } finally {
        writer.releaseLock();
      }
    } finally {
      release();
    }
  };

  return {
    json_header,
    binary_header,
    // meta is copied from the header for convenience, next to the decrypted meta_encrypted.
    ...(json_header.meta !== undefined ? { meta: json_header.meta } : {}),
    ...readMetaEncrypted(json_header, fek),
    async decrypt_payload(output) {
      skvaAssert(
        payload_promise === undefined && !released,
        "ERR_INVALID_ARGUMENT",
        "decrypt_payload can be called only once and not after close.",
      );
      payload_promise = decryptPayload(output);
      return payload_promise;
    },
    async close() {
      // Without a running payload, release synchronously, so a decrypt_payload call right after close is rejected.
      if (payload_promise !== undefined) {
        await payload_promise.catch(() => {
          // The caller of decrypt_payload receives this error.
        });
      }
      release();
    },
  };
}

async function resolveFek(
  json_header: SkvaJsonHeader,
  options: SkvaDecryptOptions,
): Promise<Uint8Array> {
  if (options.fek === undefined) {
    skvaAssert(
      typeof options.password === "string",
      "ERR_INVALID_ARGUMENT",
      "Either password or fek is required.",
    );
    const { fek } = await tryUnwrapFekFromRecipients(
      json_header.recipients,
      options.password,
      options.recipient_id,
    );
    return fek;
  }

  skvaAssert(
    options.password === undefined && options.recipient_id === undefined,
    "ERR_INVALID_ARGUMENT",
    "fek cannot be combined with password or recipient_id.",
  );
  skvaAssert(
    options.fek instanceof Uint8Array && options.fek.length === SKVA_FEK_BYTES,
    "ERR_INVALID_ARGUMENT",
    `fek must be a ${SKVA_FEK_BYTES}-byte Uint8Array.`,
  );
  // Copy, so zeroing the FEK after decryption never touches the caller's key. Buffer.slice would return a view.
  return new Uint8Array(options.fek);
}

// meta_encrypted is optional, so a failure to decrypt it is reported instead of stopping payload decryption.
function readMetaEncrypted(
  json_header: SkvaJsonHeader,
  fek: Uint8Array,
): Pick<SkvaDecryptStream, "meta_encrypted" | "meta_encrypted_error"> {
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
