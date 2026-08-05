import { describe, expect, it } from "vitest";

import {
  decryptPayloadChunksStream,
  encryptPayloadChunksStream,
} from "../../src/format/chunk.js";
import { createByteReader } from "../../src/stream/byte_reader.js";
import {
  bytesToReadableStream,
  createBufferingWritable,
} from "../../src/stream/adapters.js";

const FIXED_FEK = new Uint8Array([
  101, 23, 88, 4, 199, 42, 17, 230, 61, 12, 149, 73, 8, 254, 99, 140, 5, 176,
  33, 222, 67, 91, 118, 44, 210, 13, 87, 166, 39, 121, 52, 201,
]);

const FIXED_PLAINTEXT = new TextEncoder().encode(
  "Integration roundtrip payload: chunk stream encrypt/decrypt with progress check.",
);

async function encryptWithChunkSize(
  plaintext: Uint8Array,
  fek: Uint8Array,
  plaintext_chunk_bytes: number,
  on_progress?: (processed_bytes: number) => void,
): Promise<Uint8Array> {
  const reader = createByteReader(bytesToReadableStream(plaintext).getReader());
  const { writable, get_bytes } = createBufferingWritable();
  const writer = writable.getWriter();

  try {
    await encryptPayloadChunksStream(
      reader,
      writer,
      fek,
      plaintext_chunk_bytes,
      on_progress,
    );
    await writer.close();
    return get_bytes();
  } finally {
    reader.releaseLock();
    writer.releaseLock();
  }
}

async function decryptWithChunkSize(
  ciphertext: Uint8Array,
  fek: Uint8Array,
  plaintext_chunk_bytes: number,
  on_progress?: (processed_bytes: number) => void,
): Promise<Uint8Array> {
  const reader = createByteReader(
    bytesToReadableStream(ciphertext).getReader(),
  );
  const { writable, get_bytes } = createBufferingWritable();
  const writer = writable.getWriter();

  try {
    await decryptPayloadChunksStream(
      reader,
      writer,
      fek,
      plaintext_chunk_bytes,
      on_progress,
    );
    await writer.close();
    return get_bytes();
  } finally {
    reader.releaseLock();
    writer.releaseLock();
  }
}

describe("integration/chunk_stream_roundtrip", () => {
  for (const chunk_bytes of [1, 11, 64] as const) {
    it(`decryptPayloadChunksStream(encryptPayloadChunksStream()) roundtrips for chunk_bytes=${chunk_bytes}`, async () => {
      const encrypted = await encryptWithChunkSize(
        FIXED_PLAINTEXT,
        FIXED_FEK,
        chunk_bytes,
      );

      const decrypted = await decryptWithChunkSize(
        encrypted,
        FIXED_FEK,
        chunk_bytes,
      );

      expect(decrypted).toEqual(FIXED_PLAINTEXT);
    });
  }

  it("onProgress receives expected values for chunk_bytes=11", async () => {
    const encrypt_progress: number[] = [];
    const decrypt_progress: number[] = [];

    const encrypted = await encryptWithChunkSize(
      FIXED_PLAINTEXT,
      FIXED_FEK,
      11,
      (processed_bytes) => encrypt_progress.push(processed_bytes),
    );

    const decrypted = await decryptWithChunkSize(
      encrypted,
      FIXED_FEK,
      11,
      (processed_bytes) => decrypt_progress.push(processed_bytes),
    );

    expect(decrypted).toEqual(FIXED_PLAINTEXT);
    expect(encrypt_progress).toEqual([11, 22, 33, 44, 55, 66, 77, 80]);
    expect(decrypt_progress).toEqual([27, 54, 81, 108, 135, 162, 189, 208]);
  });
});
