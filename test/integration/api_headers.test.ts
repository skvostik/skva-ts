import { describe, expect, it } from "vitest";

import {
  skvaEncryptBytes,
  skvaReadHeaderBytes,
  skvaReadHeaderStream,
} from "../../src/api.js";
import { skvaGenerateRecipient } from "../../src/recipient.js";
import { bytesToReadableStream } from "../../src/stream/adapters.js";

const RECIPIENT_TEST_TIMEOUT_MS = 30_000;

const CHEAP_KDF = {
  time_cost: 1,
  memory_cost_kib: 256,
  parallelism: 1,
  derived_key_bytes: 32,
} as const;

const FIXED_PLAINTEXT = new TextEncoder().encode(
  "API integration payload: end-to-end encrypt/decrypt and header reads.",
);

describe("integration/api/headers", { timeout: 30_000 }, () => {
  it("skvaReadHeaderBytes returns same header as skvaEncryptBytes result", async () => {
    const recipient = await skvaGenerateRecipient(
      "api-pass-2",
      "api-r2",
      CHEAP_KDF,
    );

    const encrypted = await skvaEncryptBytes(FIXED_PLAINTEXT, {
      recipients: [recipient],
      plaintext_chunk_bytes: 13,
      meta: { tag: "bytes-header" },
      header_extension_bytes: new Uint8Array([9, 8]),
    });

    const header_only = await skvaReadHeaderBytes(encrypted.bytes);

    expect(header_only.json_header).toEqual(encrypted.json_header);
    expect(header_only.binary_header).toEqual(encrypted.binary_header);
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("skvaReadHeaderStream returns same header as skvaReadHeaderBytes", async () => {
    const recipient = await skvaGenerateRecipient(
      "api-pass-3",
      "api-r3",
      CHEAP_KDF,
    );

    const encrypted = await skvaEncryptBytes(FIXED_PLAINTEXT, {
      recipients: [recipient],
      plaintext_chunk_bytes: 7,
      meta: { tag: "stream-header" },
      header_extension_bytes: new Uint8Array([5, 6, 7]),
    });

    const from_bytes = await skvaReadHeaderBytes(encrypted.bytes);
    const from_stream = await skvaReadHeaderStream(
      bytesToReadableStream(encrypted.bytes),
    );

    expect(from_stream.json_header).toEqual(from_bytes.json_header);
    expect(from_stream.binary_header).toEqual(from_bytes.binary_header);
  }, RECIPIENT_TEST_TIMEOUT_MS);
});
