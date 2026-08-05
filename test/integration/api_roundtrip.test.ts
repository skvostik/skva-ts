import { describe, expect, it } from "vitest";

import {
  SKVA_DEFAULT_PLAINTEXT_CHUNK_SIZE_BYTES,
  SKVA_HEADER_PREFIX_BYTES,
} from "../../src/constants.js";
import { skvaDecryptBytes, skvaEncryptBytes } from "../../src/api.js";
import { skvaGenerateRecipient } from "../../src/recipient.js";

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

describe("integration/api/roundtrip", { timeout: 30_000 }, () => {
  it("skvaEncryptBytes + skvaDecryptBytes support empty payload", async () => {
    const recipient = await skvaGenerateRecipient(
      "api-pass-empty",
      "api-r-empty",
      CHEAP_KDF,
    );

    const encrypt_progress: number[] = [];
    const decrypt_progress: number[] = [];

    const encrypted = await skvaEncryptBytes(new Uint8Array(0), {
      recipients: [recipient],
      plaintext_chunk_bytes: 11,
      on_progress: (processed_bytes) => encrypt_progress.push(processed_bytes),
    });

    const decrypted = await skvaDecryptBytes(encrypted.bytes, {
      password: "api-pass-empty",
      recipient_id: "api-r-empty",
      on_progress: (processed_bytes) => decrypt_progress.push(processed_bytes),
    });

    expect(decrypted.bytes).toEqual(new Uint8Array(0));
    expect(encrypt_progress).toEqual([]);
    expect(decrypt_progress).toEqual([]);
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("skvaEncryptBytes uses default plaintext_chunk_bytes when omitted", async () => {
    const recipient = await skvaGenerateRecipient(
      "api-pass-default-chunk",
      "api-r-default-chunk",
      CHEAP_KDF,
    );

    const encrypted = await skvaEncryptBytes(FIXED_PLAINTEXT, {
      recipients: [recipient],
    });

    expect(encrypted.json_header.payload.plaintext_chunk_bytes).toBe(
      SKVA_DEFAULT_PLAINTEXT_CHUNK_SIZE_BYTES,
    );
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("skvaEncryptBytes + skvaDecryptBytes roundtrip with callbacks", async () => {
    const recipient = await skvaGenerateRecipient(
      "api-pass-1",
      "api-r1",
      CHEAP_KDF,
    );

    const encrypt_progress: number[] = [];
    const decrypt_progress: number[] = [];

    const encrypted = await skvaEncryptBytes(FIXED_PLAINTEXT, {
      recipients: [recipient],
      plaintext_chunk_bytes: 11,
      meta: { source: "api-integration" },
      header_extension_bytes: new Uint8Array([1, 2, 3, 4]),
      on_progress: (processed_bytes) => encrypt_progress.push(processed_bytes),
    });

    const decrypted = await skvaDecryptBytes(encrypted.bytes, {
      password: "api-pass-1",
      recipient_id: "api-r1",
      on_progress: (processed_bytes) => decrypt_progress.push(processed_bytes),
    });

    expect(decrypted.bytes).toEqual(FIXED_PLAINTEXT);

    expect(encrypt_progress.length).toBeGreaterThan(0);
    expect(encrypt_progress[encrypt_progress.length - 1]).toBe(
      FIXED_PLAINTEXT.length,
    );

    expect(decrypt_progress.length).toBeGreaterThan(0);
    expect(decrypt_progress[decrypt_progress.length - 1]).toBe(
      encrypted.bytes.length -
        encrypted.binary_header.header_length -
        SKVA_HEADER_PREFIX_BYTES -
        4 -
        encrypted.binary_header.header_extension_length,
    );

    expect(encrypted.json_header.payload.plaintext_chunk_bytes).toBe(11);
    expect(encrypted.binary_header.header_extension_bytes).toEqual(
      new Uint8Array([1, 2, 3, 4]),
    );
    expect(decrypted.json_header).toEqual(encrypted.json_header);
  }, RECIPIENT_TEST_TIMEOUT_MS);
});
