import { beforeAll, describe, expect, it } from "vitest";

import { skvaDecryptBytes, skvaEncryptBytes } from "../../src/api.js";
import { skvaOpenDecryptStream } from "../../src/decrypt.js";
import { SkvaError, type SkvaErrorCode } from "../../src/errors.js";
import { skvaGenerateRecipient } from "../../src/recipient.js";
import {
  bytesToReadableStream,
  createBufferingWritable,
} from "../../src/stream/adapters.js";

const CHEAP_KDF = {
  time_cost: 1,
  memory_cost_kib: 256,
  parallelism: 1,
  derived_key_bytes: 32,
} as const;

const PASSWORD = "api-pass-open";
const FIXED_PLAINTEXT = new TextEncoder().encode(
  "API integration payload: open the header first, then decrypt the payload.",
);
const META = { created_at: "2026-10-29T00:00:00Z" };
const META_ENCRYPTED = { original_filename: "restore-me.bin" };
// Larger than the whole file, so the header read takes the entire payload along with it.
const WHOLE_FILE_CHUNK_BYTES = 1 << 20;

let skva_bytes: Uint8Array;
let fek: Uint8Array;

beforeAll(async () => {
  const recipient = await skvaGenerateRecipient(
    PASSWORD,
    "api-r-open",
    CHEAP_KDF,
  );
  const encrypted = await skvaEncryptBytes(FIXED_PLAINTEXT, {
    recipients: [recipient],
    plaintext_chunk_bytes: 16,
    meta: META,
    meta_encrypted: META_ENCRYPTED,
    return_fek: true,
  });
  skva_bytes = encrypted.bytes;
  fek = encrypted.fek!;
});

// Splits bytes into fixed-size chunks, like a download that delivers data in pieces.
function chunkedStream(
  bytes: Uint8Array,
  chunk_bytes: number,
): ReadableStream<Uint8Array> {
  let offset = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (offset >= bytes.length) {
        controller.close();
        return;
      }
      controller.enqueue(bytes.slice(offset, offset + chunk_bytes));
      offset += chunk_bytes;
    },
  });
}

async function expectSkvaError(
  promise: Promise<unknown>,
  code: SkvaErrorCode,
): Promise<void> {
  const error = await promise.then(
    () => {
      throw new Error("Expected promise to reject");
    },
    (error: unknown) => error,
  );
  expect(error).toBeInstanceOf(SkvaError);
  expect((error as SkvaError).code).toBe(code);
}

describe("integration/api/decrypt_stream", { timeout: 30_000 }, () => {
  it.each([
    ["one chunk", WHOLE_FILE_CHUNK_BYTES],
    ["5-byte chunks", 5],
  ])(
    "exposes meta_encrypted before the payload and decrypts the payload (%s)",
    async (_label, chunk_bytes) => {
      const input = chunkedStream(skva_bytes, chunk_bytes);
      const skva_stream = await skvaOpenDecryptStream(input, {
        password: PASSWORD,
      });
      const { writable, get_bytes } = createBufferingWritable();

      try {
        expect(skva_stream.meta).toEqual(META);
        expect(skva_stream.meta_encrypted).toEqual(META_ENCRYPTED);
        expect(skva_stream.json_header.recipients[0]!.recipient_id).toBe(
          "api-r-open",
        );
        expect(get_bytes()).toHaveLength(0);

        await skva_stream.decrypt_payload(writable);
      } finally {
        await skva_stream.close();
      }

      expect(get_bytes()).toEqual(FIXED_PLAINTEXT);
      expect(input.locked).toBe(false);
    },
  );

  it("reports progress through on_progress passed to open", async () => {
    const progress: number[] = [];
    const skva_stream = await skvaOpenDecryptStream(
      bytesToReadableStream(skva_bytes),
      { password: PASSWORD, on_progress: (bytes) => progress.push(bytes) },
    );
    await skva_stream.decrypt_payload(createBufferingWritable().writable);
    await skva_stream.close();

    expect(progress.length).toBeGreaterThan(1);
  });

  it("decrypts with a FEK instead of a password and leaves the caller's FEK intact", async () => {
    const fek_before = fek.slice();

    const skva_stream = await skvaOpenDecryptStream(
      bytesToReadableStream(skva_bytes),
      { fek },
    );
    const { writable, get_bytes } = createBufferingWritable();
    await skva_stream.decrypt_payload(writable);
    await skva_stream.close();

    expect(skva_stream.meta_encrypted).toEqual(META_ENCRYPTED);
    expect(get_bytes()).toEqual(FIXED_PLAINTEXT);

    const decrypted = await skvaDecryptBytes(skva_bytes, { fek });
    expect(decrypted.bytes).toEqual(FIXED_PLAINTEXT);
    expect(decrypted.meta_encrypted).toEqual(META_ENCRYPTED);

    expect(fek).toEqual(fek_before);
  });

  it("leaves a FEK passed as a Node.js Buffer intact", async () => {
    // Buffer.slice returns a view, so a copy made with it would zero the caller's key.
    const fek_buffer = Buffer.from(fek);

    const first = await skvaDecryptBytes(skva_bytes, { fek: fek_buffer });
    const second = await skvaDecryptBytes(skva_bytes, { fek: fek_buffer });

    expect(first.bytes).toEqual(FIXED_PLAINTEXT);
    expect(second.bytes).toEqual(FIXED_PLAINTEXT);
    expect(new Uint8Array(fek_buffer)).toEqual(fek);
  });

  it("detects a wrong FEK in meta_encrypted and on the first payload chunk", async () => {
    const skva_stream = await skvaOpenDecryptStream(
      bytesToReadableStream(skva_bytes),
      { fek: new Uint8Array(32) },
    );
    const { writable, get_bytes } = createBufferingWritable();

    expect(skva_stream.meta_encrypted_error?.code).toBe("ERR_AEAD_AUTH_FAILED");
    await expectSkvaError(
      skva_stream.decrypt_payload(writable),
      "ERR_AEAD_AUTH_FAILED",
    );
    await skva_stream.close();

    expect(get_bytes()).toHaveLength(0);
  });

  it("rejects a wrong password and releases the input", async () => {
    const input = bytesToReadableStream(skva_bytes);

    await expectSkvaError(
      skvaOpenDecryptStream(input, { password: "wrong-password" }),
      "ERR_NO_RECIPIENT_MATCH",
    );
    expect(input.locked).toBe(false);
  });

  it("rejects invalid key options with ERR_INVALID_ARGUMENT", async () => {
    // The type errors are expected too: the runtime checks are for JavaScript callers.
    const open_calls: Array<
      (input: ReadableStream<Uint8Array>) => Promise<unknown>
    > = [
      // @ts-expect-error password or fek is required
      (input) => skvaOpenDecryptStream(input, {}),
      // @ts-expect-error password and fek are exclusive
      (input) => skvaOpenDecryptStream(input, { password: PASSWORD, fek }),
      // @ts-expect-error recipient_id only applies to password
      (input) => skvaOpenDecryptStream(input, { fek, recipient_id: "api-r-open" }),
      // @ts-expect-error fek must be a Uint8Array
      (input) => skvaOpenDecryptStream(input, { fek: "not bytes" }),
      (input) => skvaOpenDecryptStream(input, { fek: new Uint8Array(16) }),
    ];

    for (const open_call of open_calls) {
      const input = bytesToReadableStream(skva_bytes);
      await expectSkvaError(open_call(input), "ERR_INVALID_ARGUMENT");
      expect(input.locked).toBe(false);
    }
  });

  it("allows decrypt_payload only once and not after close", async () => {
    const used = await skvaOpenDecryptStream(
      bytesToReadableStream(skva_bytes),
      { password: PASSWORD },
    );
    await used.decrypt_payload(createBufferingWritable().writable);
    await expectSkvaError(
      used.decrypt_payload(createBufferingWritable().writable),
      "ERR_INVALID_ARGUMENT",
    );
    await used.close();

    const closed = await skvaOpenDecryptStream(
      bytesToReadableStream(skva_bytes),
      { password: PASSWORD },
    );
    await closed.close();
    await expectSkvaError(
      closed.decrypt_payload(createBufferingWritable().writable),
      "ERR_INVALID_ARGUMENT",
    );

    // close without await must already reject a decrypt_payload that follows it.
    const closing = await skvaOpenDecryptStream(
      bytesToReadableStream(skva_bytes),
      { password: PASSWORD },
    );
    const close_promise = closing.close();
    await expectSkvaError(
      closing.decrypt_payload(createBufferingWritable().writable),
      "ERR_INVALID_ARGUMENT",
    );
    await close_promise;
  });

  it("close releases an unread input and can be called twice", async () => {
    const input = bytesToReadableStream(skva_bytes);
    const skva_stream = await skvaOpenDecryptStream(input, {
      password: PASSWORD,
    });
    expect(input.locked).toBe(true);

    await skva_stream.close();
    await skva_stream.close();

    expect(input.locked).toBe(false);
  });

  it("close waits for a running decrypt_payload", async () => {
    const skva_stream = await skvaOpenDecryptStream(
      chunkedStream(skva_bytes, 5),
      { password: PASSWORD },
    );
    const { writable, get_bytes } = createBufferingWritable();

    const payload = skva_stream.decrypt_payload(writable);
    await skva_stream.close();

    await payload;
    expect(get_bytes()).toEqual(FIXED_PLAINTEXT);
  });
});
