import { describe, expect, it } from "vitest";

import { SkvaError } from "../../src/errors.js";
import {
  decryptPayloadChunksStream,
  encryptPayloadChunksStream,
} from "../../src/format/chunk.js";
import { createByteReader } from "../../src/stream/byte_reader.js";
import {
  bytesToReadableStream,
  createBufferingWritable,
} from "../../src/stream/adapters.js";
import { decodeBase64, encodeBase64 } from "../../src/utils/base64.js";

const FIXED_FEK_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const FIXED_FEK_INCORRECT_B64 = "BAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const FIXED_PLAINTEXT_B64 = "U0tWREEgcmVncmVzc2lvbiB2ZWN0b3IgMjAyNg==";

const FIXED_CIPHERTEXT_CHUNK_1_B64 = "SxJRdO3KrYA1C8ywi50NfuHwDH6DtTpwtjnKTmKC5UuE21DfIsYh3Nsr8eEHno/l5ApWiamiaZ7WGh7NJQ0cteq09/uftcud6H0gSHyraX9RpGkaiT4DBdXk0XzcEaJuHcM8WqTmSdqYBCMePrm4HGoslij1JtBIdYMW6/ZaQevkd7jYegM4geB42Uu4AmxOfFEhn+mfZsVND8nkq0cMiiIgQ7afvjAmUto9EsKIdkvzh0PW+lXtR4mn6j8PjFygu3plMRAicPItb79EEbR9OPZa1TMPy6viehFicz6Xnb357I+wrYEPEhsWKDEm9boGU1zHoGRpIJRI1o0Tvs5fpb+j17uygxGtbIK7LekW9Kz1wbEPsvZC4216rj8KRHX17q7zttniJ3oyn4QLEobr80vw/PV/Fz692Y2zdbfeMQjIZrEGNLghiP7tJ4AsG0xn0/8eNpIko+x8vv77ReD+CtrNRr3zQBelyJBJG43aiQRAdcKH+7K0GvVJX79Yiftgqlbh6uHW10VSXw+pf+hb5CrevvXLoGGVIkzvvu6O9l3SowfGMYc20NuJHhbFefzUsM1zaogUbp/Tqow6aQ6UmrfVT7Y5UPwltzVttL3qaNANyYXEdF5ywWEwQeQ=";
const FIXED_CIPHERTEXT_CHUNK_11_B64 = "S/MUdezG1LR0EzmfJABAl4NxVQmHrzmMRVzIyBSoTMANXtZnWQM3K5TWUtJkjMbA5JWxQk6YNliI5q3sKTFmc5Sd56F5KsADrEsI6g==";

function expectedCiphertextB64(chunk_bytes: number): string {
  return chunk_bytes === 1
    ? FIXED_CIPHERTEXT_CHUNK_1_B64
    : FIXED_CIPHERTEXT_CHUNK_11_B64;
}

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
  const reader = createByteReader(bytesToReadableStream(ciphertext).getReader());
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


describe("regression/chunk_stream_vectors", () => {
  for (const chunk_bytes of [1, 11] as const) {
    it(`encryptPayloadChunksStream is stable and matches expected b64 for chunk_bytes=${chunk_bytes}`, async () => {
      const fek = decodeBase64(FIXED_FEK_B64, "fixed FEK");
      const plaintext = decodeBase64(FIXED_PLAINTEXT_B64, "fixed plaintext");

      const first = encodeBase64(
        await encryptWithChunkSize(plaintext, fek, chunk_bytes),
      );
      const second = encodeBase64(
        await encryptWithChunkSize(plaintext, fek, chunk_bytes),
      );

      expect(first).toBe(second);

      const expected_b64 = expectedCiphertextB64(chunk_bytes);
      expect(first).toBe(expected_b64);
      expect(second).toBe(expected_b64);
    });

    it(`decryptPayloadChunksStream is stable and matches expected plaintext for chunk_bytes=${chunk_bytes}`, async () => {
      const expected_ciphertext_b64 = expectedCiphertextB64(chunk_bytes);
      const fek = decodeBase64(FIXED_FEK_B64, "fixed FEK");
      const ciphertext = decodeBase64(expected_ciphertext_b64, `chunk ${chunk_bytes} ciphertext`);

      const first = encodeBase64(
        await decryptWithChunkSize(ciphertext, fek, chunk_bytes),
      );
      const second = encodeBase64(
        await decryptWithChunkSize(ciphertext, fek, chunk_bytes),
      );

      expect(first).toBe(second);
      expect(first).toBe(FIXED_PLAINTEXT_B64);
      expect(second).toBe(FIXED_PLAINTEXT_B64);
    });

    it(`decryptPayloadChunksStream fails with incorrect FEK for chunk_bytes=${chunk_bytes}`, async () => {
      const expected_ciphertext_b64 = expectedCiphertextB64(chunk_bytes);
      const incorrect_fek = decodeBase64(
        FIXED_FEK_INCORRECT_B64,
        "incorrect fixed FEK",
      );
      const ciphertext = decodeBase64(
        expected_ciphertext_b64,
        `chunk ${chunk_bytes} ciphertext`,
      );

      await expect(
        decryptWithChunkSize(ciphertext, incorrect_fek, chunk_bytes),
      ).rejects.toBeInstanceOf(SkvaError);

      try {
        await decryptWithChunkSize(ciphertext, incorrect_fek, chunk_bytes);
        throw new Error("Expected decryptWithChunkSize to reject");
      } catch (error) {
        expect(error).toBeInstanceOf(SkvaError);
        const skva_error = error as SkvaError;
        expect(skva_error.code).toBe("ERR_AEAD_AUTH_FAILED");
      }
    });
  }
});
