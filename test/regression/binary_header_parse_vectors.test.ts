import { describe, expect, it } from "vitest";

import {
  SKVA_MAGIC,
  SKVA_VERSION,
} from "../../src/constants.js";
import { SkvaError } from "../../src/errors.js";
import { parseSkvaBinaryHeaderStream } from "../../src/format/binary_header.js";
import { bytesToReadableStream } from "../../src/stream/adapters.js";
import { concatBytes, uint32ToBe } from "../../src/utils/bytes.js";

const FIXED_HEADER_JSON =
  '{"format":"skva","version":1,"recovery_note":{"algorithm":"det"},"recipients":[{"recipient_id":"r1","kdf":{"algorithm":"argon2id","salt_b64":"AAECAwQFBgcICQoLDA0ODw==","time_cost":3,"memory_cost_kib":65536,"parallelism":1,"derived_key_bytes":32},"kem":{"algorithm":"ml_kem1024_p384","ciphertext_b64":"AQI="},"fek":{"algorithm":"chacha20poly1305","nonce_b64":"AAECAwQFBgcICQoL","encrypted_fek_b64":"AAECAwQFBgcICQoLDA0ODxAREhM="}}],"payload":{"algorithm":"chacha20poly1305","plaintext_chunk_bytes":11}}';
const FIXED_HEADER_OBJECT = JSON.parse(FIXED_HEADER_JSON);

const FIXED_HEADER_EXTENSION_BYTES = new Uint8Array([9, 8, 7]);
const FIXED_TRAILING_PAYLOAD_BYTES = new Uint8Array([1, 2, 3, 4, 5]);

function buildFixedBinaryStreamBytes(): Uint8Array {
  const header_bytes = new TextEncoder().encode(FIXED_HEADER_JSON);
  return concatBytes(
    new TextEncoder().encode(SKVA_MAGIC),
    new Uint8Array([SKVA_VERSION]),
    uint32ToBe(header_bytes.length),
    header_bytes,
    uint32ToBe(FIXED_HEADER_EXTENSION_BYTES.length),
    FIXED_HEADER_EXTENSION_BYTES,
    FIXED_TRAILING_PAYLOAD_BYTES,
  );
}

describe("regression/binary_header_parse_vectors", () => {
  it("parseSkvaBinaryHeaderStream parses fixed vector and preserves trailing payload", async () => {
    const fixed_stream_bytes = buildFixedBinaryStreamBytes();
    const fixed_header_bytes = new TextEncoder().encode(FIXED_HEADER_JSON);
    const parsed = await parseSkvaBinaryHeaderStream(
      bytesToReadableStream(fixed_stream_bytes),
    );

    expect(parsed.binary_header.magic).toBe(SKVA_MAGIC);
    expect(parsed.binary_header.version).toBe(SKVA_VERSION);
    expect(parsed.binary_header.header_length).toBe(fixed_header_bytes.length);
    expect(parsed.binary_header.header_bytes).toEqual(fixed_header_bytes);
    expect(parsed.binary_header.header_extension_length).toBe(
      FIXED_HEADER_EXTENSION_BYTES.length,
    );
    expect(parsed.binary_header.header_extension_bytes).toEqual(
      FIXED_HEADER_EXTENSION_BYTES,
    );

    expect(parsed.json_header).toEqual(FIXED_HEADER_OBJECT);

    const trailing_payload = await parsed.reader.readBytesExact(
      FIXED_TRAILING_PAYLOAD_BYTES.length,
      "fixed trailing payload",
    );
    expect(trailing_payload).toEqual(FIXED_TRAILING_PAYLOAD_BYTES);

    parsed.reader.releaseLock();
  });

  it("parseSkvaBinaryHeaderStream fails on magic mismatch", async () => {
    const fixed_stream_bytes = buildFixedBinaryStreamBytes();
    const bad_magic = fixed_stream_bytes.slice();
    bad_magic[0] = 0x00;

    await expect(
      parseSkvaBinaryHeaderStream(bytesToReadableStream(bad_magic)),
    ).rejects.toBeInstanceOf(SkvaError);

    try {
      await parseSkvaBinaryHeaderStream(bytesToReadableStream(bad_magic));
      throw new Error("Expected parseSkvaBinaryHeaderStream to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_MAGIC_MISMATCH");
    }
  });

  it("parseSkvaBinaryHeaderStream fails on unsupported version", async () => {
    const fixed_stream_bytes = buildFixedBinaryStreamBytes();
    const bad_version = fixed_stream_bytes.slice();
    bad_version[SKVA_MAGIC.length] = 0x02;

    await expect(
      parseSkvaBinaryHeaderStream(bytesToReadableStream(bad_version)),
    ).rejects.toBeInstanceOf(SkvaError);

    try {
      await parseSkvaBinaryHeaderStream(bytesToReadableStream(bad_version));
      throw new Error("Expected parseSkvaBinaryHeaderStream to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_UNSUPPORTED_VERSION");
    }
  });
});
