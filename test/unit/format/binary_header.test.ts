import { describe, expect, it } from "vitest";

import {
  SKVA_MAGIC,
  SKVA_VERSION,
} from "../../../src/constants.js";
import { SkvaError } from "../../../src/errors.js";
import {
  buildSkvaBinaryHeader,
  parseSkvaBinaryHeaderStream,
  serializeSkvaBinaryHeaderBytes,
} from "../../../src/format/binary_header.js";
import { serializeSkvaJsonHeader } from "../../../src/format/json_header.js";
import { bytesToReadableStream } from "../../../src/stream/adapters.js";
import { concatBytes, uint32ToBe } from "../../../src/utils/bytes.js";

function makeJsonHeaderBytes(): Uint8Array {
  return serializeSkvaJsonHeader({
    format: "skva",
    version: 1,
    recovery_note: { source: "unit" },
    recipients: [
      {
        recipient_id: "r1",
        kdf: {
          algorithm: "argon2id",
          salt_b64: "AAECAwQFBgcICQoLDA0ODw==",
          time_cost: 3,
          memory_cost_kib: 65536,
          parallelism: 1,
          derived_key_bytes: 32,
        },
        kem: {
          algorithm: "ml_kem1024_p384",
          ciphertext_b64: "AQI=",
        },
        fek: {
          algorithm: "chacha20poly1305",
          nonce_b64: "AAECAwQFBgcICQoL",
          encrypted_fek_b64: "AAECAwQFBgcICQoLDA0ODxAREhM=",
        },
      },
    ],
    payload: {
      algorithm: "chacha20poly1305",
      plaintext_chunk_bytes: 11,
    },
  });
}

describe("format/binary_header", () => {
  it("buildSkvaBinaryHeader fills all fields from input bytes", () => {
    const header_bytes = makeJsonHeaderBytes();
    const extension_bytes = new Uint8Array([9, 8, 7]);

    const out = buildSkvaBinaryHeader(header_bytes, extension_bytes);

    expect(out.magic).toBe(SKVA_MAGIC);
    expect(out.version).toBe(SKVA_VERSION);
    expect(out.header_length).toBe(header_bytes.length);
    expect(out.header_bytes).toBe(header_bytes);
    expect(out.header_extension_length).toBe(extension_bytes.length);
    expect(out.header_extension_bytes).toBe(extension_bytes);
  });

  it("serializeSkvaBinaryHeaderBytes encodes bytes in wire order", () => {
    const header_bytes = makeJsonHeaderBytes();
    const extension_bytes = new Uint8Array([1, 2, 3]);
    const binary_header = buildSkvaBinaryHeader(header_bytes, extension_bytes);

    const actual = serializeSkvaBinaryHeaderBytes(binary_header);
    const expected = concatBytes(
      new TextEncoder().encode(SKVA_MAGIC),
      new Uint8Array([SKVA_VERSION]),
      uint32ToBe(header_bytes.length),
      header_bytes,
      uint32ToBe(extension_bytes.length),
      extension_bytes,
    );

    expect(actual).toEqual(expected);
  });

  it("serializeSkvaBinaryHeaderBytes rejects header_length above uint32", () => {
    const header_bytes = makeJsonHeaderBytes();
    const extension_bytes = new Uint8Array([1]);
    const binary_header = buildSkvaBinaryHeader(header_bytes, extension_bytes);
    binary_header.header_length = 0x1_0000_0000;

    try {
      serializeSkvaBinaryHeaderBytes(binary_header);
      throw new Error("Expected serializeSkvaBinaryHeaderBytes to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_HEADER_LENGTH_INVALID");
      expect(skva_error.message).toContain("Header bytes exceed");
    }
  });

  it("serializeSkvaBinaryHeaderBytes rejects header_extension_length above uint32", () => {
    const header_bytes = makeJsonHeaderBytes();
    const extension_bytes = new Uint8Array([1]);
    const binary_header = buildSkvaBinaryHeader(header_bytes, extension_bytes);
    binary_header.header_extension_length = 0x1_0000_0000;

    try {
      serializeSkvaBinaryHeaderBytes(binary_header);
      throw new Error("Expected serializeSkvaBinaryHeaderBytes to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_HEADER_LENGTH_INVALID");
      expect(skva_error.message).toContain("Header extension bytes exceed");
    }
  });

  it("parseSkvaBinaryHeaderStream parses binary header and leaves payload readable", async () => {
    const header_bytes = makeJsonHeaderBytes();
    const extension_bytes = new Uint8Array([4, 5, 6]);
    const payload_tail = new Uint8Array([10, 11]);

    const wire_bytes = concatBytes(
      new TextEncoder().encode(SKVA_MAGIC),
      new Uint8Array([SKVA_VERSION]),
      uint32ToBe(header_bytes.length),
      header_bytes,
      uint32ToBe(extension_bytes.length),
      extension_bytes,
      payload_tail,
    );

    const parsed = await parseSkvaBinaryHeaderStream(
      bytesToReadableStream(wire_bytes),
    );

    expect(parsed.binary_header.magic).toBe(SKVA_MAGIC);
    expect(parsed.binary_header.version).toBe(SKVA_VERSION);
    expect(parsed.binary_header.header_length).toBe(header_bytes.length);
    expect(parsed.binary_header.header_bytes).toEqual(header_bytes);
    expect(parsed.binary_header.header_extension_length).toBe(
      extension_bytes.length,
    );
    expect(parsed.binary_header.header_extension_bytes).toEqual(extension_bytes);
    expect(parsed.json_header.payload.plaintext_chunk_bytes).toBe(11);

    const tail = await parsed.reader.readBytesExact(2, "payload tail");
    expect(tail).toEqual(payload_tail);
    parsed.reader.releaseLock();
  });

  it("parseSkvaBinaryHeaderStream rejects mismatched magic", async () => {
    const header_bytes = makeJsonHeaderBytes();
    const wire_bytes = concatBytes(
      new TextEncoder().encode("XKVA"),
      new Uint8Array([SKVA_VERSION]),
      uint32ToBe(header_bytes.length),
      header_bytes,
      uint32ToBe(0),
    );

    await expect(
      parseSkvaBinaryHeaderStream(bytesToReadableStream(wire_bytes)),
    ).rejects.toBeInstanceOf(SkvaError);

    try {
      await parseSkvaBinaryHeaderStream(bytesToReadableStream(wire_bytes));
      throw new Error("Expected parseSkvaBinaryHeaderStream to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_MAGIC_MISMATCH");
    }
  });

  it("parseSkvaBinaryHeaderStream rejects unsupported version", async () => {
    const header_bytes = makeJsonHeaderBytes();
    const wire_bytes = concatBytes(
      new TextEncoder().encode(SKVA_MAGIC),
      new Uint8Array([2]),
      uint32ToBe(header_bytes.length),
      header_bytes,
      uint32ToBe(0),
    );

    await expect(
      parseSkvaBinaryHeaderStream(bytesToReadableStream(wire_bytes)),
    ).rejects.toBeInstanceOf(SkvaError);

    try {
      await parseSkvaBinaryHeaderStream(bytesToReadableStream(wire_bytes));
      throw new Error("Expected parseSkvaBinaryHeaderStream to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_UNSUPPORTED_VERSION");
    }
  });
});
