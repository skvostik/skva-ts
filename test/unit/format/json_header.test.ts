import { describe, expect, it } from "vitest";

import {
  SKVA_CIPHER_NAME,
  SKVA_KDF_NAME,
  SKVA_KEM_NAME,
  SKVA_RECOVERY_NOTE,
} from "../../../src/constants.js";
import { SkvaError } from "../../../src/errors.js";
import {
  createSkvaJsonHeader,
  parseSkvaJsonHeaderBytes,
  serializeSkvaJsonHeader,
  validateSkvaJsonHeader,
} from "../../../src/format/json_header.js";
import type { SkvaJsonHeader, SkvaRecipientFekWrapper } from "../../../src/types.js";

function makeRecipient(): SkvaRecipientFekWrapper {
  return {
    recipient_id: "ops-primary",
    kdf: {
      algorithm: SKVA_KDF_NAME,
      salt_b64: "AAECAwQFBgcICQoLDA0ODw==",
      time_cost: 3,
      memory_cost_kib: 65536,
      parallelism: 1,
      derived_key_bytes: 32,
    },
    kem: {
      algorithm: SKVA_KEM_NAME,
      ciphertext_b64: "AQI=",
      public_key_b64: "AQID",
      public_key_sha256_b64: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    },
    fek: {
      algorithm: SKVA_CIPHER_NAME,
      nonce_b64: "AAECAwQFBgcICQoL",
      encrypted_fek_b64: "AAECAwQFBgcICQoLDA0ODxAREhM=",
    },
  };
}

function makeValidHeader(): SkvaJsonHeader {
  return {
    format: "skva",
    version: 1,
    recovery_note: { hello: "world" },
    recipients: [makeRecipient()],
    payload: {
      algorithm: SKVA_CIPHER_NAME,
      plaintext_chunk_bytes: 11,
    },
    meta: { source: "unit-test" },
  };
}

describe("format/json_header", () => {
  it("serializeSkvaJsonHeader round-trips with parseSkvaJsonHeaderBytes", () => {
    const header = makeValidHeader();

    const bytes = serializeSkvaJsonHeader(header);
    const parsed = parseSkvaJsonHeaderBytes(bytes);

    expect(parsed).toEqual(header);
  });

  it("parseSkvaJsonHeaderBytes throws ERR_HEADER_JSON_INVALID for malformed bytes", () => {
    const malformed = new Uint8Array([0xff, 0xfe, 0xfd]);

    try {
      parseSkvaJsonHeaderBytes(malformed);
      throw new Error("Expected parseSkvaJsonHeaderBytes to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_HEADER_JSON_INVALID");
    }
  });

  it("validateSkvaJsonHeader accepts a schema-valid header", () => {
    const header = makeValidHeader();
    expect(() => validateSkvaJsonHeader(header)).not.toThrow();
  });

  it("validateSkvaJsonHeader rejects wrong format", () => {
    const header = makeValidHeader() as unknown as Record<string, unknown>;
    header.format = "wrong";

    try {
      validateSkvaJsonHeader(header);
      throw new Error("Expected validateSkvaJsonHeader to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_HEADER_SCHEMA_INVALID");
      expect(skva_error.message).toContain("format");
    }
  });

  it("validateSkvaJsonHeader rejects invalid recipient kdf salt length", () => {
    const header = makeValidHeader();
    header.recipients[0]!.kdf.salt_b64 = "AQI=";

    try {
      validateSkvaJsonHeader(header);
      throw new Error("Expected validateSkvaJsonHeader to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_HEADER_SCHEMA_INVALID");
      expect(skva_error.message).toContain("must decode to 16 bytes");
    }
  });

  it("createSkvaJsonHeader creates valid header with optional meta", () => {
    const recipient = makeRecipient();
    const header = createSkvaJsonHeader({
      recipients: [recipient],
      plaintext_chunk_bytes: 1024,
      meta: { file: "a.bin" },
    });

    expect(header.format).toBe("skva");
    expect(header.version).toBe(1);
    expect(header.recovery_note).toEqual(SKVA_RECOVERY_NOTE);
    expect(header.recipients).toEqual([recipient]);
    expect(header.payload).toEqual({
      algorithm: SKVA_CIPHER_NAME,
      plaintext_chunk_bytes: 1024,
    });
    expect(header.meta).toEqual({ file: "a.bin" });
  });

  it("createSkvaJsonHeader omits meta when not provided", () => {
    const header = createSkvaJsonHeader({
      recipients: [makeRecipient()],
      plaintext_chunk_bytes: 64,
    });

    expect("meta" in header).toBe(false);
  });
});
