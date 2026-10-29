import { describe, expect, it } from "vitest";

import {
  SKVA_CIPHER_NAME,
  SKVA_KDF_NAME,
  SKVA_KEM_NAME,
  SKVA_RECOVERY_NOTE,
  SKVA_RECOVERY_NOTE_META_ENCRYPTED,
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

    expect(parsed).toEqual({ json_header: header });
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

  it("parseSkvaJsonHeaderBytes throws ERR_HEADER_SCHEMA_INVALID when the JSON is not an object", () => {
    try {
      parseSkvaJsonHeaderBytes(new TextEncoder().encode("[1]"));
      throw new Error("Expected parseSkvaJsonHeaderBytes to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_HEADER_SCHEMA_INVALID");
      expect(skva_error.message).toContain("Header must be a JSON object");
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
    expect("meta_encrypted" in header).toBe(false);
  });

  it("createSkvaJsonHeader adds meta_encrypted and its recovery note entries", () => {
    const meta_encrypted = {
      algorithm: SKVA_CIPHER_NAME,
      key_derivation: "hkdf_sha256",
      ciphertext_b64: "AAECAwQFBgcICQoLDA0ODxAREhM=",
    } as const;

    const header = createSkvaJsonHeader({
      recipients: [makeRecipient()],
      plaintext_chunk_bytes: 64,
      meta_encrypted,
    });

    expect(header.meta_encrypted).toEqual(meta_encrypted);
    expect(header.recovery_note).toEqual({
      ...SKVA_RECOVERY_NOTE,
      ...SKVA_RECOVERY_NOTE_META_ENCRYPTED,
    });
  });

  it.each([
    ["meta", { meta: "not an object" }, "meta must be an object"],
    ["meta_encrypted", { meta_encrypted: "not an object" }, "meta_encrypted must be an object"],
  ])("validateSkvaJsonHeader rejects malformed %s", (_label, fields, message_part) => {
    const header = { ...makeValidHeader(), ...fields };

    try {
      validateSkvaJsonHeader(header);
      throw new Error("Expected validateSkvaJsonHeader to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_HEADER_SCHEMA_INVALID");
      expect(skva_error.message).toContain(message_part);
    }
  });

  it("parseSkvaJsonHeaderBytes leaves malformed meta and meta_encrypted unset", () => {
    const header = {
      ...makeValidHeader(),
      meta: ["not", "an", "object"],
      meta_encrypted: { algorithm: "chacha20poly1305" },
    };

    const parsed = parseSkvaJsonHeaderBytes(
      new TextEncoder().encode(JSON.stringify(header)),
    );

    expect("meta" in parsed.json_header).toBe(false);
    expect("meta_encrypted" in parsed.json_header).toBe(false);
    expect(parsed.json_header.recipients).toEqual(header.recipients);
    expect(parsed.meta_encrypted_error).toBeInstanceOf(SkvaError);
    expect(parsed.meta_encrypted_error!.code).toBe("ERR_HEADER_SCHEMA_INVALID");
    expect(parsed.meta_encrypted_error!.message).toContain("key_derivation");
  });

  it("parseSkvaJsonHeaderBytes keeps a well-formed meta_encrypted", () => {
    const meta_encrypted = {
      algorithm: SKVA_CIPHER_NAME,
      key_derivation: "hkdf_sha256",
      ciphertext_b64: "AAECAwQFBgcICQoLDA0ODxAREhM=",
    } as const;
    const header = { ...makeValidHeader(), meta_encrypted };

    const parsed = parseSkvaJsonHeaderBytes(serializeSkvaJsonHeader(header));

    expect(parsed).toEqual({ json_header: header });
  });

  it("validateSkvaJsonHeader ignores unrecognized fields", () => {
    const header = {
      ...makeValidHeader(),
      future_field: { anything: true },
    };
    header.recipients[0] = {
      ...header.recipients[0]!,
      future_recipient_field: 1,
    } as SkvaRecipientFekWrapper;
    expect(() => validateSkvaJsonHeader(header)).not.toThrow();
  });
});
