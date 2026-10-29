import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";

import {
  SKVA_META_ENCRYPTED_PADDING_BYTES,
  SKVA_TAG_BYTES,
} from "../../../src/constants.js";
import { SkvaError, type SkvaErrorCode } from "../../../src/errors.js";
import {
  decryptMetaEncrypted,
  encryptMetaEncrypted,
} from "../../../src/format/meta_encrypted.js";
import { decodeBase64, encodeBase64 } from "../../../src/utils/base64.js";

const FEK = Uint8Array.from({ length: 32 }, (_, i) => i);
const OTHER_FEK = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);

function expectSkvaError(
  fn: () => unknown,
  code: SkvaErrorCode,
  message_part: string,
): void {
  try {
    fn();
    throw new Error("Expected function to throw");
  } catch (error) {
    expect(error).toBeInstanceOf(SkvaError);
    const skva_error = error as SkvaError;
    expect(skva_error.code).toBe(code);
    expect(skva_error.message).toContain(message_part);
  }
}

// Encrypts raw plaintext with the spec formula, to build ciphertexts the encoder would never produce.
function encryptRawPlaintext(plaintext: Uint8Array): string {
  const key = hkdf(
    sha256,
    FEK,
    undefined,
    new TextEncoder().encode("meta_encrypted"),
    32,
  );
  return encodeBase64(
    chacha20poly1305(key, new Uint8Array(12)).encrypt(plaintext),
  );
}

function ciphertextLength(ciphertext_b64: string): number {
  return decodeBase64(ciphertext_b64).length;
}

describe("format/meta_encrypted", () => {
  it("round-trips a metadata object with non-ASCII values", () => {
    const meta = { original_filename: "žluťoučký kůň.zip", size: 42 };

    const header = encryptMetaEncrypted(meta, FEK);

    expect(header.algorithm).toBe("chacha20poly1305");
    expect(header.key_derivation).toBe("hkdf_sha256");
    expect(decryptMetaEncrypted(header, FEK)).toEqual(meta);
  });

  it("pads plaintext with spaces to a multiple of 64 bytes", () => {
    const empty = encryptMetaEncrypted({}, FEK);
    expect(ciphertextLength(empty.ciphertext_b64)).toBe(
      SKVA_META_ENCRYPTED_PADDING_BYTES + SKVA_TAG_BYTES,
    );

    // {"a":"..."} with 56 characters is exactly 64 bytes of JSON, so no extra padding block is added.
    const exact = encryptMetaEncrypted({ a: "x".repeat(56) }, FEK);
    expect(ciphertextLength(exact.ciphertext_b64)).toBe(
      SKVA_META_ENCRYPTED_PADDING_BYTES + SKVA_TAG_BYTES,
    );

    const one_over = encryptMetaEncrypted({ a: "x".repeat(57) }, FEK);
    expect(ciphertextLength(one_over.ciphertext_b64)).toBe(
      2 * SKVA_META_ENCRYPTED_PADDING_BYTES + SKVA_TAG_BYTES,
    );
  });

  it("binds the ciphertext to the FEK", () => {
    const meta = { original_filename: "a.bin" };
    const header = encryptMetaEncrypted(meta, FEK);

    expect(encryptMetaEncrypted(meta, OTHER_FEK).ciphertext_b64).not.toBe(
      header.ciphertext_b64,
    );
    expectSkvaError(
      () => decryptMetaEncrypted(header, OTHER_FEK),
      "ERR_AEAD_AUTH_FAILED",
      "authentication failed",
    );
  });

  it("rejects tampered ciphertext", () => {
    const header = encryptMetaEncrypted({ original_filename: "a.bin" }, FEK);
    const ciphertext = decodeBase64(header.ciphertext_b64);
    ciphertext[0]! ^= 0x01;

    expectSkvaError(
      () =>
        decryptMetaEncrypted(
          { ...header, ciphertext_b64: encodeBase64(ciphertext) },
          FEK,
        ),
      "ERR_AEAD_AUTH_FAILED",
      "authentication failed",
    );
  });

  it.each([
    ["a non-object", null, "meta_encrypted must be an object"],
    [
      "a wrong algorithm",
      { algorithm: "aes", key_derivation: "hkdf_sha256", ciphertext_b64: "" },
      "algorithm must be 'chacha20poly1305'",
    ],
    [
      "a wrong key_derivation",
      { algorithm: "chacha20poly1305", key_derivation: "none", ciphertext_b64: "" },
      "key_derivation must be 'hkdf_sha256'",
    ],
    [
      "a missing ciphertext",
      { algorithm: "chacha20poly1305", key_derivation: "hkdf_sha256" },
      "ciphertext_b64 must be a string",
    ],
    [
      "a ciphertext without room for a tag",
      {
        algorithm: "chacha20poly1305",
        key_derivation: "hkdf_sha256",
        ciphertext_b64: encodeBase64(new Uint8Array(SKVA_TAG_BYTES)),
      },
      "must contain ciphertext and tag",
    ],
  ])("rejects %s with ERR_HEADER_SCHEMA_INVALID", (_label, value, message_part) => {
    expectSkvaError(
      () => decryptMetaEncrypted(value, FEK),
      "ERR_HEADER_SCHEMA_INVALID",
      message_part,
    );
  });

  it("rejects invalid base64 ciphertext", () => {
    expectSkvaError(
      () =>
        decryptMetaEncrypted(
          {
            algorithm: "chacha20poly1305",
            key_derivation: "hkdf_sha256",
            ciphertext_b64: "not base64!",
          },
          FEK,
        ),
      "ERR_BASE64_INVALID",
      "meta_encrypted.ciphertext_b64",
    );
  });

  it.each([
    ["invalid UTF-8", new Uint8Array([0xff]), "not valid UTF-8 JSON"],
    ["invalid JSON", new TextEncoder().encode("not json"), "not valid UTF-8 JSON"],
    ["a JSON array", new TextEncoder().encode("[1]"), "must be a JSON object"],
  ])("rejects authenticated plaintext that is %s", (_label, plaintext, message_part) => {
    const header = {
      algorithm: "chacha20poly1305",
      key_derivation: "hkdf_sha256",
      ciphertext_b64: encryptRawPlaintext(plaintext),
    };

    expectSkvaError(
      () => decryptMetaEncrypted(header, FEK),
      "ERR_HEADER_JSON_INVALID",
      message_part,
    );
  });

  it.each([
    ["null", null, "must be an object"],
    ["an array", [], "must be an object"],
    ["a non-serializable value", { size: 1n }, "must be JSON-serializable"],
  ])("encrypt rejects %s with ERR_INVALID_ARGUMENT", (_label, value, message_part) => {
    expectSkvaError(
      () => encryptMetaEncrypted(value as Record<string, unknown>, FEK),
      "ERR_INVALID_ARGUMENT",
      message_part,
    );
  });
});
