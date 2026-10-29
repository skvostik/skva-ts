import { describe, expect, it } from "vitest";

import {
  decryptMetaEncrypted,
  encryptMetaEncrypted,
} from "../../src/format/meta_encrypted.js";

// Computed independently from the SKVA_FORMAT.md 5.8 formula with @noble primitives:
// HKDF-SHA256(FEK, salt=empty, info="meta_encrypted", 32), ChaCha20-Poly1305 with a zero nonce,
// plaintext = JSON padded with spaces to 128 bytes.
const FIXED_FEK = Uint8Array.from({ length: 32 }, (_, i) => i);
const FIXED_META = {
  original_filename: "data-archive.zip",
  created_at: "2026-07-27T12:00:00Z",
};
const FIXED_META_ENCRYPTED = {
  algorithm: "chacha20poly1305",
  key_derivation: "hkdf_sha256",
  ciphertext_b64:
    "C/jXqj7cPnQ0vWxs0zy9r19aNp9UGutOYDZHOpn+0u2rFj+ecIwGsokNl14bMPUdei5LP0+qZQf6lwdf9ThXAyDDksZKzebxdZZVkwU9eMwVdBoCSM9ncTMPIRQR0wimiCiEh1o80PJvtBguKIH2q25XdwtZMrwG/Hg9HMqRBpbhDPhAViO8S/PwiyvvkFp7",
} as const;

describe("regression/meta_encrypted_vectors", () => {
  it("encrypts the fixed metadata to the fixed vector", () => {
    expect(encryptMetaEncrypted(FIXED_META, FIXED_FEK)).toEqual(
      FIXED_META_ENCRYPTED,
    );
  });

  it("decrypts the fixed vector to the fixed metadata", () => {
    expect(decryptMetaEncrypted(FIXED_META_ENCRYPTED, FIXED_FEK)).toEqual(
      FIXED_META,
    );
  });
});
