import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import { skvaDecryptBytes, skvaReadHeaderBytes } from "../../src/api.js";
import { SKVA_RECOVERY_NOTE_META_ENCRYPTED } from "../../src/constants.js";
import { encodeBase64 } from "../../src/utils/base64.js";

const FIXED_PLAINTEXT_B64 =
  "U0tWQSBtZXRhX2VuY3J5cHRlZCByZWdyZXNzaW9uIHZlY3RvcjogbXVsdGktY2h1bmsgcGF5bG9hZCB3aXRoIGVuY3J5cHRlZCBtZXRhZGF0YS4=";
const FIXED_SKVA_BYTES = readFileSync(
  new URL("./fixed_meta_encrypted.skva", import.meta.url),
);

const EXPECTED_META = { created_at: "2026-10-29T00:00:00Z" };
const EXPECTED_META_ENCRYPTED = {
  original_filename: "tajné výplaty 2026.xlsx",
  original_size_bytes: 83,
};

const EXPECTED_RECIPIENTS = [
  {
    recipient_id: "reg-meta-r1",
    password: "reg-meta-pass-1",
  },
  {
    recipient_id: "reg-meta-r2",
    password: "reg-meta-pass-2",
  },
] as const;

describe("regression/skva_meta_encrypted_full_decrypt_vectors", () => {
  it("fixed SKVA vector contains meta_encrypted without exposing its plaintext", async () => {
    const header = await skvaReadHeaderBytes(FIXED_SKVA_BYTES);

    expect(
      header.json_header.recipients.map((recipient) => recipient.recipient_id),
    ).toEqual(EXPECTED_RECIPIENTS.map((r) => r.recipient_id));
    expect(header.json_header.payload.plaintext_chunk_bytes).toBe(32);
    expect(header.json_header.meta).toEqual(EXPECTED_META);
    expect(header.json_header.meta_encrypted).toMatchObject({
      algorithm: "chacha20poly1305",
      key_derivation: "hkdf_sha256",
    });
    expect(header.json_header.recovery_note).toMatchObject(
      SKVA_RECOVERY_NOTE_META_ENCRYPTED,
    );
    expect(new TextDecoder().decode(FIXED_SKVA_BYTES)).not.toContain(
      EXPECTED_META_ENCRYPTED.original_filename,
    );
  });

  for (const entry of EXPECTED_RECIPIENTS) {
    it(`decrypts fixed SKVA vector and meta_encrypted with ${entry.recipient_id}`, async () => {
      const decrypted = await skvaDecryptBytes(FIXED_SKVA_BYTES, {
        password: entry.password,
        recipient_id: entry.recipient_id,
      });

      expect(encodeBase64(decrypted.bytes)).toBe(FIXED_PLAINTEXT_B64);
      expect(decrypted.meta_encrypted).toEqual(EXPECTED_META_ENCRYPTED);
      expect("meta_encrypted_error" in decrypted).toBe(false);
    });
  }
});
