import { describe, expect, it } from "vitest";

import { skvaDecryptBytes, skvaEncryptBytes } from "../../src/api.js";
import { SKVA_RECOVERY_NOTE_META_ENCRYPTED } from "../../src/constants.js";
import { SkvaError } from "../../src/errors.js";
import { skvaGenerateRecipient } from "../../src/recipient.js";

const RECIPIENT_TEST_TIMEOUT_MS = 30_000;

const CHEAP_KDF = {
  time_cost: 1,
  memory_cost_kib: 256,
  parallelism: 1,
  derived_key_bytes: 32,
} as const;

const FIXED_PLAINTEXT = new TextEncoder().encode(
  "API integration payload: encrypted metadata round trip.",
);

const SECRET_FILENAME = "quarterly-salaries-2026.xlsx";

describe("integration/api/meta_encrypted", { timeout: 30_000 }, () => {
  it("round-trips meta_encrypted without exposing it in the file", async () => {
    const recipient = await skvaGenerateRecipient(
      "api-pass-meta",
      "api-r-meta",
      CHEAP_KDF,
    );

    const encrypted = await skvaEncryptBytes(FIXED_PLAINTEXT, {
      recipients: [recipient],
      meta: { created_at: "2026-07-27T12:00:00Z" },
      meta_encrypted: { original_filename: SECRET_FILENAME },
    });

    expect(encrypted.json_header.meta_encrypted).toBeDefined();
    expect(encrypted.json_header.recovery_note).toMatchObject(
      SKVA_RECOVERY_NOTE_META_ENCRYPTED,
    );
    expect(new TextDecoder().decode(encrypted.bytes)).not.toContain(
      SECRET_FILENAME,
    );

    const decrypted = await skvaDecryptBytes(encrypted.bytes, {
      password: "api-pass-meta",
    });

    expect(decrypted.bytes).toEqual(FIXED_PLAINTEXT);
    expect(decrypted.meta_encrypted).toEqual({
      original_filename: SECRET_FILENAME,
    });
    expect(decrypted.meta).toEqual({
      created_at: "2026-07-27T12:00:00Z",
    });
    expect("meta_encrypted_error" in decrypted).toBe(false);
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("omits meta_encrypted fields when not provided", async () => {
    const recipient = await skvaGenerateRecipient(
      "api-pass-no-meta",
      "api-r-no-meta",
      CHEAP_KDF,
    );

    const encrypted = await skvaEncryptBytes(FIXED_PLAINTEXT, {
      recipients: [recipient],
    });
    const decrypted = await skvaDecryptBytes(encrypted.bytes, {
      password: "api-pass-no-meta",
    });

    expect("meta_encrypted" in encrypted.json_header).toBe(false);
    expect(encrypted.json_header.recovery_note).not.toHaveProperty(
      "meta_encrypted",
    );
    expect("meta" in decrypted).toBe(false);
    expect("meta_encrypted" in decrypted).toBe(false);
    expect("meta_encrypted_error" in decrypted).toBe(false);
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("still decrypts the payload when meta_encrypted is tampered with", async () => {
    const recipient = await skvaGenerateRecipient(
      "api-pass-tamper",
      "api-r-tamper",
      CHEAP_KDF,
    );

    const encrypted = await skvaEncryptBytes(FIXED_PLAINTEXT, {
      recipients: [recipient],
      meta_encrypted: { original_filename: SECRET_FILENAME },
    });

    // Swap one base64 character in place, so the header length stays the same.
    const ciphertext_b64 = encrypted.json_header.meta_encrypted!.ciphertext_b64;
    const tampered_b64 =
      (ciphertext_b64[0] === "A" ? "B" : "A") + ciphertext_b64.slice(1);
    const file_text = new TextDecoder("latin1").decode(encrypted.bytes);
    const offset = file_text.indexOf(ciphertext_b64);
    expect(offset).toBeGreaterThan(0);
    const tampered_bytes = encrypted.bytes.slice();
    tampered_bytes.set(new TextEncoder().encode(tampered_b64), offset);

    const decrypted = await skvaDecryptBytes(tampered_bytes, {
      password: "api-pass-tamper",
    });

    expect(decrypted.bytes).toEqual(FIXED_PLAINTEXT);
    expect("meta_encrypted" in decrypted).toBe(false);
    expect(decrypted.meta_encrypted_error).toBeInstanceOf(SkvaError);
    expect(decrypted.meta_encrypted_error!.code).toBe("ERR_AEAD_AUTH_FAILED");
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("still decrypts the payload when meta and meta_encrypted are malformed", async () => {
    const recipient = await skvaGenerateRecipient(
      "api-pass-malformed",
      "api-r-malformed",
      CHEAP_KDF,
    );
    const encrypted = await skvaEncryptBytes(FIXED_PLAINTEXT, {
      recipients: [recipient],
      meta: { created_at: "2026-07-27T12:00:00Z" },
      meta_encrypted: { original_filename: SECRET_FILENAME },
    });

    const header = JSON.parse(
      new TextDecoder().decode(encrypted.binary_header.header_bytes),
    );
    header.meta = "not an object";
    header.meta_encrypted = { algorithm: "chacha20poly1305" };
    const malformed_bytes = replaceJsonHeader(encrypted.bytes, header);

    const decrypted = await skvaDecryptBytes(malformed_bytes, {
      password: "api-pass-malformed",
    });

    expect(decrypted.bytes).toEqual(FIXED_PLAINTEXT);
    expect("meta" in decrypted).toBe(false);
    expect("meta" in decrypted.json_header).toBe(false);
    expect("meta_encrypted" in decrypted).toBe(false);
    expect("meta_encrypted" in decrypted.json_header).toBe(false);
    expect(decrypted.meta_encrypted_error!.code).toBe("ERR_HEADER_SCHEMA_INVALID");
  }, RECIPIENT_TEST_TIMEOUT_MS);
});

// Rebuilds an SKVA file with a different JSON header, keeping the rest of the file.
function replaceJsonHeader(skva_bytes: Uint8Array, header: unknown): Uint8Array {
  const old_header_length = new DataView(
    skva_bytes.buffer,
    skva_bytes.byteOffset,
  ).getUint32(5);
  const header_bytes = new TextEncoder().encode(JSON.stringify(header));
  const rest = skva_bytes.slice(9 + old_header_length);

  const out = new Uint8Array(9 + header_bytes.length + rest.length);
  out.set(skva_bytes.slice(0, 5));
  new DataView(out.buffer).setUint32(5, header_bytes.length);
  out.set(header_bytes, 9);
  out.set(rest, 9 + header_bytes.length);
  return out;
}
