import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import { skvaDecryptBytes, skvaReadHeaderBytes } from "../../src/api.js";
import { encodeBase64 } from "../../src/utils/base64.js";

const FIXED_PLAINTEXT_B64 = "U0tWREEgZnVsbC1maWxlIHJlZ3Jlc3Npb24gdmVjdG9yOiBtdWx0aS1yZWNpcGllbnQgZGVjcnlwdCBjaGVjay4=";
const FIXED_SKVA_BYTES = readFileSync(new URL("./fixed.skva", import.meta.url));

const EXPECTED_RECIPIENTS = [
  {
    recipient_id: "reg-r1",
    password: "reg-pass-1",
  },
  {
    recipient_id: "reg-r2",
    password: "reg-pass-2",
  },
  {
    recipient_id: "reg-r3",
    password: "reg-pass-3",
  },
] as const;

const EXPECTED_LOW_KDF = {
  algorithm: "argon2id",
  time_cost: 1,
  memory_cost_kib: 256,
  parallelism: 1,
  derived_key_bytes: 32,
} as const;

function requireFixedSkvaBytes(): Uint8Array {
  if (FIXED_SKVA_BYTES.length === 0) {
    throw new Error(
      "test/regression/fixed.skva must contain a SKVA payload with recipients reg-r1/reg-r2/reg-r3 and low KDF settings.",
    );
  }
  return FIXED_SKVA_BYTES;
}

describe("regression/skva_full_decrypt_vectors", () => {
  it("fixed SKVA vector contains expected recipients and low KDF settings", async () => {
    const fixed_skva_bytes = requireFixedSkvaBytes();
    const header = await skvaReadHeaderBytes(fixed_skva_bytes);

    expect(header.json_header.recipients.length).toBe(EXPECTED_RECIPIENTS.length);

    const recipient_ids = header.json_header.recipients.map(
      (recipient) => recipient.recipient_id,
    );
    expect(recipient_ids).toEqual(EXPECTED_RECIPIENTS.map((r) => r.recipient_id));

    for (const recipient of header.json_header.recipients) {
      expect(recipient.kdf.algorithm).toBe(EXPECTED_LOW_KDF.algorithm);
      expect(recipient.kdf.time_cost).toBe(EXPECTED_LOW_KDF.time_cost);
      expect(recipient.kdf.memory_cost_kib).toBe(EXPECTED_LOW_KDF.memory_cost_kib);
      expect(recipient.kdf.parallelism).toBe(EXPECTED_LOW_KDF.parallelism);
      expect(recipient.kdf.derived_key_bytes).toBe(EXPECTED_LOW_KDF.derived_key_bytes);
    }
  });

  for (const entry of EXPECTED_RECIPIENTS) {
    it(`decrypts fixed SKVA vector with ${entry.recipient_id}`, async () => {
      const fixed_skva_bytes = requireFixedSkvaBytes();

      const first = await skvaDecryptBytes(fixed_skva_bytes, {
        password: entry.password,
        recipient_id: entry.recipient_id,
      });
      const second = await skvaDecryptBytes(fixed_skva_bytes, {
        password: entry.password,
        recipient_id: entry.recipient_id,
      });

      expect(encodeBase64(first.bytes)).toBe(FIXED_PLAINTEXT_B64);
      expect(encodeBase64(second.bytes)).toBe(FIXED_PLAINTEXT_B64);

      expect(first.json_header.recipients.length).toBe(EXPECTED_RECIPIENTS.length);
      expect(second.json_header.recipients.length).toBe(EXPECTED_RECIPIENTS.length);
    });
  }
});
