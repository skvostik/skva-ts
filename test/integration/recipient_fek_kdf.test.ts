import { describe, expect, it } from "vitest";

import { SkvaError } from "../../src/errors.js";
import {
  skvaGenerateRecipient,
  tryUnwrapFekFromRecipients,
  wrapFekForRecipient,
} from "../../src/recipient.js";
import type { SkvaRecipientFekWrapper } from "../../src/types.js";
import { decodeBase64, encodeBase64 } from "../../src/utils/base64.js";

const FIXED_FEK = new Uint8Array([
  201, 17, 62, 93, 44, 5, 176, 19,
  240, 121, 64, 88, 233, 7, 154, 2,
  119, 31, 212, 76, 45, 188, 53, 166,
  94, 130, 15, 173, 221, 38, 59, 97,
]);

const CHEAP_KDF = {
  time_cost: 1,
  memory_cost_kib: 256,
  parallelism: 1,
  derived_key_bytes: 32,
} as const;

const RECIPIENT_TEST_TIMEOUT_MS = 30_000;

function cloneWrapped(recipient: SkvaRecipientFekWrapper): SkvaRecipientFekWrapper {
  return JSON.parse(JSON.stringify(recipient)) as SkvaRecipientFekWrapper;
}

describe("integration/recipient_fek_kdf", { timeout: 30_000 }, () => {
  it("wrapFekForRecipient + tryUnwrapFekFromRecipients roundtrip with explicit recipient id", async () => {
    const recipient = await skvaGenerateRecipient(
      "integration-pass-1",
      "integration-r1",
      CHEAP_KDF,
    );
    const wrapped = wrapFekForRecipient(recipient, FIXED_FEK);

    const out = await tryUnwrapFekFromRecipients(
      [wrapped],
      "integration-pass-1",
      "integration-r1",
    );

    expect(out.recipient_id).toBe("integration-r1");
    expect(out.fek).toEqual(FIXED_FEK);
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("wrap/unwrap works when recipient id falls back to hash-derived value", async () => {
    const recipient = await skvaGenerateRecipient(
      "integration-pass-2",
      undefined,
      CHEAP_KDF,
    );
    const wrapped = wrapFekForRecipient(recipient, FIXED_FEK);

    expect(wrapped.recipient_id.length).toBeGreaterThan(0);

    const out = await tryUnwrapFekFromRecipients(
      [wrapped],
      "integration-pass-2",
      wrapped.recipient_id,
    );

    expect(out.recipient_id).toBe(wrapped.recipient_id);
    expect(out.fek).toEqual(FIXED_FEK);
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("wrong password cannot unwrap FEK", async () => {
    const recipient = await skvaGenerateRecipient(
      "integration-pass-3",
      "integration-r3",
      CHEAP_KDF,
    );
    const wrapped = wrapFekForRecipient(recipient, FIXED_FEK);

    await expect(
      tryUnwrapFekFromRecipients([wrapped], "wrong-password", "integration-r3"),
    ).rejects.toBeInstanceOf(SkvaError);

    try {
      await tryUnwrapFekFromRecipients([wrapped], "wrong-password", "integration-r3");
      throw new Error("Expected tryUnwrapFekFromRecipients to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_NO_RECIPIENT_MATCH");
    }
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("KDF parameters are enforced and not ignored during unwrap", async () => {
    const password = "integration-pass-4";
    const recipient = await skvaGenerateRecipient(
      password,
      "integration-r4",
      CHEAP_KDF,
    );
    const wrapped = wrapFekForRecipient(recipient, FIXED_FEK);

    const mutated_wrappers: SkvaRecipientFekWrapper[] = [];

    const salt_mutation = cloneWrapped(wrapped);
    salt_mutation.kdf.salt_b64 = encodeBase64(new Uint8Array(16).fill(7));
    mutated_wrappers.push(salt_mutation);

    const time_mutation = cloneWrapped(wrapped);
    time_mutation.kdf.time_cost += 1;
    mutated_wrappers.push(time_mutation);

    const memory_mutation = cloneWrapped(wrapped);
    memory_mutation.kdf.memory_cost_kib += 1;
    mutated_wrappers.push(memory_mutation);

    const parallelism_mutation = cloneWrapped(wrapped);
    parallelism_mutation.kdf.parallelism += 1;
    mutated_wrappers.push(parallelism_mutation);

    const derived_len_mutation = cloneWrapped(wrapped);
    derived_len_mutation.kdf.derived_key_bytes += 1;
    mutated_wrappers.push(derived_len_mutation);

    for (const mutated of mutated_wrappers) {
      await expect(
        tryUnwrapFekFromRecipients([mutated], password, "integration-r4"),
      ).rejects.toBeInstanceOf(SkvaError);

      try {
        await tryUnwrapFekFromRecipients([mutated], password, "integration-r4");
        throw new Error("Expected tryUnwrapFekFromRecipients to reject");
      } catch (error) {
        expect(error).toBeInstanceOf(SkvaError);
        const skva_error = error as SkvaError;
        expect(skva_error.code).toBe("ERR_NO_RECIPIENT_MATCH");
      }
    }
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("salts from skvaGenerateRecipient are random-looking and not reused", async () => {
    const password = "integration-pass-5";

    const recipients = await Promise.all([
      skvaGenerateRecipient(password, "integration-r5-a", CHEAP_KDF),
      skvaGenerateRecipient(password, "integration-r5-b", CHEAP_KDF),
      skvaGenerateRecipient(password, "integration-r5-c", CHEAP_KDF),
    ]);

    const salts = recipients.map((recipient) => recipient.kdf.salt_b64);
    const unique_salts = new Set(salts);

    expect(unique_salts.size).toBe(salts.length);
    for (const salt_b64 of salts) {
      expect(decodeBase64(salt_b64, "kdf.salt_b64").length).toBe(16);
    }
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("wrapFekForRecipient uses fresh nonce per wrap and outputs still unwrap", async () => {
    const recipient = await skvaGenerateRecipient(
      "integration-pass-6",
      "integration-r6",
      CHEAP_KDF,
    );

    const wrapped_1 = wrapFekForRecipient(recipient, FIXED_FEK);
    const wrapped_2 = wrapFekForRecipient(recipient, FIXED_FEK);
    const wrapped_3 = wrapFekForRecipient(recipient, FIXED_FEK);

    const nonces = [
      wrapped_1.fek.nonce_b64,
      wrapped_2.fek.nonce_b64,
      wrapped_3.fek.nonce_b64,
    ];

    expect(new Set(nonces).size).toBe(nonces.length);
    for (const nonce_b64 of nonces) {
      expect(decodeBase64(nonce_b64, "fek.nonce_b64").length).toBe(12);
    }

    expect(wrapped_1.kem.ciphertext_b64).not.toBe(wrapped_2.kem.ciphertext_b64);

    const out_1 = await tryUnwrapFekFromRecipients([wrapped_1], "integration-pass-6", "integration-r6");
    const out_2 = await tryUnwrapFekFromRecipients([wrapped_2], "integration-pass-6", "integration-r6");
    const out_3 = await tryUnwrapFekFromRecipients([wrapped_3], "integration-pass-6", "integration-r6");

    expect(out_1.fek).toEqual(FIXED_FEK);
    expect(out_2.fek).toEqual(FIXED_FEK);
    expect(out_3.fek).toEqual(FIXED_FEK);
  }, RECIPIENT_TEST_TIMEOUT_MS);
});
