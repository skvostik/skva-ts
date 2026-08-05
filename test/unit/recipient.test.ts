import { describe, expect, it } from "vitest";

import {
  SKVA_DEFAULT_KDF_DERIVED_KEY_LENGTH_BYTES,
  SKVA_DEFAULT_KDF_MEMORY_COST_KIB,
  SKVA_DEFAULT_KDF_PARALLELISM,
  SKVA_DEFAULT_KDF_TIME_COST_ITERATIONS,
} from "../../src/constants.js";
import { SkvaError } from "../../src/errors.js";
import {
  skvaFindRecipient,
  skvaGenerateRecipient,
  tryUnwrapFekFromRecipients,
  wrapFekForRecipient,
} from "../../src/recipient.js";

const FIXED_FEK = new Uint8Array([
  9, 18, 27, 36, 45, 54, 63, 72,
  81, 90, 99, 108, 117, 126, 135, 144,
  153, 162, 171, 180, 189, 198, 207, 216,
  225, 234, 243, 252, 11, 22, 33, 44,
]);

const CHEAP_KDF = {
  time_cost: 1,
  memory_cost_kib: 256,
  parallelism: 1,
  derived_key_bytes: 32,
} as const;

const RECIPIENT_TEST_TIMEOUT_MS = 30_000;

describe("recipient/unit", { timeout: 30_000 }, () => {
  it("skvaGenerateRecipient uses default KDF parameters when options are omitted", async () => {
    const recipient = await skvaGenerateRecipient(
      "unit-password-default-kdf",
      "unit-default-kdf",
    );

    expect(recipient.kdf.algorithm).toBe("argon2id");
    expect(recipient.kdf.time_cost).toBe(SKVA_DEFAULT_KDF_TIME_COST_ITERATIONS);
    expect(recipient.kdf.memory_cost_kib).toBe(SKVA_DEFAULT_KDF_MEMORY_COST_KIB);
    expect(recipient.kdf.parallelism).toBe(SKVA_DEFAULT_KDF_PARALLELISM);
    expect(recipient.kdf.derived_key_bytes).toBe(
      SKVA_DEFAULT_KDF_DERIVED_KEY_LENGTH_BYTES,
    );
  }, 120_000);

  it("skvaFindRecipient returns matched recipient id", async () => {
    const recipient = await skvaGenerateRecipient(
      "unit-password-1",
      "unit-r1",
      CHEAP_KDF,
    );
    const wrapped = wrapFekForRecipient(recipient, FIXED_FEK);

    const found = await skvaFindRecipient([wrapped], "unit-password-1");

    expect(found).toBe("unit-r1");
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("skvaFindRecipient returns null on wrong password", async () => {
    const recipient = await skvaGenerateRecipient(
      "unit-password-2",
      "unit-r2",
      CHEAP_KDF,
    );
    const wrapped = wrapFekForRecipient(recipient, FIXED_FEK);

    const found = await skvaFindRecipient([wrapped], "wrong-password");

    expect(found).toBeNull();
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("tryUnwrapFekFromRecipients respects recipientId filtering", async () => {
    const recipient_a = await skvaGenerateRecipient(
      "unit-password-a",
      "unit-a",
      CHEAP_KDF,
    );
    const recipient_b = await skvaGenerateRecipient(
      "unit-password-b",
      "unit-b",
      CHEAP_KDF,
    );

    const wrapped_a = wrapFekForRecipient(recipient_a, FIXED_FEK);
    const wrapped_b = wrapFekForRecipient(recipient_b, FIXED_FEK);

    await expect(
      tryUnwrapFekFromRecipients(
        [wrapped_a, wrapped_b],
        "unit-password-a",
        "unit-b",
      ),
    ).rejects.toBeInstanceOf(SkvaError);

    try {
      await tryUnwrapFekFromRecipients(
        [wrapped_a, wrapped_b],
        "unit-password-a",
        "unit-b",
      );
      throw new Error("Expected tryUnwrapFekFromRecipients to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_NO_RECIPIENT_MATCH");
    }

    const success = await tryUnwrapFekFromRecipients(
      [wrapped_a, wrapped_b],
      "unit-password-b",
      "unit-b",
    );

    expect(success.recipient_id).toBe("unit-b");
    expect(success.fek).toEqual(FIXED_FEK);
  }, RECIPIENT_TEST_TIMEOUT_MS);

});
