import { describe, expect, it } from "vitest";

import { skvaDecryptBytes, skvaEncryptBytes } from "../../src/api.js";
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
  "API integration payload: end-to-end encrypt/decrypt and header reads.",
);

describe("integration/api/recipients", { timeout: 30_000 }, () => {
  it("skvaDecryptBytes rejects wrong password", async () => {
    const recipient = await skvaGenerateRecipient(
      "api-pass-4",
      "api-r4",
      CHEAP_KDF,
    );

    const encrypted = await skvaEncryptBytes(FIXED_PLAINTEXT, {
      recipients: [recipient],
      plaintext_chunk_bytes: 11,
    });

    await expect(
      skvaDecryptBytes(encrypted.bytes, {
        password: "wrong-password",
        recipient_id: "api-r4",
      }),
    ).rejects.toBeInstanceOf(SkvaError);

    try {
      await skvaDecryptBytes(encrypted.bytes, {
        password: "wrong-password",
        recipient_id: "api-r4",
      });
      throw new Error("Expected skvaDecryptBytes to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_NO_RECIPIENT_MATCH");
    }
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("skvaDecryptBytes rejects non-matching recipient_id even with valid password", async () => {
    const recipient = await skvaGenerateRecipient(
      "api-pass-5",
      "api-r5",
      CHEAP_KDF,
    );

    const encrypted = await skvaEncryptBytes(FIXED_PLAINTEXT, {
      recipients: [recipient],
      plaintext_chunk_bytes: 11,
    });

    await expect(
      skvaDecryptBytes(encrypted.bytes, {
        password: "api-pass-5",
        recipient_id: "other-recipient",
      }),
    ).rejects.toBeInstanceOf(SkvaError);

    try {
      await skvaDecryptBytes(encrypted.bytes, {
        password: "api-pass-5",
        recipient_id: "other-recipient",
      });
      throw new Error("Expected skvaDecryptBytes to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_NO_RECIPIENT_MATCH");
    }
  }, RECIPIENT_TEST_TIMEOUT_MS);

  it("multi-recipient decrypt works with implicit and explicit recipient selection", async () => {
    const recipient_a = await skvaGenerateRecipient(
      "api-pass-6-a",
      "api-r6-a",
      CHEAP_KDF,
    );
    const recipient_b = await skvaGenerateRecipient(
      "api-pass-6-b",
      "api-r6-b",
      CHEAP_KDF,
    );

    const encrypted = await skvaEncryptBytes(FIXED_PLAINTEXT, {
      recipients: [recipient_a, recipient_b],
      plaintext_chunk_bytes: 11,
    });

    const decrypted_implicit = await skvaDecryptBytes(encrypted.bytes, {
      password: "api-pass-6-b",
    });
    expect(decrypted_implicit.bytes).toEqual(FIXED_PLAINTEXT);

    const decrypted_explicit = await skvaDecryptBytes(encrypted.bytes, {
      password: "api-pass-6-b",
      recipient_id: "api-r6-b",
    });
    expect(decrypted_explicit.bytes).toEqual(FIXED_PLAINTEXT);

    await expect(
      skvaDecryptBytes(encrypted.bytes, {
        password: "api-pass-6-b",
        recipient_id: "api-r6-a",
      }),
    ).rejects.toBeInstanceOf(SkvaError);

    try {
      await skvaDecryptBytes(encrypted.bytes, {
        password: "api-pass-6-b",
        recipient_id: "api-r6-a",
      });
      throw new Error("Expected skvaDecryptBytes to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_NO_RECIPIENT_MATCH");
    }
  }, RECIPIENT_TEST_TIMEOUT_MS);
});
