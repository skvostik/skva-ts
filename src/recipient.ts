import { sha256 } from "@noble/hashes/sha2.js";
import {
  SkvaKdfHeader,
  SkvaRecipient,
  SkvaRecipientFekWrapper,
} from "./types.js";
import { decodeBase64, encodeBase64 } from "./utils/base64.js";
import { ml_kem1024_p384 } from "@noble/post-quantum/hybrid.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { argon2idAsync } from "@noble/hashes/argon2.js";
import { SkvaError } from "./errors.js";
import {
  SKVA_DEFAULT_KDF_DERIVED_KEY_LENGTH_BYTES,
  SKVA_DEFAULT_KDF_MEMORY_COST_KIB,
  SKVA_DEFAULT_KDF_PARALLELISM,
  SKVA_DEFAULT_KDF_SALT_BYTES,
  SKVA_DEFAULT_KDF_TIME_COST_ITERATIONS,
  SKVA_NONCE_BYTES,
} from "./constants.js";

/**
 * Creates a recipient descriptor from a password and an optional recipient ID.
 * The returned value is suitable for passing into stream or byte encryption.
 */
export async function skvaGenerateRecipient(
  password: string,
  recipient_id?: string,
  kdf_options?: Partial<Omit<SkvaKdfHeader, "algorithm" | "salt_b64">>,
): Promise<SkvaRecipient> {
  const kdfSalt = crypto.getRandomValues(
    new Uint8Array(SKVA_DEFAULT_KDF_SALT_BYTES),
  );

  const kdf: SkvaKdfHeader = {
    algorithm: "argon2id",
    salt_b64: encodeBase64(kdfSalt),
    time_cost:
      kdf_options?.time_cost ?? SKVA_DEFAULT_KDF_TIME_COST_ITERATIONS,
    memory_cost_kib:
      kdf_options?.memory_cost_kib ?? SKVA_DEFAULT_KDF_MEMORY_COST_KIB,
    parallelism:
      kdf_options?.parallelism ?? SKVA_DEFAULT_KDF_PARALLELISM,
    derived_key_bytes:
      kdf_options?.derived_key_bytes ??
      SKVA_DEFAULT_KDF_DERIVED_KEY_LENGTH_BYTES,
  };

  let kemSeed: Uint8Array;
  try {
    kemSeed = await argon2idAsync(password, kdfSalt, {
      t: kdf.time_cost,
      m: kdf.memory_cost_kib,
      p: kdf.parallelism,
      dkLen: kdf.derived_key_bytes,
    });
  } catch (error) {
    /* c8 ignore next */
    throw new SkvaError(
      "ERR_KDF_DERIVATION_FAILED",
      "Failed to derive recipient KDF key material.",
      { cause: error },
    );
  }

  let publicKey: Uint8Array;
  try {
    ({ publicKey } = ml_kem1024_p384.keygen(kemSeed));
  } catch (error) {
    /* c8 ignore next */
    throw new SkvaError(
      "ERR_KEM_FAILED",
      "Failed to derive recipient KEM key pair.",
      { cause: error },
    );
  } finally {
    kemSeed.fill(0); // Clear KEM seed from memory
  }

  return {
    recipient_id,
    public_key: publicKey,
    kdf,
  };
}

/**
 * Returns the recipient ID that matches the provided password, or null when no recipient can be unlocked.
 */
export async function skvaFindRecipient(
  recipients: SkvaRecipientFekWrapper[],
  password: string,
): Promise<string | null> {
  try {
    const { recipient_id } = await tryUnwrapFekFromRecipients(
      recipients,
      password,
    );
    return recipient_id;
  } catch {
    return null;
  }
}

/**
 * Wraps the FEK for a single recipient entry using the recipient public key and KDF parameters.
 */
export function wrapFekForRecipient(
  recipient: SkvaRecipient,
  fek: Uint8Array,
): SkvaRecipientFekWrapper {
  const public_key_sha256_b64 = encodeBase64(sha256(recipient.public_key));
  const recipient_id = recipient.recipient_id ?? public_key_sha256_b64;
  let cipherText: Uint8Array;
  let sharedSecret: Uint8Array;
  try {
    ({ cipherText, sharedSecret } = ml_kem1024_p384.encapsulate(
      recipient.public_key,
    ));
  } catch (error) {
    /* c8 ignore next */
    throw new SkvaError(
      "ERR_KEM_FAILED",
      "Failed to encapsulate recipient KEM public key.",
      { cause: error },
    );
  }

  const fek_wrap_nonce = crypto.getRandomValues(
    new Uint8Array(SKVA_NONCE_BYTES),
  );
  let encrypted_fek: Uint8Array;
  try {
    encrypted_fek = chacha20poly1305(sharedSecret, fek_wrap_nonce).encrypt(
      fek,
    );
  } catch (error) {
    /* c8 ignore next */
    throw new SkvaError(
      "ERR_FEK_WRAP_FAILED",
      "Failed to wrap FEK for recipient.",
      { cause: error },
    );
  } finally {
    sharedSecret.fill(0); // Clear shared secret from memory
  }

  return {
    recipient_id,
    kdf: recipient.kdf,
    kem: {
      algorithm: "ml_kem1024_p384",
      public_key_sha256_b64: public_key_sha256_b64,
      ciphertext_b64: encodeBase64(cipherText),
      public_key_b64: encodeBase64(recipient.public_key),
    },
    fek: {
      algorithm: "chacha20poly1305",
      nonce_b64: encodeBase64(fek_wrap_nonce),
      encrypted_fek_b64: encodeBase64(encrypted_fek),
    },
  };
}

/**
 * Tries to unwrap FEK for a single recipient entry using the provided password. Throws if unwrapping fails.
 * @param recipient
 * @param password
 * @returns
 */
async function unwrapFekForRecipient(
  recipient: SkvaRecipientFekWrapper,
  password: string,
): Promise<Uint8Array> {
  const salt = decodeBase64(recipient.kdf.salt_b64, "kdf.salt_b64");
  const kemCiphertext = decodeBase64(
    recipient.kem.ciphertext_b64,
    "kem.ciphertext_b64",
  );
  const wrapNonce = decodeBase64(recipient.fek.nonce_b64, "fek.nonce_b64");
  const encryptedFek = decodeBase64(
    recipient.fek.encrypted_fek_b64,
    "fek.encrypted_fek_b64",
  );

  let kemSeed: Uint8Array;
  try {
    kemSeed = await argon2idAsync(password, salt, {
      t: recipient.kdf.time_cost,
      m: recipient.kdf.memory_cost_kib,
      p: recipient.kdf.parallelism,
      dkLen: recipient.kdf.derived_key_bytes,
    });
  } catch (error) {
    /* c8 ignore next */
    throw new SkvaError(
      "ERR_KDF_DERIVATION_FAILED",
      "Failed to derive recipient KDF key material.",
      { cause: error },
    );
  }

  let kemSharedSecret: Uint8Array;
  try {
    kemSharedSecret = ml_kem1024_p384.decapsulate(kemCiphertext, kemSeed);
  } catch (error) {
    kemSeed.fill(0); // Clear KEM seed from memory
    throw new SkvaError(
      "ERR_KEM_FAILED",
      "Failed to decapsulate recipient KEM ciphertext.",
      { cause: error },
    );
  }

  try {
    return chacha20poly1305(kemSharedSecret, wrapNonce).decrypt(encryptedFek);
  } catch (error) {
    throw new SkvaError(
      "ERR_FEK_UNWRAP_FAILED",
      "Failed to unwrap FEK for recipient.",
      { cause: error },
    );
  } finally {
    kemSeed.fill(0); // Clear KEM seed from memory
    kemSharedSecret.fill(0); // Clear KEM shared secret from memory
  }
}

/**
 * Attempts to unwrap the FEK for each recipient candidate and returns the first successful match.
 * Throws when no recipient entry can be unlocked with the provided password.
 */
export async function tryUnwrapFekFromRecipients(
  recipients: SkvaRecipientFekWrapper[],
  password: string,
  recipientId?: string,
): Promise<{ fek: Uint8Array; recipient_id: string }> {
  const candidates = recipientId
    ? recipients.filter((recipient) => recipient.recipient_id === recipientId)
    : recipients;

  for (const recipient of candidates) {
    try {
      const fek = await unwrapFekForRecipient(recipient, password);
      return { fek: fek, recipient_id: recipient.recipient_id };
    } catch {
      // Try next recipient entry.
    }
  }

  throw new SkvaError(
    "ERR_NO_RECIPIENT_MATCH",
    "No recipient entry could unwrap FEK with the provided password.",
  );
}
