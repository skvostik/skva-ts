export const SKVA_MAGIC = "SKVA";
export const SKVA_VERSION = 1;
export const SKVA_HEADER_PREFIX_BYTES = SKVA_MAGIC.length + 1 + 4;
export const SKVA_NONCE_BYTES = 12;
export const SKVA_TAG_BYTES = 16;
export const SKVA_FEK_BYTES = 32;
export const SKVA_NONCE_COUNTER_BYTES = 11;
export const SKVA_MAX_CHUNKS = 2n ** BigInt(SKVA_NONCE_COUNTER_BYTES * 8);
export const SKVA_CHACHA20POLY1305_MAX_PLAINTEXT_BYTES = (2 ** 32 - 1) * 64;
export const SKVA_CHACHA20POLY1305_MAX_ENCRYPTED_CHUNK_BYTES = SKVA_CHACHA20POLY1305_MAX_PLAINTEXT_BYTES + SKVA_TAG_BYTES;

export const SKVA_KDF_NAME = "argon2id";
export const SKVA_KEM_NAME = "ml_kem1024_p384";
export const SKVA_CIPHER_NAME = "chacha20poly1305";

export const SKVA_DEFAULT_KDF_TIME_COST_ITERATIONS = 3;
export const SKVA_DEFAULT_KDF_MEMORY_COST_KIB = 64 * 1024;
export const SKVA_DEFAULT_KDF_PARALLELISM = 1;
export const SKVA_DEFAULT_KDF_DERIVED_KEY_LENGTH_BYTES = 32;
export const SKVA_DEFAULT_KDF_SALT_BYTES = 16;
export const SKVA_DEFAULT_PLAINTEXT_CHUNK_SIZE_BYTES = 64 * 1024;

export const SKVA_RECOVERY_NOTE = {
  algorithm:
    "Basic file format: magic + version + header length + UTF-8 JSON header + header extension length + header extension bytes + encrypted chunks. " +
    "For each recipient entry: run Argon2id with recorded parameters and that entry's password to recover the deterministic ML-KEM private seed, " +
    "derive the recipient private key, use ML-KEM decapsulation to recover a shared secret, unwrap FEK with chacha20poly1305 using that shared secret, " +
    "then decrypt chunks sequentially.",
  chunk_nonce_format: "uint88_be(chunk_index) || eof_flag_u8",
  chunk_encrypted:
    "chacha20poly1305(FEK, nonce_i, aad=empty).encrypt(plaintext_chunk)",
  fek_encrypted:
    "chacha20poly1305(kem.shared_secret, fek_nonce, aad=empty).encrypt(FEK)",
} as const;
