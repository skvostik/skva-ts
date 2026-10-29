# @skvostik/skva

TypeScript library for the [.skva format](./SKVA_FORMAT.md): a stream-based encrypted backup archive.

## Features

- Strict SKVA v1 header parsing and validation.
- Stream-based encryption and decryption with chunked payload processing.
- Multi-recipient support with password-based recipient selection.
- Password-based recipient recovery is deterministic from the stored KDF parameters and password, while recipient generation uses a fresh random salt per call.
- Typed errors for parsing, validation, and cryptographic failures.

## Public API

The supported public contract is exposed from the package entrypoint. Each function below is meant for a specific integration path, and the brief descriptions should make it easier to choose the right one.

### skvaEncryptStream
Encrypts a plaintext stream and writes the SKVA payload to an output stream. Use this when you want to process large inputs without buffering them in memory.

```ts
skvaEncryptStream(
  input: ReadableStream<Uint8Array>,
  output: WritableStream<Uint8Array>,
  options: SkvaEncryptOptions,
): Promise<{ json_header: SkvaJsonHeader; binary_header: SkvaBinaryHeader; fek?: Uint8Array }>
```

`fek` is returned only when you set `return_fek: true` in the options; by default the key is zeroed and never leaves the function. It is a copy of the randomly generated 32-byte file encryption key. Use it if you need to wrap the key in your own envelope, for example to store it in a database. It decrypts the payload on its own without any password, so treat it as a secret and zero it (`fek.fill(0)`) when you are done.

### skvaDecryptStream
Decrypts a SKVA stream and writes the recovered plaintext to an output stream. This is the stream-based counterpart to byte decryption.

```ts
skvaDecryptStream(
  input: ReadableStream<Uint8Array>,
  output: WritableStream<Uint8Array>,
  options: SkvaDecryptOptions,
): Promise<{
  json_header: SkvaJsonHeader;
  binary_header: SkvaBinaryHeader;
  meta_encrypted?: Record<string, unknown>;
  meta_encrypted_error?: SkvaError;
}>
```

When the header contains `meta_encrypted`, the decrypted metadata object is returned as `meta_encrypted`. If it is malformed or fails authentication, `meta_encrypted_error` is returned instead, and the payload is still decrypted.

### skvaEncryptBytes
Encrypts an in-memory plaintext buffer and returns the encoded SKVA bytes plus the parsed headers. This is the simplest option for small to medium payloads.

```ts
skvaEncryptBytes(
  plaintext: Uint8Array,
  options: SkvaEncryptOptions,
): Promise<{ bytes: Uint8Array; json_header: SkvaJsonHeader; binary_header: SkvaBinaryHeader; fek?: Uint8Array }>
```

### skvaDecryptBytes
Decrypts an in-memory SKVA byte buffer and returns the recovered plaintext plus the parsed headers.

```ts
skvaDecryptBytes(
  skva_bytes: Uint8Array,
  options: SkvaDecryptOptions,
): Promise<{
  bytes: Uint8Array;
  json_header: SkvaJsonHeader;
  binary_header: SkvaBinaryHeader;
  meta_encrypted?: Record<string, unknown>;
  meta_encrypted_error?: SkvaError;
}>
```

### skvaReadHeaderStream
Parses the SKVA binary header and JSON metadata from a stream without decrypting the payload. Use this when you only need recipient or metadata information.

```ts
skvaReadHeaderStream(
  stream: ReadableStream<Uint8Array>,
): Promise<{ json_header: SkvaJsonHeader; binary_header: SkvaBinaryHeader }>
```

### skvaReadHeaderBytes
Parses the SKVA header from in-memory bytes without decrypting the payload.

```ts
skvaReadHeaderBytes(
  skva_bytes: Uint8Array,
): Promise<{ json_header: SkvaJsonHeader; binary_header: SkvaBinaryHeader }>
```

### skvaOpenDecryptStream
Reads the header, unlocks it and decrypts `meta_encrypted`, without touching the payload. Use it when you need the metadata, such as the original filename, before choosing the output. Throws on a wrong password or an invalid header.

```ts
skvaOpenDecryptStream(
  input: ReadableStream<Uint8Array>,
  options: SkvaDecryptOptions,
): Promise<SkvaDecryptStream>
```

### skvaGenerateRecipient
Creates a recipient descriptor from a password and an optional recipient ID. The returned value can be passed directly into encryption options.
Each call generates a fresh random KDF salt, so generated recipient material is intentionally different across calls.

```ts
skvaGenerateRecipient(
  password: string,
  recipient_id?: string,
  kdf_options?: Partial<Omit<SkvaKdfHeader, "algorithm" | "salt_b64">>,
): Promise<SkvaRecipient>
```

### skvaFindRecipient
Tries to determine which recipient entry can be unlocked with the provided password and returns its recipient ID, or `null` if none match.

```ts
skvaFindRecipient(
  recipients: SkvaRecipientFekWrapper[],
  password: string,
): Promise<string | null>
```

The most commonly used exported types are `SkvaKdfHeader`, `SkvaRecipient`, `SkvaJsonHeader`, `SkvaBinaryHeader`, `SkvaEncryptOptions`, `SkvaDecryptOptions`, `SkvaDecryptStream`, and `SkvaError`.

## Core options

Encryption accepts one or more recipients and writes the wrapped FEK information into the header:

```ts
interface SkvaEncryptOptions {
  recipients: SkvaRecipient[];
  meta?: Record<string, unknown>;
  meta_encrypted?: Record<string, unknown>;
  plaintext_chunk_bytes?: number;
  header_extension_bytes?: Uint8Array;
  return_fek?: boolean;
  on_progress?: (processedBytes: number) => void;
}
```

`meta` is stored in the header as plaintext. `meta_encrypted` is stored encrypted, so only recipients can read it, which makes it the place for values like the original filename. It is padded to a multiple of 64 bytes to hide its exact length. Anyone who has a recipient's public key can create a file with any `meta_encrypted`, so treat decrypted values such as filenames as untrusted input.

Decryption takes either `password` or `fek`. With a password, recipients are tried in order until one matches, or only the selected recipient when `recipient_id` is provided. With `fek`, for example one returned by `return_fek`, no password is needed:

```ts
type SkvaDecryptOptions = {
  on_progress?: (processedBytes: number) => void;
} & (
  | { password: string; recipient_id?: string; fek?: never }
  | { fek: Uint8Array; password?: never; recipient_id?: never }
);
```

## Key types

### SkvaKdfHeader

Argon2id parameters used to derive the KEM seed and recover the FEK for a recipient:

```ts
interface SkvaKdfHeader {
  algorithm: "argon2id";
  salt_b64: string;
  time_cost: number;
  memory_cost_kib: number;
  parallelism: number;
  derived_key_bytes: number;
}
```

### SkvaRecipient

A recipient descriptor that can be used during encryption:

```ts
interface SkvaRecipient {
  recipient_id?: string;
  public_key: Uint8Array;
  kdf: SkvaKdfHeader;
}
```

### SkvaJsonHeader

The decoded JSON header stored in the SKVA wire format:

```ts
interface SkvaJsonHeader {
  format: "skva";
  version: 1;
  recovery_note?: unknown;
  recipients: SkvaRecipientFekWrapper[];
  payload: SkvaPayloadHeader;
  meta?: Record<string, unknown>;
  meta_encrypted?: SkvaMetaEncryptedHeader;
}

interface SkvaMetaEncryptedHeader {
  algorithm: "chacha20poly1305";
  key_derivation: "hkdf_sha256";
  ciphertext_b64: string;
}
```

### SkvaBinaryHeader

The binary prefix and length information parsed from the SKVA stream:

```ts
interface SkvaBinaryHeader {
  magic: "SKVA";
  version: number;
  header_length: number;
  header_bytes: Uint8Array;
  header_extension_length: number;
  header_extension_bytes: Uint8Array;
}
```

### SkvaDecryptStream

Returned by `skvaOpenDecryptStream`. `decrypt_payload` can be called once. `close` zeroes the FEK and releases the input; always call it.

```ts
interface SkvaDecryptStream {
  json_header: SkvaJsonHeader;
  binary_header: SkvaBinaryHeader;
  meta_encrypted?: Record<string, unknown>;
  meta_encrypted_error?: SkvaError;
  decrypt_payload(output: WritableStream<Uint8Array>): Promise<void>;
  close(): Promise<void>;
}
```

### SkvaError

Typed errors are surfaced through `SkvaError` and the `code` field:

```ts
class SkvaError extends Error {
  readonly code: SkvaErrorCode;
}
```

## Quick example

```ts
import {
  skvaGenerateRecipient,
  skvaEncryptBytes,
  skvaDecryptBytes,
} from "@skvostik/skva";

const password = "correct horse battery staple";
const recipient = await skvaGenerateRecipient(password, "primary");

const plaintext = new TextEncoder().encode("hello SKVA");
const encrypted = await skvaEncryptBytes(plaintext, {
  recipients: [recipient],
  plaintext_chunk_bytes: 64 * 1024,
});

const decrypted = await skvaDecryptBytes(encrypted.bytes, {
  password,
  recipient_id: "primary",
});

console.log(decrypted.bytes);
```

## Stream example

```ts
import { createReadStream, createWriteStream } from "node:fs";
import { Readable, Writable } from "node:stream";
import {
  skvaGenerateRecipient,
  skvaEncryptStream,
  skvaDecryptStream,
} from "@skvostik/skva";

const password = "correct horse battery staple";
const recipient = await skvaGenerateRecipient(password, "primary");

const input = Readable.toWeb(createReadStream("./input.bin")) as ReadableStream<Uint8Array>;
const output = Writable.toWeb(createWriteStream("./output.skva")) as WritableStream<Uint8Array>;

await skvaEncryptStream(input, output, {
  recipients: [recipient],
  plaintext_chunk_bytes: 256 * 1024,
});
```

## Header-only parse

Use this when you only need metadata or recipient information without decrypting the payload:

```ts
import { skvaReadHeaderBytes } from "@skvostik/skva";

const { json_header } = await skvaReadHeaderBytes(skva_bytes);
console.log(json_header.recipients.length);
console.log(json_header.payload.plaintext_chunk_bytes);
```

## Decrypt the header first, then the payload

```ts
import { skvaOpenDecryptStream } from "@skvostik/skva";

// reads header and verifies password, throws on invalid password or parse error
const skva_stream = await skvaOpenDecryptStream(input, { password });

try {
  const sanitized_filename = sanitize_filename(skva_stream.meta_encrypted?.original_filename);
  const output = Writable.toWeb(createWriteStream(sanitized_filename)) as WritableStream<Uint8Array>;
  await skva_stream.decrypt_payload(output);
} finally {
  await skva_stream.close();
}
```
