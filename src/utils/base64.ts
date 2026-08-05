import { SkvaError } from "../errors.js";

/**
 * Encodes bytes using RFC 4648 Base64.
 * Output is canonical Base64 with no embedded whitespace.
 */
export function encodeBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }

  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/**
 * Decodes RFC 4648 Base64 and throws SKVA-typed errors on malformed input.
 */
export function decodeBase64(value: string, label?: string): Uint8Array {
  try {
    if (typeof Buffer !== "undefined") {
      return decodeBase64WithBuffer(value, label);
    }

    return decodeBase64WithBrowser(value, label);
  } catch (error) {
    if (error instanceof SkvaError) {
      throw error;
    }

    throw invalidBase64Error(label);
  }
}

// Node runtime path: Buffer exists and is the most direct byte-safe decoder.
function decodeBase64WithBuffer(value: string, label?: string): Uint8Array {
  const bytes = Uint8Array.from(Buffer.from(value, "base64"));
  const normalized = Buffer.from(bytes).toString("base64");
  const withPadding = normalizeBase64(value);
  if (normalized !== withPadding) {
    throw invalidBase64Error(label);
  }
  return bytes;
}

// Browser runtime path: atob/btoa is used when Buffer is unavailable.
function decodeBase64WithBrowser(value: string, label?: string): Uint8Array {
  const withPadding = normalizeBase64(value);
  const binary = atob(withPadding);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }

  const normalized = btoa(binary);
  if (normalized !== withPadding) {
    throw invalidBase64Error(label);
  }

  return out;
}

function invalidBase64Error(label?: string): SkvaError {
  return new SkvaError("ERR_BASE64_INVALID", `Invalid base64${label ? ` for ${label}` : ""}.`);
}

function normalizeBase64(input: string): string {
  const remainder = input.length % 4;
  if (remainder === 0) {
    return input;
  }

  return `${input}${"=".repeat(4 - remainder)}`;
}
