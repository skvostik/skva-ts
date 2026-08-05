import {
} from "../constants.js";
import { skvaAssert } from "../errors.js";

/**
 * Converts a number to 4-byte big-endian representation.
 */
export function uint32ToBe(value: number): Uint8Array {
  skvaAssert(Number.isInteger(value) && value >= 0 && value <= 0xffffffff, "ERR_INVALID_ARGUMENT", "Value must be uint32.");
  const out = new Uint8Array(4);
  out[0] = (value >>> 24) & 0xff;
  out[1] = (value >>> 16) & 0xff;
  out[2] = (value >>> 8) & 0xff;
  out[3] = value & 0xff;
  return out;
}

/**
 * Reads a 4-byte big-endian uint32.
 */
export function beToUint32(value: Uint8Array): number {
  skvaAssert(value.length === 4, "ERR_INVALID_ARGUMENT", "Expected 4 bytes for uint32.");
  return ((value[0] << 24) >>> 0) + ((value[1] << 16) >>> 0) + ((value[2] << 8) >>> 0) + value[3];
}

/**
 * Concatenates byte arrays.
 */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

