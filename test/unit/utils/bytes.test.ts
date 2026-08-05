import { describe, expect, it } from "vitest";

import { SkvaError } from "../../../src/errors.js";
import { beToUint32, concatBytes, uint32ToBe } from "../../../src/utils/bytes.js";

describe("utils/bytes", () => {
  it("uint32ToBe converts number to big-endian bytes", () => {
    expect(uint32ToBe(0x12345678)).toEqual(new Uint8Array([0x12, 0x34, 0x56, 0x78]));
  });

  it("beToUint32 converts big-endian bytes back to number", () => {
    expect(beToUint32(new Uint8Array([0x12, 0x34, 0x56, 0x78]))).toBe(0x12345678);
  });

  it("uint32 conversion round-trips boundary values", () => {
    const values = [0, 0xffffffff];

    for (const value of values) {
      expect(beToUint32(uint32ToBe(value))).toBe(value);
    }
  });

  it("uint32ToBe throws ERR_INVALID_ARGUMENT for out-of-range values", () => {
    const invalid_values = [-1, 1.5, 0x1_0000_0000];

    for (const value of invalid_values) {
      try {
        uint32ToBe(value);
        throw new Error("Expected uint32ToBe to throw");
      } catch (error) {
        expect(error).toBeInstanceOf(SkvaError);
        const skva_error = error as SkvaError;
        expect(skva_error.code).toBe("ERR_INVALID_ARGUMENT");
      }
    }
  });

  it("beToUint32 throws ERR_INVALID_ARGUMENT for non-4-byte input", () => {
    try {
      beToUint32(new Uint8Array([1, 2, 3]));
      throw new Error("Expected beToUint32 to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_INVALID_ARGUMENT");
    }
  });

  it("concatBytes merges arrays in input order", () => {
    const out = concatBytes(
      new Uint8Array([1, 2]),
      new Uint8Array([]),
      new Uint8Array([3]),
      new Uint8Array([4, 5]),
    );

    expect(out).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
  });
});
