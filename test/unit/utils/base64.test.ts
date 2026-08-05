import { describe, expect, it } from "vitest";

import { SkvaError } from "../../../src/errors.js";
import { decodeBase64, encodeBase64 } from "../../../src/utils/base64.js";

describe("utils/base64", () => {
  it("encodes and decodes bytes as a round-trip", () => {
    const input = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);

    const encoded = encodeBase64(input);
    const decoded = decodeBase64(encoded);

    expect(decoded).toEqual(input);
  });

  it("decodes valid base64 without explicit padding", () => {
    expect(decodeBase64("AQI")).toEqual(new Uint8Array([1, 2]));
  });

  it("throws ERR_BASE64_INVALID for malformed base64", () => {
    try {
      decodeBase64("$$");
      throw new Error("Expected decodeBase64 to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_BASE64_INVALID");
    }
  });

  it("includes label in invalid base64 error message", () => {
    try {
      decodeBase64("$$", "recipient key");
      throw new Error("Expected decodeBase64 to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_BASE64_INVALID");
      expect(skva_error.message).toContain("recipient key");
    }
  });

  it("uses browser fallback path when Buffer is unavailable", () => {
    const original_buffer_descriptor = Object.getOwnPropertyDescriptor(globalThis, "Buffer");

    Object.defineProperty(globalThis, "Buffer", {
      configurable: true,
      writable: true,
      value: undefined,
    });

    try {
      expect(decodeBase64("AQI=")).toEqual(new Uint8Array([1, 2]));
    } finally {
      if (original_buffer_descriptor) {
        Object.defineProperty(globalThis, "Buffer", original_buffer_descriptor);
      } else {
        Reflect.deleteProperty(globalThis, "Buffer");
      }
    }
  });

  it("encodes using browser fallback path when Buffer is unavailable", () => {
    const original_buffer_descriptor = Object.getOwnPropertyDescriptor(globalThis, "Buffer");

    Object.defineProperty(globalThis, "Buffer", {
      configurable: true,
      writable: true,
      value: undefined,
    });

    try {
      expect(encodeBase64(new Uint8Array([1, 2]))).toBe("AQI=");
    } finally {
      if (original_buffer_descriptor) {
        Object.defineProperty(globalThis, "Buffer", original_buffer_descriptor);
      } else {
        Reflect.deleteProperty(globalThis, "Buffer");
      }
    }
  });

  it("wraps non-Skva browser decode failures as ERR_BASE64_INVALID", () => {
    const original_buffer_descriptor = Object.getOwnPropertyDescriptor(globalThis, "Buffer");
    const original_atob = globalThis.atob;

    Object.defineProperty(globalThis, "Buffer", {
      configurable: true,
      writable: true,
      value: undefined,
    });
    globalThis.atob = () => {
      throw new TypeError("bad base64");
    };

    try {
      expect(() => decodeBase64("AQI=")).toThrowError(SkvaError);

      try {
        decodeBase64("AQI=");
        throw new Error("Expected decodeBase64 to throw");
      } catch (error) {
        expect(error).toBeInstanceOf(SkvaError);
        const skva_error = error as SkvaError;
        expect(skva_error.code).toBe("ERR_BASE64_INVALID");
      }
    } finally {
      globalThis.atob = original_atob;
      if (original_buffer_descriptor) {
        Object.defineProperty(globalThis, "Buffer", original_buffer_descriptor);
      } else {
        Reflect.deleteProperty(globalThis, "Buffer");
      }
    }
  });

  it("rejects non-canonical browser decode output", () => {
    const original_buffer_descriptor = Object.getOwnPropertyDescriptor(globalThis, "Buffer");
    const original_atob = globalThis.atob;
    const original_btoa = globalThis.btoa;

    Object.defineProperty(globalThis, "Buffer", {
      configurable: true,
      writable: true,
      value: undefined,
    });
    globalThis.atob = () => "\x01\x02";
    globalThis.btoa = () => "DIFFERENT";

    try {
      expect(() => decodeBase64("AQI=")).toThrowError(SkvaError);
    } finally {
      globalThis.atob = original_atob;
      globalThis.btoa = original_btoa;
      if (original_buffer_descriptor) {
        Object.defineProperty(globalThis, "Buffer", original_buffer_descriptor);
      } else {
        Reflect.deleteProperty(globalThis, "Buffer");
      }
    }
  });
});
