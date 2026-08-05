import { describe, expect, it } from "vitest";

import { SkvaError } from "../../../src/errors.js";
import { createByteReader } from "../../../src/stream/byte_reader.js";

function streamFromChunks(chunks: number[][]): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(new Uint8Array(chunk));
      }
      controller.close();
    },
  });
}

describe("stream/byte_reader", () => {
  it("closed forwards the underlying reader closed promise", async () => {
    const stream = streamFromChunks([[1]]);
    const raw_reader = stream.getReader();
    const reader = createByteReader(raw_reader);

    await raw_reader.cancel();
    await expect(reader.closed).resolves.toBeUndefined();
  });

  it("read returns pending bytes before touching underlying reader", async () => {
    const stream = streamFromChunks([[9, 8, 7]]);
    const reader = createByteReader(stream.getReader());

    const prefetched = await reader.readBytes(2);
    expect(prefetched).toEqual(new Uint8Array([9, 8]));

    const direct_read = await reader.read();
    expect(direct_read.done).toBe(false);
    expect(direct_read.value).toEqual(new Uint8Array([7]));
  });

  it("read marks stream as done when underlying reader is exhausted", async () => {
    const stream = streamFromChunks([]);
    const reader = createByteReader(stream.getReader());

    const direct_read = await reader.read();
    expect(direct_read.done).toBe(true);

    const follow_up = await reader.readBytes(1);
    expect(follow_up).toBeNull();
  });

  it("read returns non-done result from underlying reader when stream has data", async () => {
    const stream = streamFromChunks([[42]]);
    const reader = createByteReader(stream.getReader());

    const direct_read = await reader.read();
    expect(direct_read.done).toBe(false);
    expect(direct_read.value).toEqual(new Uint8Array([42]));
  });

  it("readBytes reads across chunk boundaries", async () => {
    const stream = streamFromChunks([[1, 2], [3], [4, 5]]);
    const reader = createByteReader(stream.getReader());

    const first = await reader.readBytes(4);
    expect(first).toEqual(new Uint8Array([1, 2, 3, 4]));

    const second = await reader.readBytes(1);
    expect(second).toEqual(new Uint8Array([5]));

    const third = await reader.readBytes(1);
    expect(third).toBeNull();
  });

  it("readBytes ignores empty chunks while buffering", async () => {
    const stream = streamFromChunks([[1], [], [2, 3]]);
    const reader = createByteReader(stream.getReader());

    const out = await reader.readBytes(3);
    expect(out).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("readBytes(0) returns empty bytes", async () => {
    const stream = streamFromChunks([[1, 2, 3]]);
    const reader = createByteReader(stream.getReader());

    const out = await reader.readBytes(0);
    expect(out).toEqual(new Uint8Array(0));
  });

  it("readBytes returns null when stream is already exhausted", async () => {
    const stream = streamFromChunks([]);
    const reader = createByteReader(stream.getReader());

    const out = await reader.readBytes(3);
    expect(out).toBeNull();
  });

  it("readBytes rejects invalid count", async () => {
    const stream = streamFromChunks([[1]]);
    const reader = createByteReader(stream.getReader());

    await expect(reader.readBytes(-1, "packet length")).rejects.toBeInstanceOf(SkvaError);

    try {
      await reader.readBytes(-1, "packet length");
      throw new Error("Expected readBytes to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_INVALID_ARGUMENT");
      expect(skva_error.message).toContain("packet length");
    }
  });

  it("readBytesExact throws ERR_STREAM_TRUNCATED when fewer bytes are available", async () => {
    const stream = streamFromChunks([[1, 2]]);
    const reader = createByteReader(stream.getReader());

    try {
      await reader.readBytesExact(3, "header");
      throw new Error("Expected readBytesExact to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_STREAM_TRUNCATED");
      expect(skva_error.message).toContain("header");
    }
  });

  it("readBytesExact truncation without label uses default message", async () => {
    const stream = streamFromChunks([[1, 2]]);
    const reader = createByteReader(stream.getReader());

    try {
      await reader.readBytesExact(3);
      throw new Error("Expected readBytesExact to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(SkvaError);
      const skva_error = error as SkvaError;
      expect(skva_error.code).toBe("ERR_STREAM_TRUNCATED");
      expect(skva_error.message).toContain("requested bytes");
    }
  });

  it("readBytesExact returns exact bytes when enough data is present", async () => {
    const stream = streamFromChunks([[4, 5, 6]]);
    const reader = createByteReader(stream.getReader());

    const out = await reader.readBytesExact(3, "payload");
    expect(out).toEqual(new Uint8Array([4, 5, 6]));
  });

  it("cancel clears pending bytes and forwards reason", async () => {
    const cancel_calls: unknown[] = [];
    const fake_reader = {
      closed: Promise.resolve(),
      async read(): Promise<ReadableStreamReadResult<Uint8Array>> {
        return { done: false, value: new Uint8Array([1, 2, 3]) };
      },
      async cancel(reason?: unknown): Promise<void> {
        cancel_calls.push(reason);
      },
      releaseLock(): void {
        // no-op in fake reader
      },
    } as unknown as ReadableStreamDefaultReader<Uint8Array>;

    const reader = createByteReader(fake_reader);
    await reader.readBytes(2);

    await reader.cancel("stop");
    expect(cancel_calls).toEqual(["stop"]);

    const out = await reader.readBytes(1);
    expect(out).toBeNull();
  });

  it("releaseLock delegates to underlying reader", () => {
    let release_lock_calls = 0;
    const fake_reader = {
      closed: Promise.resolve(),
      async read(): Promise<ReadableStreamReadResult<Uint8Array>> {
        return { done: true, value: undefined };
      },
      async cancel(): Promise<void> {
        // no-op in fake reader
      },
      releaseLock(): void {
        release_lock_calls += 1;
      },
    } as unknown as ReadableStreamDefaultReader<Uint8Array>;

    const reader = createByteReader(fake_reader);
    reader.releaseLock();

    expect(release_lock_calls).toBe(1);
  });
});
