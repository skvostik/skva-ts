import { describe, expect, it } from "vitest";

import {
  bytesToReadableStream,
  createBufferingWritable,
  readableStreamToBytes,
} from "../../../src/stream/adapters.js";

describe("stream/adapters", () => {
  it("bytesToReadableStream emits one chunk and then closes", async () => {
    const input = new Uint8Array([1, 2, 3]);
    const reader = bytesToReadableStream(input).getReader();

    const first = await reader.read();
    expect(first.done).toBe(false);
    expect(first.value).toEqual(input);

    const second = await reader.read();
    expect(second.done).toBe(true);
  });

  it("readableStreamToBytes concatenates chunks in order", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([10, 11]));
        controller.enqueue(new Uint8Array([12]));
        controller.enqueue(new Uint8Array([13, 14]));
        controller.close();
      },
    });

    const out = await readableStreamToBytes(stream);
    expect(out).toEqual(new Uint8Array([10, 11, 12, 13, 14]));
  });

  it("readableStreamToBytes ignores empty chunks", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([7]));
        controller.enqueue(new Uint8Array([]));
        controller.enqueue(new Uint8Array([8, 9]));
        controller.close();
      },
    });

    const out = await readableStreamToBytes(stream);
    expect(out).toEqual(new Uint8Array([7, 8, 9]));
  });

  it("createBufferingWritable stores all writes and returns merged bytes", async () => {
    const { writable, get_bytes } = createBufferingWritable();
    const writer = writable.getWriter();

    await writer.write(new Uint8Array([1, 2]));
    await writer.write(new Uint8Array([3]));
    await writer.close();

    expect(get_bytes()).toEqual(new Uint8Array([1, 2, 3]));
  });
});
