/**
 * Converts bytes to a single-chunk readable stream.
 */
export function bytesToReadableStream(
  bytes: Uint8Array,
): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

/**
 * Collects all Uint8Array chunks from a stream into one byte array.
 */
export async function readableStreamToBytes(
  stream: ReadableStream<Uint8Array>,
): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total_bytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (!value || value.length === 0) {
        continue;
      }
      chunks.push(value);
      total_bytes += value.length;
    }
  } finally {
    reader.releaseLock();
  }

  const out_bytes = new Uint8Array(total_bytes);
  let byte_offset = 0;
  for (const chunk of chunks) {
    out_bytes.set(chunk, byte_offset);
    byte_offset += chunk.length;
  }
  return out_bytes;
}

/**
 * Creates a writable stream that appends chunks into an internal buffer.
 */
export function createBufferingWritable(): {
  writable: WritableStream<Uint8Array>;
  get_bytes: () => Uint8Array;
} {
  const chunks: Uint8Array[] = [];
  let total_bytes = 0;

  return {
    writable: new WritableStream<Uint8Array>({
      write(chunk) {
        chunks.push(chunk);
        total_bytes += chunk.length;
      },
    }),
    get_bytes() {
      const out_bytes = new Uint8Array(total_bytes);
      let byte_offset = 0;
      for (const chunk of chunks) {
        out_bytes.set(chunk, byte_offset);
        byte_offset += chunk.length;
      }
      return out_bytes;
    },
  };
}
