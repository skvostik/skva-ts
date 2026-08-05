import { SkvaError, skvaAssert } from "../errors.js";

/**
 * Reader that supports exact-byte reads from a Uint8Array stream.
 */
export type ByteReader = ReadableStreamDefaultReader<Uint8Array> & {
  readBytes: (count: number, label?: string) => Promise<Uint8Array | null>;
  readBytesExact: (count: number, label?: string) => Promise<Uint8Array>;
};

class BufferedByteReader implements ByteReader {
  private pending_bytes = new Uint8Array(0) as Uint8Array<ArrayBufferLike>;
  private stream_done = false;

  constructor(
    private readonly reader: ReadableStreamDefaultReader<Uint8Array>,
  ) {}

  get closed(): Promise<void> {
    return this.reader.closed;
  }

  async read(): Promise<ReadableStreamReadResult<Uint8Array>> {
    if (this.pending_bytes.length > 0) {
      const out_bytes = this.pending_bytes;
      this.pending_bytes = new Uint8Array(0);
      return { done: false, value: out_bytes };
    }

    const result = await this.reader.read();
    if (result.done) {
      this.stream_done = true;
    }
    return result;
  }

  async readBytes(count: number, label?: string): Promise<Uint8Array | null> {
    skvaAssert(
      Number.isInteger(count) && count >= 0,
      "ERR_INVALID_ARGUMENT",
      `readBytes(count) requires a non-negative integer${label ? ` for ${label}` : ""}.`,
    );
    if (count === 0) {
      return new Uint8Array(0);
    }

    while (this.pending_bytes.length < count && !this.stream_done) {
      const result = await this.reader.read();
      if (result.done) {
        this.stream_done = true;
        break;
      }

      this.appendPendingBytes(result.value);
    }

    if (this.pending_bytes.length === 0 && this.stream_done) {
      return null;
    }

    const take_count = Math.min(count, this.pending_bytes.length);
    const out_bytes = this.pending_bytes.slice(0, take_count);
    this.pending_bytes = this.pending_bytes.slice(take_count);
    return out_bytes;
  }

  async readBytesExact(count: number, label?: string): Promise<Uint8Array> {
    const chunk = await this.readBytes(count, label);
    if (chunk === null || chunk.length < count) {
      throw new SkvaError(
        "ERR_STREAM_TRUNCATED",
        `Stream ended before ${label ? label : "requested bytes"} could be fully read.`,
      );
    }
    return chunk;
  }

  cancel(reason?: unknown): Promise<void> {
    this.pending_bytes = new Uint8Array(0);
    this.stream_done = true;
    return this.reader.cancel(reason);
  }

  releaseLock(): void {
    this.reader.releaseLock();
  }

  private appendPendingBytes(chunk: Uint8Array): void {
    if (chunk.length === 0) {
      return;
    }

    if (this.pending_bytes.length === 0) {
      this.pending_bytes = chunk;
      return;
    }

    const merged_bytes = new Uint8Array(this.pending_bytes.length + chunk.length);
    merged_bytes.set(this.pending_bytes, 0);
    merged_bytes.set(chunk, this.pending_bytes.length);
    this.pending_bytes = merged_bytes;
  }
}

/**
 * Wraps a stream reader and provides buffered exact-byte reads.
 */
export function createByteReader(
  reader: ReadableStreamDefaultReader<Uint8Array>,
): ByteReader {
  return new BufferedByteReader(reader);
}
