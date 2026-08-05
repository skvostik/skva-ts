import {
  SKVA_HEADER_PREFIX_BYTES,
  SKVA_MAGIC,
  SKVA_VERSION,
} from "../constants.js";
import { SkvaError, skvaAssert } from "../errors.js";
import type { SkvaBinaryHeader, SkvaJsonHeader } from "../types.js";
import { beToUint32, concatBytes, uint32ToBe } from "../utils/bytes.js";
import { createByteReader } from "../stream/byte_reader.js";
import { parseSkvaJsonHeaderBytes } from "./json_header.js";

/**
 * Reads and validates the SKVA wire prefix and JSON header.
 */
export async function parseSkvaBinaryHeaderStream(
  stream: ReadableStream<Uint8Array>,
): Promise<{
  json_header: SkvaJsonHeader;
  binary_header: SkvaBinaryHeader;
  reader: ReturnType<typeof createByteReader>;
}> {
  const reader = createByteReader(stream.getReader());
  const prefix = await reader.readBytesExact(
    SKVA_HEADER_PREFIX_BYTES,
    "SKVA wire prefix",
  );

  const magic_length = SKVA_MAGIC.length;
  const magic = new TextDecoder().decode(prefix.slice(0, magic_length));
  if (magic !== SKVA_MAGIC) {
    throw new SkvaError("ERR_MAGIC_MISMATCH", "SKVA magic mismatch.");
  }

  const version = prefix[magic_length];
  if (version !== SKVA_VERSION) {
    throw new SkvaError(
      "ERR_UNSUPPORTED_VERSION",
      `Unsupported SKVA version ${version}.`,
    );
  }

  const header_length_offset = magic_length + 1;
  const header_length = beToUint32(
    prefix.slice(header_length_offset, header_length_offset + 4),
  );
  const header_bytes = await reader.readBytesExact(
    header_length,
    "SKVA header bytes",
  );
  const header_extension_length_bytes = await reader.readBytesExact(
    4,
    "SKVA header_extension_length",
  );
  const header_extension_length = beToUint32(header_extension_length_bytes);
  const header_extension_bytes = await reader.readBytesExact(
    header_extension_length,
    "SKVA header_extension bytes",
  );

  const json_header = parseSkvaJsonHeaderBytes(header_bytes);
  const binary_header: SkvaBinaryHeader = {
    magic: SKVA_MAGIC,
    version,
    header_length,
    header_bytes,
    header_extension_length,
    header_extension_bytes,
  };

  return {
    json_header,
    binary_header,
    reader,
  };
}

export function buildSkvaBinaryHeader(
  json_header_bytes: Uint8Array,
  header_extension_bytes: Uint8Array,
): SkvaBinaryHeader {
  return {
    magic: SKVA_MAGIC,
    version: SKVA_VERSION,
    header_length: json_header_bytes.length,
    header_bytes: json_header_bytes,
    header_extension_length: header_extension_bytes.length,
    header_extension_bytes,
  };
}

/**
 * Encodes the SKVA binary header bytes.
 */
export function serializeSkvaBinaryHeaderBytes(
  binary_header: SkvaBinaryHeader,
): Uint8Array {
  skvaAssert(
    binary_header.header_length <= 0xffffffff,
    "ERR_HEADER_LENGTH_INVALID",
    "Header bytes exceed uint32 capacity.",
  );

  skvaAssert(
    binary_header.header_extension_length <= 0xffffffff,
    "ERR_HEADER_LENGTH_INVALID",
    "Header extension bytes exceed uint32 capacity.",
  );

  return concatBytes(
    new TextEncoder().encode(binary_header.magic),
    new Uint8Array([binary_header.version]),
    uint32ToBe(binary_header.header_length),
    binary_header.header_bytes,
    uint32ToBe(binary_header.header_extension_length),
    binary_header.header_extension_bytes,
  );
}
