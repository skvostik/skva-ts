export {
  skvaEncryptBytes,
  skvaDecryptBytes,
  skvaReadHeaderStream,
  skvaReadHeaderBytes,
} from "./api.js";

export { skvaGenerateRecipient, skvaFindRecipient } from "./recipient.js";

export { skvaEncryptStream } from "./encrypt.js";
export { skvaDecryptStream } from "./decrypt.js";

export { SkvaError } from "./errors.js";
export type { SkvaErrorCode } from "./errors.js";

export type {
  SkvaKdfHeader,
  SkvaKemHeader,
  SkvaFekHeader,
  SkvaPayloadHeader,
  SkvaRecipientFekWrapper,
  SkvaJsonHeader,
  SkvaBinaryHeader,
  SkvaRecipient,
  SkvaProgressCallback,
  SkvaEncryptOptions,
  SkvaDecryptOptions,
} from "./types.js";
