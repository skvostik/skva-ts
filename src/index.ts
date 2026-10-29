export {
  skvaEncryptBytes,
  skvaDecryptStream,
  skvaDecryptBytes,
  skvaReadHeaderStream,
  skvaReadHeaderBytes,
} from "./api.js";

export { skvaGenerateRecipient, skvaFindRecipient } from "./recipient.js";

export { skvaEncryptStream } from "./encrypt.js";
export { skvaOpenDecryptStream } from "./decrypt.js";

export { SkvaError } from "./errors.js";
export type { SkvaErrorCode } from "./errors.js";

export type {
  SkvaKdfHeader,
  SkvaKemHeader,
  SkvaFekHeader,
  SkvaPayloadHeader,
  SkvaMetaEncryptedHeader,
  SkvaRecipientFekWrapper,
  SkvaJsonHeader,
  SkvaBinaryHeader,
  SkvaRecipient,
  SkvaProgressCallback,
  SkvaEncryptOptions,
  SkvaDecryptOptions,
  SkvaDecryptStream,
} from "./types.js";
