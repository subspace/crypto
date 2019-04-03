import {cleartext, key, message, Signature, VerifiedMessage} from "openpgp";

/**
 * Minimal set of types used in this library, doesn't cover the whole openpgp
 */
declare module 'openpgp' {
  export interface VerifySignatureOptions {
    message: cleartext.CleartextMessage | message.Message,
    signature: Signature,
    publicKeys: Array<key.Key>
  }

  export interface SignOptions {
    message: cleartext.CleartextMessage | message.Message,
    privateKeys: Array<key.Key>,
    detached: boolean
  }

  export interface SignResult {
    signature: string
  }

  export function sign(options: SignOptions): Promise<SignResult>;
  export function verify(options: VerifySignatureOptions): Promise<VerifiedMessage>;
  export namespace signature {
    function readArmored(armoredText: string): Signature
  }
  namespace message {
    function fromBinary(bytes: Uint8Array): message.Message;
  }
}
