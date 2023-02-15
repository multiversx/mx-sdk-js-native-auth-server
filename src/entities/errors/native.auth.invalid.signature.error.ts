import { NativeAuthError } from "./native.auth.error";

export class NativeAuthInvalidSignatureError extends NativeAuthError {
  constructor() {
    super('Invalid signature');
  }
}
