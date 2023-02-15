import { NativeAuthError } from "./native.auth.error";

export class NativeAuthInvalidBlockHashError extends NativeAuthError {
  constructor() {
    super('Invalid block hash');
  }
}
