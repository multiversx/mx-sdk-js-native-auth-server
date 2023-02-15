import { NativeAuthError } from "./native.auth.error";

export class NativeAuthInvalidTokenError extends NativeAuthError {
  constructor() {
    super('The provided token is not a NativeAuth token');
  }
}
