import { NativeAuthError } from "./native.auth.error";

export class NativeAuthInvalidWildcardOriginError extends NativeAuthError {
  constructor() {
    super('Invalid wildcard origin');
  }
}
