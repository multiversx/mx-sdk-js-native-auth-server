import { NativeAuthError } from "./native.auth.error";

export class NativeAuthInvalidImpersonateError extends NativeAuthError {
  constructor() {
    super('Invalid impersonate');
  }
}
