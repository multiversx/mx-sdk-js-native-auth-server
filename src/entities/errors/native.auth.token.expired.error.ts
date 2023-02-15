import { NativeAuthError } from "./native.auth.error";

export class NativeAuthTokenExpiredError extends NativeAuthError {
  constructor() {
    super('Token expired');
  }
}
