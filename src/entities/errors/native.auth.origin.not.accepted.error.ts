import { NativeAuthError } from "./native.auth.error";

export class NativeAuthOriginNotAcceptedError extends NativeAuthError {
  constructor() {
    super('Origin not accepted');
  }
}
