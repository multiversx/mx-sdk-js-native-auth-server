import { NativeAuthError } from "./native.auth.error";

export class NativeAuthInvalidConfigError extends NativeAuthError {
  constructor(message: string) {
    super(message);
  }
}
