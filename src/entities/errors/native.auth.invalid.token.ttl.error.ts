import { NativeAuthError } from "./native.auth.error";

export class NativeAuthInvalidTokenTtlError extends NativeAuthError {
  constructor(currentTtl: number, maxTtl: number) {
    super(`The provided TTL in the token (${currentTtl}) is larger than the maximum allowed TTL (${maxTtl})`);
  }
}
