export class NativeAuthInvalidTokenTtlError extends Error {
  constructor(currentTtl: number, maxTtl: number) {
    super(`The provided TTL in the token (${currentTtl}) is larger than the maximum allowed TTL (${maxTtl})`);
  }
}
