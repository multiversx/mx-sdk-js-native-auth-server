export class NativeAuthInvalidTokenError extends Error {
  constructor() {
    super('The provided token is not a NativeAuth token');
  }
}
