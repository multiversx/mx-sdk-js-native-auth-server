export class NativeAuthOriginNotAcceptedError extends Error {
  constructor() {
    super('Origin not accepted');
  }
}
