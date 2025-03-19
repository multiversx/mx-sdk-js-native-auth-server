export class NativeAuthSignature {
  constructor(private readonly signature: string) {}

  hex(): string {
    return this.signature;
  }
}
