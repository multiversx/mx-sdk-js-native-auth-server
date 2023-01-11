import { ISignature } from "@multiversx/sdk-core";

export class NativeAuthSignature implements ISignature {
  constructor(private readonly signature: string) { }

  hex(): string {
    return this.signature;
  }
}
