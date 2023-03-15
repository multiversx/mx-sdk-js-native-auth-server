import { NativeAuthCacheInterface } from "../native.auth.cache.interface";

export class NativeAuthServerConfig {
  apiUrl?: string;
  acceptedOrigins: string[] = [];
  maxExpirySeconds: number = 86400;
  cache?: NativeAuthCacheInterface;
  skipLegacyValidation?: boolean;
  extraRequestHeaders?: { [key: string]: string };
}
