import { NativeAuthCacheInterface } from "../native.auth.cache.interface";

export class NativeAuthServerConfig {
  apiUrl?: string;
  acceptedOrigins: string[] = [];
  isOriginAccepted?: (origin: string) => boolean | Promise<boolean>;
  maxExpirySeconds: number = 86400;
  cache?: NativeAuthCacheInterface;
  skipLegacyValidation?: boolean;
  extraRequestHeaders?: { [key: string]: string };
}
