import { NativeAuthCacheInterface } from "../native.auth.cache.interface";

export class NativeAuthServerConfig {
  apiUrl: string = 'https://api.elrond.com';
  maxExpirySeconds: number = 86400;
  cache?: NativeAuthCacheInterface;
}
