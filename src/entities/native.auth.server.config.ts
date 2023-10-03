import { NativeAuthCacheInterface } from "../native.auth.cache.interface";

export class NativeAuthServerConfig {
  /** The endpoint from where the current block information will be fetched upon validation.
   * 
   * The default value points to the mainnet API, but can be overridden to be network-specific 
   * or to point to a self-hosted location */
  apiUrl?: string;

  /** A mandatory list of accepted origins in case the server component must validate the
   * incoming requests by domain.
   * 
   * At least one value must be provided */
  acceptedOrigins: string[] = [];

  /** An optional function that returns a boolean if the origin received as a parameter is accepted.
   * 
   * This is called only if the origin is not in the list of accepted origins defined in `acceptedOrigins` */
  isOriginAccepted?: (origin: string) => boolean | Promise<boolean>;

  /** Maximum allowed TTL from the token. Default: one day (86400 seconds) */
  maxExpirySeconds: number = 86400;

  /** An optional implementation of the caching interface used for resolving latest block
   * timestamp and also to validate and provide a block timestamp given a certain block hash.
   * 
   * It can be integrated with popular caching mechanisms such as redis */
  cache?: NativeAuthCacheInterface;

  skipLegacyValidation?: boolean;

  extraRequestHeaders?: { [key: string]: string };
}
