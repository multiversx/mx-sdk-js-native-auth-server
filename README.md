# Native Authenticator for JavaScript

Native Authenticator server-side component for JavaScript and TypeScript (written in TypeScript).

## Distribution

[npm](https://www.npmjs.com/package/@elrondnetwork/native-auth-server)

## Example

```js
const server = new NativeAuthServer();
const result = await server.validate(accessToken);
```


### Config

```js
{
  // The endpoint from where the current block information will be fetched upon validation.
  // The default value points to the mainnet API, but can be overridden to be network-specific
  // or to point to a self-hosted location
  apiUrl: string = 'https://api.elrond.com';
  
  // An optional list of accepted hosts in case the server component must validate the incoming requests
  // by domain
  acceptedHosts: string[] = [];

  // Maximum allowed TTL from the token.
  // Default: one day (86400 seconds)
  maxExpirySeconds: number = 86400;

  // An optional implementation of the caching interface used for resolving 
  // latest block timestamp and also to validate and provide a block timestamp given a certain block hash.
  // It can be integrated with popular caching mechanisms such as redis
  cache?: NativeAuthCacheInterface;
}
```
