import axios from "axios";
import { RequestHandler } from "axios-mock-adapter";
import { NativeAuthInvalidBlockHashError } from "../src/entities/errors/native.auth.invalid.block.hash.error";
import { NativeAuthInvalidSignatureError } from "../src/entities/errors/native.auth.invalid.signature.error";
import { NativeAuthTokenExpiredError } from "../src/entities/errors/native.auth.token.expired.error";
import { NativeAuthDecoded } from "../src/entities/native.auth.decoded";
import { NativeAuthResult } from "../src/entities/native.auth.validate.result";
import { NativeAuthInvalidConfigError, NativeAuthInvalidTokenError, NativeAuthInvalidTokenTtlError, NativeAuthServer, NativeAuthServerConfig } from '../src';
import { NativeAuthOriginNotAcceptedError } from "../src/entities/errors/native.auth.origin.not.accepted.error";
import MockAdapter = require("axios-mock-adapter");
import { NativeAuthInvalidImpersonateError } from "../src/entities/errors/native.auth.invalid.impersonate.error";
import { NativeAuthInvalidWildcardOriginError } from "../src/entities/errors/native.auth.invalid.wildcard.origin.error";

describe("Native Auth", () => {
  let mock: MockAdapter;
  const ADDRESS = 'erd1qnk2vmuqywfqtdnkmauvpm8ls0xh00k8xeupuaf6cm6cd4rx89qqz0ppgl';
  const SIGNATURE = '906e79d54e69e688680abee54ec0c49ce2561eb5abfd01865b31cb3ed738272c7cfc4fc8cc1c3590dd5757e622639b01a510945d7f7c9d1ceda20a50a817080d';
  const BLOCK_HASH = 'ab459013b27fdc6fe98eed567bd0c1754e0628a4cc16883bf0170a29da37ad46';
  const TTL = 86400;
  const TOKEN = `aHR0cHM6Ly9hcGkubXVsdGl2ZXJzeC5jb20.${BLOCK_HASH}.${TTL}.e30`;
  const ACCESS_TOKEN = `ZXJkMXFuazJ2bXVxeXdmcXRkbmttYXV2cG04bHMweGgwMGs4eGV1cHVhZjZjbTZjZDRyeDg5cXF6MHBwZ2w.YUhSMGNITTZMeTloY0drdWJYVnNkR2wyWlhKemVDNWpiMjAuYWI0NTkwMTNiMjdmZGM2ZmU5OGVlZDU2N2JkMGMxNzU0ZTA2MjhhNGNjMTY4ODNiZjAxNzBhMjlkYTM3YWQ0Ni44NjQwMC5lMzA.906e79d54e69e688680abee54ec0c49ce2561eb5abfd01865b31cb3ed738272c7cfc4fc8cc1c3590dd5757e622639b01a510945d7f7c9d1ceda20a50a817080d`;
  const BLOCK_TIMESTAMP = 1671009408;
  const ORIGIN = 'https://api.multiversx.com';

  const MULTISIG_ACCESS_TOKEN = 'ZXJkMXFuazJ2bXVxeXdmcXRkbmttYXV2cG04bHMweGgwMGs4eGV1cHVhZjZjbTZjZDRyeDg5cXF6MHBwZ2w.YUhSMGNITTZMeTloY0drdWJYVnNkR2wyWlhKemVDNWpiMjAuYWI0NTkwMTNiMjdmZGM2ZmU5OGVlZDU2N2JkMGMxNzU0ZTA2MjhhNGNjMTY4ODNiZjAxNzBhMjlkYTM3YWQ0Ni44NjQwMC5leUp0ZFd4MGFYTnBaeUk2SW1WeVpERnhjWEZ4Y1hGeGNYRnhjWEZ4Y0dkeE9UUTBhRGRvTm0xamEzYzJjVEJrTTJjeU1qTmphbm8wZVhSMmEyVnVPRFoxTURCemVqZGpZWEozSW4w.b38b3766de5fcc9f66b1bb65662404238b1eddad18436bea39a694db591dc27bc2a66c62c4dfec3ce09021de83d324cd5f4e49a329833c67baafdd71ab2f750b';
  const IMPERSONATE_ACCESS_TOKEN = 'ZXJkMXFuazJ2bXVxeXdmcXRkbmttYXV2cG04bHMweGgwMGs4eGV1cHVhZjZjbTZjZDRyeDg5cXF6MHBwZ2w.YUhSMGNITTZMeTloY0drdWJYVnNkR2wyWlhKemVDNWpiMjAuYWI0NTkwMTNiMjdmZGM2ZmU5OGVlZDU2N2JkMGMxNzU0ZTA2MjhhNGNjMTY4ODNiZjAxNzBhMjlkYTM3YWQ0Ni44NjQwMC5leUpwYlhCbGNuTnZibUYwWlNJNkltVnlaREZ4Y1hGeGNYRnhjWEZ4Y1hGeGNHZHhPVFEwYURkb05tMWphM2MyY1RCa00yY3lNak5qYW5vMGVYUjJhMlZ1T0RaMU1EQnplamRqWVhKM0luMA.91c5ee2f4020f0c1f098331760c6963b6b300dc3002d9caa9479d8d1509edf4c44ee518d8f19506830232d76b5baeee5ab6f442354dac69a35e69c290b638d04';
  const MULTISIG_ADDRESS = 'erd1qqqqqqqqqqqqqpgq944h7h6mckw6q0d3g223cjz4ytvken86u00sz7carw';

  const defaultConfig: NativeAuthServerConfig = {
    acceptedOrigins: ['https://api.multiversx.com'],
    maxExpirySeconds: 86400,
    apiUrl: 'https://api.multiversx.com',
    validateImpersonateUrl: 'https://extras-api.multiversx.com/impersonate/allowed',
  };

  const onLatestBlockTimestampGet = function (mock: MockAdapter): RequestHandler {
    return mock.onGet('https://api.multiversx.com/blocks?size=1&fields=timestamp');
  };

  const onSpecificBlockTimestampGet = function (mock: MockAdapter): RequestHandler {
    return mock.onGet(`https://api.multiversx.com/blocks/${BLOCK_HASH}?extract=timestamp`);
  };

  const onSpecificImpersonateGet = function (mock: MockAdapter): RequestHandler {
    return mock.onGet(`https://extras-api.multiversx.com/impersonate/allowed/${ADDRESS}/${MULTISIG_ADDRESS}`);
  };

  beforeAll(() => {
    mock = new MockAdapter(axios);
  });

  afterEach(() => {
    mock.reset();
  });

  describe('Server', () => {
    it('Simple decode', () => {
      const server = new NativeAuthServer(defaultConfig);

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      const result = server.decode(ACCESS_TOKEN);

      expect(result).toStrictEqual(new NativeAuthDecoded({
        address: ADDRESS,
        origin: ORIGIN,
        ttl: TTL,
        blockHash: BLOCK_HASH,
        signature: SIGNATURE,
        body: TOKEN,
      }));
    });

    it('Invalid config ttl', () => {
      expect(() => new NativeAuthServer({ ...defaultConfig, maxExpirySeconds: 86401 })).toThrow(NativeAuthInvalidConfigError);
      expect(() => new NativeAuthServer({ ...defaultConfig, maxExpirySeconds: 0 })).toThrow(NativeAuthInvalidConfigError);
      expect(() => new NativeAuthServer({ ...defaultConfig, maxExpirySeconds: -1 })).toThrow(NativeAuthInvalidConfigError);
      // @ts-ignore
      expect(() => new NativeAuthServer({ ...defaultConfig, maxExpirySeconds: "asdada" })).toThrow(NativeAuthInvalidConfigError);
    });

    it('Invalid config accepted origins', () => {
      expect(() => new NativeAuthServer({ ...defaultConfig, acceptedOrigins: [] })).toThrow(NativeAuthInvalidConfigError);
      // @ts-ignore
      expect(() => new NativeAuthServer({ ...defaultConfig, acceptedOrigins: 'hello world' })).toThrow(NativeAuthInvalidConfigError);
    });

    it('Invalid token error', () => {
      const server = new NativeAuthServer(defaultConfig);

      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImFkZHJlc3MiOiJlcmQxY2V2c3c3bXE1dXZxeW1qcXp3cXZwcXRkcmhja2Vod2Z6OTluN3ByYXR5M3k3cTJqN3lwczg0Mm1xaCIsImlkIjozMTl9LCJkYXRhIjp7fSwiaWF0IjoxNjc1Nzg2NjU5LCJleHAiOjE2NzYyMTg2NTksImlzcyI6ImRldm5ldC1pZC1hcGkubXVsdGl2ZXJzeC5jb20iLCJzdWIiOiJlcmQxY2V2c3c3bXE1dXZxeW1qcXp3cXZwcXRkcmhja2Vod2Z6OTluN3ByYXR5M3k3cTJqN3lwczg0Mm1xaCJ9.pmndzMy2KVJWjTKM4xos8hzSA5FMnHsC0qWRr85IN8o';
      expect(() => server.decode(jwt)).toThrowError(NativeAuthInvalidTokenError);
    });

    it('Simple validation for current timestamp', async () => {
      const server = new NativeAuthServer(defaultConfig);

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      const result = await server.validate(ACCESS_TOKEN);

      expect(result).toStrictEqual(new NativeAuthResult({
        address: ADDRESS,
        signerAddress: ADDRESS,
        origin: ORIGIN,
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
      }));
    });

    it('Latest possible timestamp validation', async () => {
      const server = new NativeAuthServer(defaultConfig);

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP + TTL }]);

      const result = await server.validate(ACCESS_TOKEN);

      expect(result).toStrictEqual(new NativeAuthResult({
        address: ADDRESS,
        signerAddress: ADDRESS,
        origin: ORIGIN,
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
      }));
    });

    it('Origin should be accepted', async () => {
      const server = new NativeAuthServer(defaultConfig);

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      const result = await server.validate(ACCESS_TOKEN);

      expect(result).toStrictEqual(new NativeAuthResult({
        address: ADDRESS,
        signerAddress: ADDRESS,
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
        origin: ORIGIN,
      }));
    });

    it('Unsupported origin should not be accepted', async () => {
      const server = new NativeAuthServer({
        ...defaultConfig,
        acceptedOrigins: ['other-origin'],
      });

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      await expect(server.validate(ACCESS_TOKEN)).rejects.toThrow(NativeAuthOriginNotAcceptedError);
    });

    it('Block hash not found should not be accepted', async () => {
      const server = new NativeAuthServer(defaultConfig);

      onSpecificBlockTimestampGet(mock).reply(404);

      await expect(server.validate(ACCESS_TOKEN)).rejects.toThrow(NativeAuthInvalidBlockHashError);
    });

    it('Block hash unexpected error should throw', async () => {
      const server = new NativeAuthServer(defaultConfig);

      onSpecificBlockTimestampGet(mock).reply(500);

      await expect(server.validate(ACCESS_TOKEN)).rejects.toThrow('Request failed with status code 500');
    });

    it('Latest block + ttl + 1 should throw expired error', async () => {
      const server = new NativeAuthServer(defaultConfig);

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP + TTL + 1 }]);

      await expect(server.validate(ACCESS_TOKEN)).rejects.toThrow(NativeAuthTokenExpiredError);
    });

    it('Invalid signature should throw error', async () => {
      const server = new NativeAuthServer(defaultConfig);
      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      await expect(server.validate(ACCESS_TOKEN + 'abbbbbbbbb')).rejects.toThrow(NativeAuthInvalidSignatureError);
    });

    it('Ttl greater than max expiry seconds should throw error', async () => {
      const server = new NativeAuthServer({
        ...defaultConfig,
        maxExpirySeconds: 80000,
      });

      await expect(server.validate(ACCESS_TOKEN)).rejects.toThrow(NativeAuthInvalidTokenTtlError);
    });

    it('Cache hit', async () => {
      const server = new NativeAuthServer(defaultConfig);

      server.config.cache = {
        getValue: (key: string): Promise<number | undefined> => {
          if (key === `block:timestamp:${BLOCK_HASH}`) {
            return Promise.resolve(BLOCK_TIMESTAMP);
          }

          if (key === 'block:timestamp:latest') {
            return Promise.resolve(BLOCK_TIMESTAMP);
          }

          throw new Error(`Key '${key}' not mocked`);
        },
        setValue: (): Promise<void> => {
          return Promise.resolve();
        },
      };

      const result = await server.validate(ACCESS_TOKEN);

      expect(result).toStrictEqual(new NativeAuthResult({
        address: ADDRESS,
        signerAddress: ADDRESS,
        origin: ORIGIN,
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
      }));
    });

    it('Cache miss', async () => {
      const server = new NativeAuthServer(defaultConfig);

      server.config.cache = {
        // eslint-disable-next-line require-await
        getValue: async function <T>(key: string): Promise<T | undefined> {
          return undefined;
        },
        setValue: async function <T>(key: string, value: T, ttl: number): Promise<void> {

        },
      };

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      const result = await server.validate(ACCESS_TOKEN);

      expect(result).toStrictEqual(new NativeAuthResult({
        address: ADDRESS,
        signerAddress: ADDRESS,
        origin: ORIGIN,
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
      }));
    });

    it('General wildcard is accepted', async () => {
      const server = new NativeAuthServer({
        ...defaultConfig,
        acceptedOrigins: ['*'],
      });

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      const result = await server.validate(ACCESS_TOKEN);
      expect(result).toStrictEqual(new NativeAuthResult({
        address: ADDRESS,
        signerAddress: ADDRESS,
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
        origin: ORIGIN,
      }));
    });

    it('Wildcard origin is accepted', async () => {
      const server = new NativeAuthServer({
        ...defaultConfig,
        acceptedOrigins: ['*.multiversx.com'],
      });

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      const result = await server.validate(ACCESS_TOKEN);
      expect(result).toStrictEqual(new NativeAuthResult({
        address: ADDRESS,
        signerAddress: ADDRESS,
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
        origin: ORIGIN,
      }));
    });

    it('Wildcard validation two wildcards not accepted', () => {
      const config: NativeAuthServerConfig = {
        ...defaultConfig,
        acceptedOrigins: ['*.multiversx*.com'],
      };

      expect(() => new NativeAuthServer(config)).toThrow(NativeAuthInvalidWildcardOriginError);
    });

    it('Wildcard validation protocol not accepted', () => {
      const config: NativeAuthServerConfig = {
        ...defaultConfig,
        acceptedOrigins: ['www.*.multiversx.com'],
      };

      expect(() => new NativeAuthServer(config)).toThrow(NativeAuthInvalidWildcardOriginError);
    });

    it('Wildcard origin is not accepted', async () => {
      const server = new NativeAuthServer({
        ...defaultConfig,
        acceptedOrigins: ['*.elrond.com'],
      });

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      await expect(server.validate(ACCESS_TOKEN)).rejects.toThrow(NativeAuthOriginNotAcceptedError);
    });

    it('Wildcard origin with https is accepted', async () => {
      const server = new NativeAuthServer({
        ...defaultConfig,
        acceptedOrigins: ['https://*.multiversx.com'],
      });

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      const result = await server.validate(ACCESS_TOKEN);
      expect(result).toStrictEqual(new NativeAuthResult({
        address: ADDRESS,
        signerAddress: ADDRESS,
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
        origin: ORIGIN,
      }));
    });

    it('Wildcard origin with http is not accepted', async () => {
      const server = new NativeAuthServer({
        ...defaultConfig,
        acceptedOrigins: ['http://*.multiversx.com'],
      });

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      await expect(server.validate(ACCESS_TOKEN)).rejects.toThrow(NativeAuthOriginNotAcceptedError);
    });

    it('Origin should be accepted with custom validation', async () => {
      const server = new NativeAuthServer({
        ...defaultConfig,
        acceptedOrigins: ['other-origin'],
        isOriginAccepted: (origin: string): boolean => {
          return origin === ORIGIN;
        },
      });

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      const result = await server.validate(ACCESS_TOKEN);
      expect(result).toStrictEqual(new NativeAuthResult({
        address: ADDRESS,
        signerAddress: ADDRESS,
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
        origin: ORIGIN,
      }));
    });

    it('Origin should not be accepted with custom validation', async () => {
      const server = new NativeAuthServer({
        ...defaultConfig,
        acceptedOrigins: ['other-origin'],
        isOriginAccepted: (origin: string): boolean => {
          return origin !== ORIGIN;
        },
      });

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      await expect(server.validate(ACCESS_TOKEN)).rejects.toThrow(NativeAuthOriginNotAcceptedError);
    });

    it('Custom origin validation should be called', async () => {
      const server = new NativeAuthServer({
        ...defaultConfig,
        acceptedOrigins: ['other-origin'],
        isOriginAccepted: (_origin: string): boolean => true,
      });

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      const isOriginAcceptedMethod = jest.spyOn(server.config, 'isOriginAccepted');

      await server.validate(ACCESS_TOKEN);

      expect(isOriginAcceptedMethod).toHaveBeenCalled();
    });

    it('Custom origin validation should not be called', async () => {
      const server = new NativeAuthServer({
        ...defaultConfig,
        isOriginAccepted: (_origin: string): boolean => {
          return true;
        },
      });

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      const isOriginAcceptedMethod = jest.spyOn(server.config, 'isOriginAccepted');

      await server.validate(ACCESS_TOKEN);

      expect(isOriginAcceptedMethod).not.toHaveBeenCalled();
    });

    it('Custom origin validation should throw', async () => {
      const server = new NativeAuthServer({
        ...defaultConfig,
        acceptedOrigins: ['other-origin'],
        // eslint-disable-next-line require-await
        isOriginAccepted: async (_origin: string): Promise<boolean> => {
          throw new Error('Custom error');
        },
      });

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      await expect(server.validate(ACCESS_TOKEN)).rejects.toThrow('Custom error');
    });

    it('Custom origin validation can be async', async () => {
      const server = new NativeAuthServer({
        ...defaultConfig,
        acceptedOrigins: ['other-origin'],
        // eslint-disable-next-line require-await
        isOriginAccepted: async (_origin: string): Promise<boolean> => {
          return true;
        },
      });

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      const result = await server.validate(ACCESS_TOKEN);
      expect(result).toStrictEqual(new NativeAuthResult({
        address: ADDRESS,
        signerAddress: ADDRESS,
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
        origin: ORIGIN,
      }));
    });

    it('Simple validation for multisig key via api', async () => {
      const server = new NativeAuthServer(defaultConfig);

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);
      onSpecificImpersonateGet(mock).reply(200, true);

      const result = await server.validate(MULTISIG_ACCESS_TOKEN);

      expect(result).toStrictEqual(new NativeAuthResult({
        address: MULTISIG_ADDRESS,
        signerAddress: ADDRESS,
        origin: ORIGIN,
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
        extraInfo: {
          multisig: MULTISIG_ADDRESS,
        },
      }));
    });
  });

  it('Simple validation for impersonate key via api', async () => {
    const server = new NativeAuthServer(defaultConfig);

    onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
    onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);
    onSpecificImpersonateGet(mock).reply(200, true);

    const result = await server.validate(IMPERSONATE_ACCESS_TOKEN);

    expect(result).toStrictEqual(new NativeAuthResult({
      address: MULTISIG_ADDRESS,
      signerAddress: ADDRESS,
      origin: ORIGIN,
      issued: BLOCK_TIMESTAMP,
      expires: BLOCK_TIMESTAMP + TTL,
      extraInfo: {
        impersonate: MULTISIG_ADDRESS,
      },
    }));
  });

  it('Simple validation for impersonate key via callback synchronously', async () => {
    const server = new NativeAuthServer({
      ...defaultConfig,
      validateImpersonateCallback: () => true,
    });

    onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
    onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

    const result = await server.validate(IMPERSONATE_ACCESS_TOKEN);

    expect(result).toStrictEqual(new NativeAuthResult({
      address: MULTISIG_ADDRESS,
      signerAddress: ADDRESS,
      origin: ORIGIN,
      issued: BLOCK_TIMESTAMP,
      expires: BLOCK_TIMESTAMP + TTL,
      extraInfo: {
        impersonate: MULTISIG_ADDRESS,
      },
    }));
  });

  it('Simple validation for impersonate key via callback asynchronously', async () => {
    const server = new NativeAuthServer({
      ...defaultConfig,
      validateImpersonateCallback: () => Promise.resolve(true),
    });

    onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
    onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

    const result = await server.validate(IMPERSONATE_ACCESS_TOKEN);

    expect(result).toStrictEqual(new NativeAuthResult({
      address: MULTISIG_ADDRESS,
      signerAddress: ADDRESS,
      origin: ORIGIN,
      issued: BLOCK_TIMESTAMP,
      expires: BLOCK_TIMESTAMP + TTL,
      extraInfo: {
        impersonate: MULTISIG_ADDRESS,
      },
    }));
  });

  it('Impersonate request fails', async () => {
    const server = new NativeAuthServer(defaultConfig);

    onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
    onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);
    onSpecificImpersonateGet(mock).reply(403);

    await expect(server.validate(MULTISIG_ACCESS_TOKEN)).rejects.toThrow(NativeAuthInvalidImpersonateError);
  });

  it('Impersonate caching hit', async () => {
    const server = new NativeAuthServer({
      ...defaultConfig,
      cache: {
        getValue: (key: string) => {
          if (key === `impersonate:${ADDRESS}:${MULTISIG_ADDRESS}`) {
            return Promise.resolve(1);
          }

          if (key === `block:timestamp:${BLOCK_HASH}`) {
            return Promise.resolve(BLOCK_TIMESTAMP);
          }

          if (key === 'block:timestamp:latest') {
            return Promise.resolve(BLOCK_TIMESTAMP);
          }

          throw new Error(`Key '${key}' not mocked`);
        },
        setValue: (key: string, value: number, ttl: number) => {
          return Promise.resolve();
        },
      },
    });

    const result = await server.validate(IMPERSONATE_ACCESS_TOKEN);

    expect(result).toStrictEqual(new NativeAuthResult({
      address: MULTISIG_ADDRESS,
      signerAddress: ADDRESS,
      origin: ORIGIN,
      issued: BLOCK_TIMESTAMP,
      expires: BLOCK_TIMESTAMP + TTL,
      extraInfo: {
        impersonate: MULTISIG_ADDRESS,
      },
    }));
  });

  it('Impersonate caching miss', async () => {
    const server = new NativeAuthServer({
      ...defaultConfig,
      cache: {
        getValue: (key: string) => {
          if (key === `impersonate:${ADDRESS}:${MULTISIG_ADDRESS}`) {
            return Promise.resolve(undefined);
          }

          if (key === `block:timestamp:${BLOCK_HASH}`) {
            return Promise.resolve(BLOCK_TIMESTAMP);
          }

          if (key === 'block:timestamp:latest') {
            return Promise.resolve(BLOCK_TIMESTAMP);
          }

          throw new Error(`Key '${key}' not mocked`);
        },
        setValue: (key: string, value: number, ttl: number) => {
          return Promise.resolve();
        },
      },
    });

    onSpecificImpersonateGet(mock).reply(200, true);

    const result = await server.validate(IMPERSONATE_ACCESS_TOKEN);

    expect(result).toStrictEqual(new NativeAuthResult({
      address: MULTISIG_ADDRESS,
      signerAddress: ADDRESS,
      origin: ORIGIN,
      issued: BLOCK_TIMESTAMP,
      expires: BLOCK_TIMESTAMP + TTL,
      extraInfo: {
        impersonate: MULTISIG_ADDRESS,
      },
    }));
  });
});
