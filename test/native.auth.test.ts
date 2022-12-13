import axios from "axios";
import MockAdapter, { RequestHandler } from "axios-mock-adapter";
import { NativeAuthInvalidBlockHashError } from "../src/entities/errors/native.auth.invalid.block.hash.error";
import { NativeAuthInvalidSignatureError } from "../src/entities/errors/native.auth.invalid.signature.error";
import { NativeAuthTokenExpiredError } from "../src/entities/errors/native.auth.token.expired.error";
import { NativeAuthDecoded } from "../src/entities/native.auth.decoded";
import { NativeAuthResult } from "../src/entities/native.auth.validate.result";
import { NativeAuthServer } from '../src';

describe("Native Auth", () => {
  let mock: MockAdapter;
  const ADDRESS = 'erd1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssycr6th';
  const SIGNATURE = '22ec047bfa02e1617b84f5f5c328ebf46c15cbdbfdd57ca148dfdfc2134a8a97b087fd6ab880cc815a315c70080aac5298f56666b9bea032598adc9b11a3ca08';
  const BLOCK_HASH = 'b3d07565293fd5684c97d2b96eb862d124fd698678f3f95b2515ed07178a27b4';
  const TTL = 86400;
  const TOKEN = `${BLOCK_HASH}.${TTL}.e30=`;
  const ACCESS_TOKEN = `ZXJkMXF5dTV3dGhsZHpyOHd4NWM5dWNnOGtqYWdnMGpmczUzczhucjN6cHozaHlwZWZzZGQ4c3N5Y3I2dGg=.YjNkMDc1NjUyOTNmZDU2ODRjOTdkMmI5NmViODYyZDEyNGZkNjk4Njc4ZjNmOTViMjUxNWVkMDcxNzhhMjdiNC44NjQwMC5lMzA9.${SIGNATURE}`;
  const BLOCK_TIMESTAMP = 1653068466;

  const onLatestBlockTimestampGet = function (mock: MockAdapter): RequestHandler {
    return mock.onGet('https://api.elrond.com/blocks?size=1&fields=timestamp');
  };

  const onSpecificBlockTimestampGet = function (mock: MockAdapter): RequestHandler {
    return mock.onGet(`https://api.elrond.com/blocks/${BLOCK_HASH}?extract=timestamp`);
  };

  beforeAll(() => {
    mock = new MockAdapter(axios);
  });

  afterEach(() => {
    mock.reset();
  });

  describe('Server', () => {
    it('Simple decode', () => {
      const server = new NativeAuthServer();

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      const result = server.decode(ACCESS_TOKEN);

      expect(result).toStrictEqual(new NativeAuthDecoded({
        address: ADDRESS,
        ttl: TTL,
        blockHash: BLOCK_HASH,
        signature: SIGNATURE,
        body: TOKEN,
      }));
    });

    it('Simple validation for current timestamp', async () => {
      const server = new NativeAuthServer();

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      const result = await server.validate(ACCESS_TOKEN);

      expect(result).toStrictEqual(new NativeAuthResult({
        address: ADDRESS,
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
      }));
    });

    it('Latest possible timestamp validation', async () => {
      const server = new NativeAuthServer();

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP + TTL }]);

      const result = await server.validate(ACCESS_TOKEN);

      expect(result).toStrictEqual(new NativeAuthResult({
        address: ADDRESS,
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
      }));
    });

    it('Block hash not found should not be accepted', async () => {
      const server = new NativeAuthServer();

      onSpecificBlockTimestampGet(mock).reply(404);

      await expect(server.validate(ACCESS_TOKEN)).rejects.toThrow(NativeAuthInvalidBlockHashError);
    });

    it('Block hash unexpected error should throw', async () => {
      const server = new NativeAuthServer();

      onSpecificBlockTimestampGet(mock).reply(500);

      await expect(server.validate(ACCESS_TOKEN)).rejects.toThrow('Request failed with status code 500');
    });

    it('Latest block + ttl + 1 should throw expired error', async () => {
      const server = new NativeAuthServer();

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP + TTL + 1 }]);

      await expect(server.validate(ACCESS_TOKEN)).rejects.toThrow(NativeAuthTokenExpiredError);
    });

    it('Invalid signature should throw error', async () => {
      const server = new NativeAuthServer();

      onSpecificBlockTimestampGet(mock).reply(200, BLOCK_TIMESTAMP);
      onLatestBlockTimestampGet(mock).reply(200, [{ timestamp: BLOCK_TIMESTAMP }]);

      await expect(server.validate(ACCESS_TOKEN + 'abbbbbbbbb')).rejects.toThrow(NativeAuthInvalidSignatureError);
    });

    it('Cache hit', async () => {
      const server = new NativeAuthServer();

      server.config.cache = {
        // eslint-disable-next-line require-await
        getValue: async function <T>(key: string): Promise<T | undefined> {
          if (key === `block:timestamp:${BLOCK_HASH}`) {
            // @ts-ignore
            return BLOCK_TIMESTAMP;
          }

          if (key === 'block:timestamp:latest') {
            // @ts-ignore
            return BLOCK_TIMESTAMP;
          }

          throw new Error(`Key '${key}' not mocked`);
        },
        setValue: async function <T>(key: string, value: T, ttl: number): Promise<void> {

        },
      };

      const result = await server.validate(ACCESS_TOKEN);

      expect(result).toStrictEqual(new NativeAuthResult({
        address: ADDRESS,
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
      }));
    });

    it('Cache miss', async () => {
      const server = new NativeAuthServer();

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
        issued: BLOCK_TIMESTAMP,
        expires: BLOCK_TIMESTAMP + TTL,
      }));
    });
  });
});
