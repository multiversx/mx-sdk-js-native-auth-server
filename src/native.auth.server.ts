import axios from "axios";
import { NativeAuthInvalidBlockHashError } from "./entities/errors/native.auth.invalid.block.hash.error";
import { NativeAuthInvalidSignatureError } from "./entities/errors/native.auth.invalid.signature.error";
import { NativeAuthTokenExpiredError } from "./entities/errors/native.auth.token.expired.error";
import { NativeAuthServerConfig } from "./entities/native.auth.server.config";
import { NativeAuthSignature } from "./native.auth.signature";
import { NativeAuthResult as NativeAuthValidateResult } from "./entities/native.auth.validate.result";
import { NativeAuthDecoded } from "./entities/native.auth.decoded";
import { NativeAuthHostNotAcceptedError } from "./entities/errors/native.auth.host.not.accepted.error";
import { SignableMessage, Address } from "@multiversx/sdk-core";
import { UserPublicKey, UserVerifier } from "@multiversx/sdk-wallet";
import { NativeAuthInvalidTokenTtlError } from "./entities/errors/native.auth.invalid.token.ttl.error";
export class NativeAuthServer {
  config: NativeAuthServerConfig;

  constructor(
    config?: Partial<NativeAuthServerConfig>,
  ) {
    this.config = Object.assign(new NativeAuthServerConfig(), config);
  }

  decode(accessToken: string): NativeAuthDecoded {
    const [address, body, signature] = accessToken.split('.');
    const parsedAddress = this.decodeValue(address);
    const parsedBody = this.decodeValue(body);
    const components = parsedBody.split('.');

    const [host, blockHash, ttl, extraInfo] = components;
    const parsedExtraInfo = JSON.parse(this.decodeValue(extraInfo));
    const parsedHost = this.decodeValue(host);

    const result = new NativeAuthDecoded({
      ttl: Number(ttl),
      host: parsedHost,
      address: parsedAddress,
      extraInfo: parsedExtraInfo,
      signature,
      blockHash,
      body: parsedBody,
    });

    // if empty object, delete extraInfo ('e30' = encoded '{}')
    if (extraInfo === 'e30') {
      delete result.extraInfo;
    }

    return result;
  }

  async validate(accessToken: string): Promise<NativeAuthValidateResult> {
    const decoded = this.decode(accessToken);

    if (decoded.ttl > this.config.maxExpirySeconds) {
      throw new NativeAuthInvalidTokenTtlError(decoded.ttl, this.config.maxExpirySeconds);
    }

    if (this.config.acceptedHosts.length > 0 && !this.config.acceptedHosts.includes(decoded.host)) {
      throw new NativeAuthHostNotAcceptedError();
    }

    const blockTimestamp = await this.getBlockTimestamp(decoded.blockHash);
    if (!blockTimestamp) {
      throw new NativeAuthInvalidBlockHashError();
    }

    const currentBlockTimestamp = await this.getCurrentBlockTimestamp();

    const expires = blockTimestamp + decoded.ttl;

    const isTokenExpired = expires < currentBlockTimestamp;
    if (isTokenExpired) {
      throw new NativeAuthTokenExpiredError();
    }

    const signedMessage = `${decoded.address}${decoded.body}`;
    const signableMessage = new SignableMessage({
      address: new Address(decoded.address),
      message: Buffer.from(signedMessage, 'utf8'),
      signature: new NativeAuthSignature(decoded.signature),
    });

    const signedMessageLegacy = `${decoded.address}${decoded.body}{}`;
    const signableMessageLegacy = new SignableMessage({
      address: new Address(decoded.address),
      message: Buffer.from(signedMessageLegacy, 'utf8'),
      signature: new NativeAuthSignature(decoded.signature),
    });

    const publicKey = new UserPublicKey(
      Address.fromString(decoded.address).pubkey(),
    );

    const verifier = new UserVerifier(publicKey);
    const valid = verifier.verify(signableMessage) || verifier.verify(signableMessageLegacy);

    if (!valid) {
      throw new NativeAuthInvalidSignatureError();
    }

    const result = new NativeAuthValidateResult({
      issued: blockTimestamp,
      expires,
      host: decoded.host,
      address: decoded.address,
      extraInfo: decoded.extraInfo,
    });

    if (!decoded.extraInfo) {
      delete result.extraInfo;
    }

    return result;
  }

  private async getCurrentBlockTimestamp(): Promise<number> {
    if (this.config.cache) {
      const timestamp = await this.config.cache.getValue('block:timestamp:latest');
      if (timestamp) {
        return timestamp;
      }
    }

    const response = await axios.get(`${this.config.apiUrl}/blocks?size=1&fields=timestamp`);
    const timestamp = Number(response.data[0].timestamp);

    if (this.config.cache) {
      await this.config.cache.setValue('block:timestamp:latest', timestamp, 6);
    }

    return timestamp;
  }

  private async getBlockTimestamp(hash: string): Promise<number | undefined> {
    if (this.config.cache) {
      const timestamp = await this.config.cache.getValue(`block:timestamp:${hash}`);
      if (timestamp) {
        return timestamp;
      }
    }

    try {
      const { data: timestamp } = await axios.get(`${this.config.apiUrl}/blocks/${hash}?extract=timestamp`);

      if (this.config.cache) {
        await this.config.cache.setValue(`block:timestamp:${hash}`, Number(timestamp), this.config.maxExpirySeconds);
      }

      return Number(timestamp);
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.response?.status === 404) {
          return undefined;
        }
      }

      throw error;
    }
  }

  private decodeValue(str: string) {
    return Buffer.from(this.unescape(str), 'base64').toString('utf8');
  }

  private unescape(str: string) {
    return str.replace(/-/g, "+").replace(/_/g, "\/");
  }
}
