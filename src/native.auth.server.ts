import axios from "axios";
import * as crypto from "crypto";
import { NativeAuthInvalidBlockHashError } from "./entities/errors/native.auth.invalid.block.hash.error";
import { NativeAuthInvalidSignatureError } from "./entities/errors/native.auth.invalid.signature.error";
import { NativeAuthTokenExpiredError } from "./entities/errors/native.auth.token.expired.error";
import { NativeAuthServerConfig } from "./entities/native.auth.server.config";
import { NativeAuthResult as NativeAuthValidateResult } from "./entities/native.auth.validate.result";
import { NativeAuthDecoded } from "./entities/native.auth.decoded";
import { NativeAuthOriginNotAcceptedError } from "./entities/errors/native.auth.origin.not.accepted.error";
import { SignableMessage, Address } from "@multiversx/sdk-core";
import { NativeAuthInvalidTokenTtlError } from "./entities/errors/native.auth.invalid.token.ttl.error";
import { NativeAuthInvalidTokenError } from "./entities/errors/native.auth.invalid.token.error";
import { NativeAuthInvalidConfigError } from "./entities/errors/native.auth.invalid.config.error";


export class NativeAuthServer {
  private DEFAULT_API_URL = "https://api.multiversx.com";
  private MAX_EXPIRY_SECONDS = 86400;

  constructor(
    readonly config: NativeAuthServerConfig
  ) {
    if (!config.apiUrl) {
      config.apiUrl = this.DEFAULT_API_URL;
    }

    if (!(config.maxExpirySeconds > 0 && config.maxExpirySeconds <= this.MAX_EXPIRY_SECONDS)) {
      throw new NativeAuthInvalidConfigError(`maxExpirySeconds must be greater than 0 and cannot be greater than ${this.MAX_EXPIRY_SECONDS}`);
    }

    if (!Array.isArray(config.acceptedOrigins)) {
      throw new NativeAuthInvalidConfigError('acceptedOrigins must be an array');
    }

    if (!config.acceptedOrigins || config.acceptedOrigins.length === 0) {
      throw new NativeAuthInvalidConfigError('at least one value must be specified in the acceptedOrigins array');
    }
  }

  decode(accessToken: string): NativeAuthDecoded {
    const tokenComponents = accessToken.split('.');
    if (tokenComponents.length !== 3) {
      throw new NativeAuthInvalidTokenError();
    }

    const [address, body, signature] = accessToken.split('.');
    const parsedAddress = this.decodeValue(address);
    const parsedBody = this.decodeValue(body);
    const bodyComponents = parsedBody.split('.');
    if (bodyComponents.length !== 4) {
      throw new NativeAuthInvalidTokenError();
    }

    const [origin, blockHash, ttl, extraInfo] = bodyComponents;

    let parsedExtraInfo;
    try {
      parsedExtraInfo = JSON.parse(this.decodeValue(extraInfo));
    } catch {
      throw new NativeAuthInvalidTokenError();
    }

    const parsedOrigin = this.decodeValue(origin);

    const result = new NativeAuthDecoded({
      ttl: Number(ttl),
      origin: parsedOrigin,
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

    if (
      this.config.acceptedOrigins.length > 0 &&
      !this.config.acceptedOrigins.includes(decoded.origin) &&
      !this.config.acceptedOrigins.includes('https://' + decoded.origin)
    ) {
      throw new NativeAuthOriginNotAcceptedError();
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

    const address = new Address(decoded.address);
    const signatureBuffer = Buffer.from(decoded.signature, 'hex');

    const signedMessage = `${decoded.address}${decoded.body}`;
    let valid = this.verifySignature(address, signedMessage, signatureBuffer);

    if (!valid && !this.config.skipLegacyValidation) {
      const signedMessageLegacy = `${decoded.address}${decoded.body}{}`;
      valid = this.verifySignature(address, signedMessageLegacy, signatureBuffer);
    }

    if (!valid) {
      throw new NativeAuthInvalidSignatureError();
    }

    const result = new NativeAuthValidateResult({
      issued: blockTimestamp,
      expires,
      origin: decoded.origin,
      address: decoded.address,
      extraInfo: decoded.extraInfo,
    });

    if (!decoded.extraInfo) {
      delete result.extraInfo;
    }

    return result;
  }

  private verifySignature(address: Address, messageString: string, signature: Buffer): boolean {
    const cryptoPublicKey = crypto.createPublicKey({
      format: 'der',
      type: 'spki',
      key: this.toDER(address.pubkey()),
    });

    const signableMessage = new SignableMessage({
      address,
      message: Buffer.from(messageString, 'utf8'),
    });

    const cryptoMessage = Buffer.from(signableMessage.serializeForSigning().toString('hex'), "hex");

    return crypto.verify(null, cryptoMessage, cryptoPublicKey, signature);
  }


  private async get(url: string): Promise<any> {
    const response = await axios.get(url, { headers: this.config.extraRequestHeaders });
    return response.data;
  }

  private async getCurrentBlockTimestamp(): Promise<number> {
    if (this.config.cache) {
      const timestamp = await this.config.cache.getValue('block:timestamp:latest');
      if (timestamp) {
        return timestamp;
      }
    }

    const response = await this.get(`${this.config.apiUrl}/blocks?size=1&fields=timestamp`);
    const timestamp = Number(response[0].timestamp);

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
      const timestamp = await this.get(`${this.config.apiUrl}/blocks/${hash}?extract=timestamp`);

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

  private toDER(key: Buffer) {
    // Ed25519's OID
    const oid = Buffer.from([0x06, 0x03, 0x2B, 0x65, 0x70]);

    // Create a byte sequence containing the OID and key
    const elements = Buffer.concat([
      Buffer.concat([
        Buffer.from([0x30]), // Sequence tag
        Buffer.from([oid.length]),
        oid,
      ]),
      Buffer.concat([
        Buffer.from([0x03]), // Bit tag
        Buffer.from([key.length + 1]),
        Buffer.from([0x00]), // Zero bit
        key,
      ]),
    ]);

    // Wrap up by creating a sequence of elements
    const der = Buffer.concat([
      Buffer.from([0x30]), // Sequence tag
      Buffer.from([elements.length]),
      elements,
    ]);

    return der;
  }
}
