/**
 * wop-typescript-sdk 公共导出。
 *
 * axios peer 适配器经独立入口 `@wanlianyida/wop-typescript-sdk/axios` 导入（不污染核心依赖面，
 * 且避免 CJS 主入口 eager require 触发可选 peer 加载）。
 */

export { WopError, SIGNATURE_FAILED, DECRYPT_FAILED } from './error';
export type { WopErrorCategory } from './error';
export { WopGatewayResponseError } from './gatewayResponseError';
export {
  loadDefault,
  load,
  clearCache,
  parseConfigJson,
  validateAndNormalize,
  buildConfig,
  validateGatewayUrl,
  validateApiPath,
  joinUrl,
  CONFIG_FILE_ENV,
  CONFIG_FILE_ENV_OVERRIDE,
  DEFAULT_CONNECT_TIMEOUT,
  DEFAULT_READ_TIMEOUT,
  DEFAULT_MAX_RETRY_COUNT,
  DEFAULT_EXPIRED_SECONDS,
  defaultHttpClientSettings,
  maskConfigForLog,
} from './config';
export type { WopSdkConfig, HttpClientSettings } from './config';
export { parseSecurityReq } from './suite';
export type { AlgorithmSuite } from './suite';
export { canonicalRequest, canonicalHeaders, javaUrlEncode, trimall } from './canonical';
export { computeDigestHeader, verifyDigestHeader } from './digest';
export { keyMaterialToDer } from './keys';
export {
  webcrypto,
  rsaSign,
  rsaVerify,
  oaepWrap,
  oaepUnwrap,
  aesGcmEncrypt,
  aesGcmDecrypt,
  randomBytes,
} from './crypto';
export { buildDekPayload, parseDekPayload } from './envelope';
export type { DekPayload } from './envelope';
export {
  toBase64Url,
  fromBase64Url,
  toBase64,
  fromBase64,
  toHex,
  fromHex,
  utf8Encode,
  utf8Decode,
} from './encode';
export type { Bytes } from './encode';
export { WopClient } from './client';
export type { WopConfig, RequestOptions, RequestDraft, VerifyResult, SendResult } from './client';
export type { Transport, TransportRequest, TransportResponse } from './transport/types';
export { FetchTransport } from './transport/fetch';
