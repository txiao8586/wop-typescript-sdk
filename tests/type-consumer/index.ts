/**
 * 类型消费方下界测试（兼容性维度 3：TypeScript 类型消费）。
 *
 * 以「商户工程」视角 import SDK 的两个入口并使用全部导出符号：
 * - 语法下界：CI types-floor job 分别用 TS 5.0.4（支持下界）与最新版编译本文件，
 *   .d.ts 若使用了 5.1+ 语法/库类型，下界编译立即失败
 * - API 演进哨兵：noUnusedLocals/noUnusedParameters 强制全部 import 被「使用」，
 *   既有导出的改形/移除在此处立即编译失败，与 etc/*.api.md 快照互补
 *
 * 路径映射（tsconfig paths）直接指向 dist 产物——exports/typesVersions 的
 * 解析正确性由 attw（test:dist）覆盖，本工程只验证类型语法兼容。
 */

import type {
  WopErrorCategory,
  AlgorithmSuite,
  DekPayload,
  Bytes,
  WopConfig,
  RequestOptions,
  RequestDraft,
  VerifyResult,
  SendResult,
  Transport,
  TransportRequest,
  TransportResponse,
} from '@wanlianyida/wop-typescript-sdk';

import {
  WopClient,
  WopError,
  FetchTransport,
  SIGNATURE_FAILED,
  DECRYPT_FAILED,
  parseSecurityReq,
  canonicalRequest,
  canonicalHeaders,
  javaUrlEncode,
  trimall,
  computeDigestHeader,
  verifyDigestHeader,
  keyMaterialToDer,
  webcrypto,
  rsaSign,
  rsaVerify,
  oaepWrap,
  oaepUnwrap,
  aesGcmEncrypt,
  aesGcmDecrypt,
  randomBytes,
  buildDekPayload,
  parseDekPayload,
  toBase64Url,
  fromBase64Url,
  toBase64,
  fromBase64,
  toHex,
  fromHex,
  utf8Encode,
  utf8Decode,
} from '@wanlianyida/wop-typescript-sdk';

import { AxiosTransport } from '@wanlianyida/wop-typescript-sdk/axios';

/** 编译期结构哨兵：导出类型的形变在此立即失败 */
type AssertEq<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : never;
const t1: AssertEq<VerifyResult['ok'], boolean> = true;
const t2: AssertEq<RequestDraft['wireBody'], string> = true;
const t3: AssertEq<AlgorithmSuite['keyLength'], 2048 | 3072 | 4096> = true;
const t4: AssertEq<SendResult extends VerifyResult ? true : false, true> = true;
const t5: AssertEq<WopErrorCategory, 'parse' | 'unsupported' | 'integrity' | 'signature' | 'decrypt' | 'consistency' | 'configuration' | 'system'> = true;
const t6: AssertEq<TransportRequest['body'], string> = true;
const t7: AssertEq<TransportResponse['headers'], Record<string, string>> = true;

const CONFIG: WopConfig = {
  appKey: 'consumer-type-check',
  suite: 'WOP-RSA3072-SHA256',
  merchantPrivateKey: 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBH...',
  platformPublicKey: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...',
  gatewayBaseUrl: 'https://gw.example.com',
};

const OPTIONS: RequestOptions = {
  level: 'L2',
  expiredSeconds: 900,
  timestamp: 1770000000000,
  nonce: 'consumer-nonce',
  dek: new Uint8Array(32),
  iv: new Uint8Array(12),
};

const client = new WopClient(CONFIG);
const fetchTransport: Transport = new FetchTransport();
const axiosTransport: Transport = new AxiosTransport();
client.setTransport(fetchTransport);

const suite: AlgorithmSuite = parseSecurityReq('WOP-RSA3072-SHA256');
const sigLen: 342 | 512 | 683 = suite.signatureB64uLength;
const dekAlg: 'AES-256-GCM' = suite.expectedDekAlg;

const REQ: TransportRequest = {
  method: 'POST',
  url: 'https://gw.example.com/v1/order/create',
  headers: { 'content-type': 'application/json' },
  body: '{"orderId":"x"}',
};
const RESP_HEADERS: TransportResponse['headers'] = { 'x-wop-appkey': 'ak' };
const RESP: TransportResponse = { status: 200, headers: RESP_HEADERS, body: '{}' };

const ENCODED: string = javaUrlEncode('a b;c');
const TRIMMED: string = trimall('  a   b  ');
const CANON_H: string = canonicalHeaders({ 'X-Wop-Nonce': 'n', 'X-Wop-Timestamp': 't' });
const CANON: string = canonicalRequest({
  authString: 'v1/1800',
  method: 'post',
  path: '/v1/order/create',
  queryString: '',
  headers: { 'x-wop-nonce': 'n' },
});

const DER: Uint8Array = keyMaterialToDer(CONFIG.platformPublicKey);
const B: Bytes = new Uint8Array(8);
const SIG_MSG_FAILED: string = SIGNATURE_FAILED;
const DECRYPT_MSG_FAILED: string = DECRYPT_FAILED;
const ERR_CATEGORY: WopErrorCategory = new WopError('consumer', 'parse').category;

async function consumeCryptoPrimitives(): Promise<void> {
  const engine: Crypto = await webcrypto();
  const nonce = await randomBytes(16);
  const sig = await rsaSign(DER, nonce);
  const okSig = await rsaVerify(DER, sig, nonce);
  const wrapped = await oaepWrap(DER, nonce);
  const unwrapped = await oaepUnwrap(DER, wrapped);
  const ct = await aesGcmEncrypt(unwrapped, nonce, utf8Encode('body'));
  const pt = await aesGcmDecrypt(unwrapped, nonce, ct);
  const digest = await computeDigestHeader(utf8Decode(pt));
  const parsed: { alg: string; hex: string } | null = verifyDigestHeader(digest, suite);
  const payloadStr: string = buildDekPayload('AES-256-GCM', new Uint8Array(32), new Uint8Array(12));
  const payload: DekPayload = parseDekPayload(payloadStr);
  const b64u: string = toBase64Url(pt);
  const back: Uint8Array = fromBase64Url(b64u);
  const b64: string = toBase64(pt);
  const back2: Uint8Array = fromBase64(b64);
  const hex: string = toHex(pt);
  const back3: Uint8Array = fromHex(hex);
  void [engine, okSig, wrapped, ct, parsed, payload, back, back2, back3];
}

async function consumeClient(): Promise<void> {
  const draftL0: RequestDraft = await client.buildRequest('POST', '/v1/order/create', '{"a":1}');
  const draftL2: RequestDraft = await client.buildRequest('POST', '/v1/order/create', '{"a":1}', OPTIONS);
  const draftGet: RequestDraft = await client.buildRequest('GET', '/v1/order/query?status=PAID');

  const verified: VerifyResult = await client.verifyResponse(RESP_HEADERS, '{}', '/v1/order/create');
  const okFlag: boolean = verified.ok;
  const plaintext: string | undefined = verified.plaintext;
  const reason: string | undefined = verified.reason;

  const callback: VerifyResult = await client.verifyCallback(RESP_HEADERS, '{}', 'https://m.example.cn/cb?src=async');

  client.setTransport(axiosTransport);
  const sent: SendResult = await client.send('POST', '/v1/order/create', '{"a":1}');
  const status: number = sent.status;
  void [draftL0, draftL2, draftGet, verified, okFlag, plaintext, reason, callback, sent, status];
}

/** 顶层引用：满足 noUnusedLocals；本文件只编译不运行（noEmit），无运行时副作用 */
void [
  consumeCryptoPrimitives, consumeClient, REQ, RESP,
  t1, t2, t3, t4, t5, t6, t7,
  sigLen, dekAlg, ENCODED, TRIMMED, CANON_H, CANON,
  SIG_MSG_FAILED, DECRYPT_MSG_FAILED, ERR_CATEGORY, B,
];
