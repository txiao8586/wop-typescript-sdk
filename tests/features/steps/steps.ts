import { Given, When, Then } from '@cucumber/cucumber';
import assert from 'node:assert/strict';
import { WopClient, WopError } from '../../../src/index';
import { FetchTransport, MAX_RESPONSE_BYTES } from '../../../src/transport/fetch';
import {
  MERCH_PRIV,
  PLAT_PUB,
  platformRespond,
  gatewayVerifyDraft,
  gatewayDecryptDraft,
  AES_KEY,
  AES_IV,
} from './platform';
import type { VerifyResult, RequestDraft } from '../../../src/client';

/** 每个场景的商户侧状态 */
const state: {
  appKey: string;
  client?: WopClient;
  suite?: string;
  initError?: string;
  draft?: RequestDraft;
  draft2?: RequestDraft;
  result?: VerifyResult;
  sendError?: string;
  restoreFetch?: () => void;
} = { appKey: '' };

const PATH = '/v1/order/create';
const BODY = JSON.stringify({ orderId: 'bdd-20260829-001', amount: 188 });
/** S11 重放确定性：requestId 缺省生成是每次独立的（附录 I），全等断言须显式透传固定值 */
const S11_REQUEST_ID = 'req-bdd-s11-fixed-000000000000001';

function freshClient(suite = 'WOP-RSA3072-SHA256'): WopClient {
  return new WopClient({
    appKey: state.appKey,
    suite,
    merchantPrivateKey: MERCH_PRIV,
    platformPublicKey: PLAT_PUB,
  });
}

// ---------- Given ----------

Given('一套 RSA3072 测试密钥与 appKey {string}', function (appKey: string) {
  state.appKey = appKey;
});

// ---------- When（初始化，S1-S3）----------

When('商户用 {string} 套件初始化客户端', function (suite: string) {
  state.suite = suite;
  try {
    state.client = freshClient(suite);
  } catch (e) {
    state.initError = (e as Error).message;
  }
});

// ---------- When（出向，S4-S6）----------

When('商户对订单接口发起 L0 请求', async function () {
  state.client ??= freshClient();
  state.draft = await state.client.buildRequest('POST', PATH, BODY, { timestamp: 1, nonce: 'n', requestId: S11_REQUEST_ID });
});

When('商户对查询接口发起无 body 的 GET 请求', async function () {
  state.client ??= freshClient();
  state.draft = await state.client.buildRequest('GET', '/v1/order/query', undefined, { timestamp: 1, nonce: 'n' });
});

When('商户对订单接口发起 L2 加密请求', async function () {
  state.client ??= freshClient();
  state.draft = await state.client.buildRequest('POST', PATH, BODY, {
    level: 'L2',
    timestamp: 1,
    nonce: 'n',
    dek: AES_KEY,
    iv: AES_IV,
  });
});

// ---------- When（入向，S7-S11）----------

When('商户校验平台的 {string} 同步响应', async function (level: 'L0' | 'L2') {
  state.client ??= freshClient();
  const { headers, body } = await platformRespond(PATH, BODY, { level });
  state.result = await state.client.verifyResponse(headers, body, PATH);
});

When('商户校验被篡改了 {string} 的 L0 响应', async function (what: 'signature' | 'digest') {
  state.client ??= freshClient();
  const { headers, body } = await platformRespond(PATH, BODY, { tamper: what });
  state.result = await state.client.verifyResponse(headers, body, PATH);
});

When('商户校验被篡改了 DEK 载荷的 L2 响应', async function () {
  state.client ??= freshClient();
  const { headers, body } = await platformRespond(PATH, BODY, { level: 'L2', tamper: 'dek' });
  state.result = await state.client.verifyResponse(headers, body, PATH);
});

When('商户校验平台对回调地址 {string} 的通知', async function (callbackUrl: string) {
  state.client ??= freshClient();
  const path = new URL(callbackUrl).pathname;
  const { headers, body } = await platformRespond(path, BODY);
  state.result = await state.client.verifyCallback(headers, body, callbackUrl);
});

When('商户校验平台签名到另一路径的回调', async function () {
  state.client ??= freshClient();
  const { headers, body } = await platformRespond('/callback/other', BODY);
  state.result = await state.client.verifyCallback(headers, body, 'https://merchant.example.cn/callback/order?src=async');
});

// ---------- When（重放/传输，S11-S12）----------

When('商户以同参数再构造一次 L0 请求', async function () {
  state.draft2 = await state.client!.buildRequest('POST', PATH, BODY, { timestamp: 1, nonce: 'n', requestId: S11_REQUEST_ID });
});

When('平台返回超过 11MiB 上限的无限响应体', async function () {
  state.client ??= freshClient('WOP-RSA3072-SHA256');
  const originalFetch = globalThis.fetch;
  const chunk = new Uint8Array(1024 * 1024).fill(0x61); // 1MiB，无限入队 → 必越 11MiB
  globalThis.fetch = (async () =>
    new Response(
      new ReadableStream<Uint8Array>({
        pull: (c) => c.enqueue(chunk),
      }),
      { status: 200 },
    )) as unknown as typeof fetch;
  state.restoreFetch = () => {
    globalThis.fetch = originalFetch;
  };
  try {
    await new FetchTransport().send({ method: 'GET', url: 'https://gateway.test/p', headers: {}, body: '' });
  } catch (e) {
    state.sendError = (e as WopError).message;
  }
});

// ---------- Then（初始化）----------

Then('客户端构造成功', function () {
  assert.ok(state.client instanceof WopClient);
  assert.equal(state.initError, undefined);
});

Then('初始化失败并提示 {string}', function (fragment: string) {
  assert.ok(state.initError);
  assert.ok(state.initError.includes(fragment), `实际错误：${state.initError}`);
});

// ---------- Then（出向）----------

Then('网关侧公钥验签通过', async function () {
  assert.ok(await gatewayVerifyDraft(state.draft!.headers, 'POST', PATH, ''));
});

Then('线上体为原文', function () {
  assert.equal(state.draft!.wireBody, BODY);
});

Then('摘要头缺席且不入签', function () {
  assert.equal('x-wop-content-digest' in state.draft!.headers, false);
  assert.ok(!state.draft!.headers['x-wop-sign']!.includes('x-wop-content-digest'));
});

Then('线上体为单字段密文载体且网关解密回文为原文', async function () {
  assert.match(state.draft!.wireBody, /^\{"encrypted":"[A-Za-z0-9_-]+"\}$/);
  assert.equal(await gatewayDecryptDraft(state.draft!.headers, state.draft!.wireBody), BODY);
});

Then('两次请求完全一致', function () {
  assert.deepEqual(state.draft, state.draft2);
});

// ---------- Then（入向）----------

Then('校验通过且明文为原文', function () {
  assert.equal(state.result!.ok, true);
  assert.equal(state.result!.plaintext, BODY);
});

Then('校验失败且原因为 {string}', function (exact: string) {
  assert.equal(state.result!.ok, false);
  assert.equal(state.result!.reason, exact);
});

Then('校验失败且原因包含 {string}', function (fragment: string) {
  assert.equal(state.result!.ok, false);
  assert.ok(state.result!.reason!.includes(fragment), `实际原因：${state.result!.reason}`);
});

Then('失败原因不泄露验签或解密细节', function () {
  assert.ok(state.result!.reason);
  assert.doesNotMatch(state.result!.reason!, /OAEP|tag|padding|import|密钥不符/i);
});

// ---------- Then（传输）----------

Then('响应体读取被流式拒绝', function () {
  try {
    assert.ok(state.sendError!.includes(`${MAX_RESPONSE_BYTES}`));
  } finally {
    state.restoreFetch?.();
  }
});
