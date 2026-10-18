import { describe, it, expect } from 'vitest';
import {
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
  privateDecrypt,
} from 'node:crypto';
import { rsaSign, rsaVerify, oaepWrap, oaepUnwrap, aesGcmDecrypt } from '../src/crypto';
import { parseDekPayload } from '../src/envelope';
import { fromBase64, fromBase64Url, utf8Encode, utf8Decode } from '../src/encode';
import { canonicalRequest } from '../src/canonical';
import { computeDigestHeader } from '../src/digest';
import { WopClient } from '../src/client';
import vectors from './fixtures/crypto-vectors.json';

/**
 * RSA2048 全链路（WOP-RSA2048-SHA256）：向量源自真源抽取并入 fixture（只读，禁手改）。
 * 覆盖：a) 签名字节级 + SIGNATURE_RAW_LENGTH[342]=256 消费；b) OAEP unwrap；
 * c) wrap→unwrap 与 L2 信封往返；d) WebCrypto 与 node:crypto 双实现一致性。
 */
const K = vectors.keys.rsa2048!;
const MSG = utf8Encode(vectors.inputs.message!);
const priv2048 = fromBase64(K.privatePkcs8B64);
const pub2048 = fromBase64(K.publicSpkiB64);

function client2048(): WopClient {
  return new WopClient({
    appKey: 'ak-2048',
    suite: 'WOP-RSA2048-SHA256',
    merchantPrivateKey: K.privatePkcs8B64,
    platformPublicKey: K.publicSpkiB64,
  });
}

describe('RSA2048 全链路（WOP-RSA2048-SHA256）', () => {
  it('a) 签名字节级一致：sigLenBytes=256 / b64uLen=342（SIGNATURE_RAW_LENGTH 342→256）', async () => {
    const vec = vectors.signature.find((s) => s.id === 'rsa2048-sign')!;
    const sig = await rsaSign(priv2048, MSG);
    expect(sig.length).toBe(vec.sigLenBytes);
    expect(sig.length).toBe(256); // SIGNATURE_RAW_LENGTH[342] = 256
    const b64u = Buffer.from(sig).toString('base64url');
    expect(b64u.length).toBe(vec.b64uLen);
    expect(b64u.length).toBe(342);
    expect(b64u).toBe(vec.expectedSigB64u);
  });

  it('a) verifyResponse 消费 342→256 定长映射：2048 签名响应验签通过', async () => {
    const client = client2048();
    const PATH = '/v1/order/query';
    const respBody = JSON.stringify({ code: 'SUCCESS' });
    const headers: Record<string, string> = {
      'x-wop-nonce': 'pn',
      'x-wop-timestamp': '1',
      'x-wop-content-digest': await computeDigestHeader(respBody),
    };
    const canonical = canonicalRequest({
      authString: 'v1/1800',
      method: 'POST',
      path: PATH,
      queryString: '',
      headers,
    });
    const sig = await rsaSign(priv2048, utf8Encode(canonical));
    headers['x-wop-sign'] = `WOP-RSA2048-SHA256 v1/1800/${Object.keys(headers).sort().join(';')}/${Buffer.from(sig).toString('base64url')}`;
    const r = await client.verifyResponse(headers, respBody, PATH);
    expect(r.ok).toBe(true);
    expect(r.plaintext).toBe(respBody);
  });

  it('b) oaep2048-unwrap：cipherB64u 解密 == expectedPlaintext', async () => {
    const vec = vectors.keyEncrypt.find((k) => k.id === 'oaep2048-unwrap')!;
    const plain = await oaepUnwrap(priv2048, fromBase64Url(vec.cipherB64u!));
    expect(utf8Decode(plain)).toBe(vec.expectedPlaintext);
  });

  it('c) 2048 OAEP wrap→unwrap 往返（密文恒 256B）', async () => {
    const payload = vectors.inputs.dekPayloadRsa!;
    const wrapped = await oaepWrap(pub2048, utf8Encode(payload));
    expect(wrapped.length).toBe(256);
    expect(utf8Decode(await oaepUnwrap(priv2048, wrapped))).toBe(payload);
  });

  it('c) L2 封装往返：buildRequest L2 → 平台侧解信封 == 原文', async () => {
    const client = client2048();
    const BODY = '{"orderId":"o2048","amount":1}';
    const dek = fromBase64Url(vectors.inputs.aesKeyB64u!);
    const iv = fromBase64Url(vectors.inputs.aesIvB64u!);
    const draft = await client.buildRequest('POST', '/v1/order/create', BODY, {
      level: 'L2',
      timestamp: 1,
      nonce: 'n2048',
      dek,
      iv,
    });
    // 平台侧：解 x-wop-encrypt 的 DEK（OAEP 解包）→ 解析载荷 → 解 wireBody
    const enc = draft.headers['x-wop-encrypt']!;
    expect(enc.startsWith('L2;dek=')).toBe(true);
    const dekPayload = utf8Decode(await oaepUnwrap(priv2048, fromBase64Url(enc.slice('L2;dek='.length))));
    expect(dekPayload).toBe(vectors.inputs.dekPayloadRsa); // 与向量 alg$key$iv 拼接一致
    const parsed = parseDekPayload(dekPayload);
    expect(Buffer.from(parsed.key).equals(Buffer.from(dek))).toBe(true);
    expect(Buffer.from(parsed.iv).equals(Buffer.from(iv))).toBe(true);
    const wire = JSON.parse(draft.wireBody) as { encrypted: string };
    expect(utf8Decode(await aesGcmDecrypt(parsed.key, parsed.iv, fromBase64Url(wire.encrypted)))).toBe(BODY);
  });

  it('d) WebCrypto 与 node:crypto 双实现一致：签名互验 + OAEP 同明文', async () => {
    const privKeyObj = createPrivateKey({ key: Buffer.from(priv2048), format: 'der', type: 'pkcs8' });
    const pubKeyObj = createPublicKey({ key: Buffer.from(pub2048), format: 'der', type: 'spki' });
    // node:crypto 验 WebCrypto 黄金签名
    const vec = vectors.signature.find((s) => s.id === 'rsa2048-sign')!;
    expect(nodeVerify('RSA-SHA256', Buffer.from(MSG), pubKeyObj, Buffer.from(fromBase64Url(vec.expectedSigB64u!)))).toBe(true);
    // node:crypto 签名 → SDK（WebCrypto）验签
    const nodeSig = nodeSign('RSA-SHA256', Buffer.from(MSG), privKeyObj);
    expect(await rsaVerify(pub2048, new Uint8Array(nodeSig), MSG)).toBe(true);
    // node:crypto OAEP（oaepHash=SHA-256，MGF1 随之）解包 == 向量明文
    const kv = vectors.keyEncrypt.find((k) => k.id === 'oaep2048-unwrap')!;
    const nodePlain = privateDecrypt({ key: privKeyObj, oaepHash: 'sha256' }, Buffer.from(fromBase64Url(kv.cipherB64u!)));
    expect(nodePlain.toString('utf8')).toBe(kv.expectedPlaintext);
  });
});
