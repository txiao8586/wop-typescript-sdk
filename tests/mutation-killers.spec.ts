import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  WopError,
  parseSecurityReq,
  keyMaterialToDer,
  verifyDigestHeader,
  computeDigestHeader,
  oaepWrap,
  buildDekPayload,
  fromBase64,
  fromBase64Url,
  fromHex,
  parseDekPayload,
  webcrypto,
  rsaSign,
  toBase64Url,
  utf8Encode,
} from '../src/index';
import { canonicalRequest } from '../src/canonical';
import { WopClient } from '../src/client';
import { FetchTransport } from '../src/transport/fetch';
import { AxiosTransport } from '../src/transport/axios';
import { platformRespond } from './features/steps/platform';
import type { AxiosInstance } from 'axios';
import vectors from './fixtures/crypto-vectors.json';

/**
 * 变异击杀测试：针对变异运行（tests/mutation/run-mutations.mjs）暴露的幸存点，
 * 以**消息全等**断言钉死错误文案、category、字段映射与边界值——这些是 spec
 * A6/I7 意义上的可观测契约（错误分类明确 vs 模糊），不是实现细节。
 *
 * 注意：vitest toThrowError(string) 是子串匹配，对追加式字符串变异天然逃逸；
 * 因此此处一律经 expectThrow 以 e.message 全等判定。
 */

const K = vectors.keys;
const MERCH_PRIV = K.rsa3072!.privatePkcs8B64;
const PLAT_PUB = K.rsa3072!.publicSpkiB64;
const RSA_SUITE = parseSecurityReq('WOP-RSA3072-SHA256');

/** 全等抛错断言：消息逐字节一致（杀字符串追加变异）；可选钉死 category */
function expectThrow(fn: () => unknown, exact: string, category?: string): void {
  try {
    fn();
  } catch (e) {
    expect((e as Error).message).toBe(exact);
    if (category !== undefined) {
      expect((e as WopError).category).toBe(category);
    }
    return;
  }
  expect.unreachable(`应抛出：${exact}`);
}

async function expectThrowAsync(fn: () => Promise<unknown>, exact: string): Promise<void> {
  try {
    await fn();
  } catch (e) {
    expect((e as Error).message).toBe(exact);
    return;
  }
  expect.unreachable(`应抛出：${exact}`);
}

describe('error.ts：错误分类与类型名（7 类 category 全等）', () => {
  it('七类 category 字面量全等 + name 恒为 WopError + 默认 parse', () => {
    const categories = [
      'parse',
      'unsupported',
      'integrity',
      'signature',
      'decrypt',
      'consistency',
      'system',
    ] as const;
    for (const c of categories) {
      const e = new WopError('msg', c);
      expect(e.category).toBe(c);
      expect(e.name).toBe('WopError');
      expect(e instanceof WopError).toBe(true);
    }
    expect(new WopError('msg').category).toBe('parse');
  });
});

describe('suite.ts：套件全字段映射与三段式守卫（F1，§3.2）', () => {
  it('WOP-RSA3072-SHA256 十字段全等', () => {
    const s = parseSecurityReq('WOP-RSA3072-SHA256');
    expect(s.securityReq).toBe('WOP-RSA3072-SHA256');
    expect(s.keyAlgorithm).toBe('RSA');
    expect(s.keyLength).toBe(3072);
    expect(s.digestAlgorithm).toBe('SHA256');
    expect(s.signAlgorithm).toBe('SHA256withRSA');
    expect(s.messageAlgorithm).toBe('AES-256-GCM');
    expect(s.keyWrapAlgorithm).toBe('RSA-3072-OAEP(SHA-256/MGF1-SHA-256)');
    expect(s.digestLabel).toBe('sha-256');
    expect(s.signatureB64uLength).toBe(512);
    expect(s.expectedDekAlg).toBe('AES-256-GCM');
  });

  it('WOP-RSA4096-SHA256 十字段全等', () => {
    const s = parseSecurityReq('WOP-RSA4096-SHA256');
    expect(s.securityReq).toBe('WOP-RSA4096-SHA256');
    expect(s.keyLength).toBe(4096);
    expect(s.keyWrapAlgorithm).toBe('RSA-4096-OAEP(SHA-256/MGF1-SHA-256)');
    expect(s.digestAlgorithm).toBe('SHA256');
    expect(s.signAlgorithm).toBe('SHA256withRSA');
    expect(s.messageAlgorithm).toBe('AES-256-GCM');
    expect(s.digestLabel).toBe('sha-256');
    expect(s.signatureB64uLength).toBe(683);
    expect(s.expectedDekAlg).toBe('AES-256-GCM');
  });

  it('三段式守卫消息全等：四段/缺段/前缀错/空段（F1）', () => {
    expectThrow(
      () => parseSecurityReq('WOP-RSA3072-SHA256-EXTRA'),
      'securityReq "WOP-RSA3072-SHA256-EXTRA" 格式错误：应为 WOP-<密钥算法>-<摘要算法> 三段式且前缀为 WOP',
      'parse',
    );
    expectThrow(
      () => parseSecurityReq('WOP-RSA3072-'),
      'securityReq "WOP-RSA3072-" 格式错误：应为 WOP-<密钥算法>-<摘要算法> 三段式且前缀为 WOP',
      'parse',
    );
    expectThrow(
      () => parseSecurityReq('RSA3072-SHA256'),
      'securityReq "RSA3072-SHA256" 格式错误：应为 WOP-<密钥算法>-<摘要算法> 三段式且前缀为 WOP',
      'parse',
    );
    expectThrow(
      () => parseSecurityReq('wop-rsa3072-sha256'),
      'securityReq "wop-rsa3072-sha256" 格式错误：应为 WOP-<密钥算法>-<摘要算法> 三段式且前缀为 WOP',
      'parse',
    );
  });

  it('支持类拒绝消息全等：SM2-SM3 暂未支持 / 组合不在列表 / 跨族（F1/Q7/I5）', () => {
    expectThrow(
      () => parseSecurityReq('WOP-SM2-SM3'),
      'SM2-SM3 套件暂未支持，见 README 路线图',
    );
    expectThrow(
      () => parseSecurityReq('WOP-SM2-SHA256'),
      '不支持的算法组合 "WOP-SM2-SHA256"：国际/国密跨族组合禁止（I5）',
    );
    expectThrow(
      () => parseSecurityReq('WOP-RSA3072-SM3'),
      '不支持的算法组合 "WOP-RSA3072-SM3"：国际/国密跨族组合禁止（I5）',
    );
    expectThrow(
      () => parseSecurityReq('WOP-RSA2048-SM3'),
      '不支持的算法组合 "WOP-RSA2048-SM3"：国际/国密跨族组合禁止（I5）',
    );
  });
});

describe('keys.ts：材料解析边界与文案全等（D12）', () => {
  it('非字符串入参文案全等 + category parse', () => {
    expectThrow(
      () => keyMaterialToDer(123 as unknown as string),
      '密钥材料须为字符串（PEM 或单行 Base64）',
      'parse',
    );
  });

  it('40 字符边界：b64 长度恰好 40 通过第一关、30B DER 触发第二关（文案可区分）', () => {
    expectThrow(
      () => keyMaterialToDer('A'.repeat(40)),
      '密钥 DER 内容过短，非合法 SPKI/PKCS8 材料',
      'parse',
    );
  });

  it('54 字符 b64 恰产 40 字节 DER：两道 40 阈值均放行', () => {
    const der = keyMaterialToDer('A'.repeat(54)); // floor(54*3/4)=40 字节
    expect(der.length).toBe(40);
  });

  it('空文案全等；非法字符落到 base64 家族文案（均全等 + parse）', () => {
    expectThrow(() => keyMaterialToDer(''), '密钥内容为空或过短', 'parse');
    expectThrow(
      () => keyMaterialToDer('A'.repeat(40) + '!!'),
      'base64 解码失败：输入含非法字符',
      'parse',
    );
  });
});

describe('encode.ts：六条错误文案全等（F7/D1）', () => {
  it('base64url 严格三态文案全等 + category parse', () => {
    expectThrow(
      () => fromBase64Url('ab=c'),
      'base64url 解码失败：输入含非法字符或填充符 "="',
      'parse',
    );
    expectThrow(() => fromBase64Url('a'), 'base64url 解码失败：长度非法（1 % 4 == 1）', 'parse');
    expectThrow(() => fromBase64Url('aE'), 'base64url 解码失败：非规范尾随位', 'parse');
  });

  it('标准 base64 与 hex 文案全等 + category parse', () => {
    expectThrow(() => fromBase64('ab*c'), 'base64 解码失败：输入含非法字符', 'parse');
    expectThrow(() => fromBase64('abcde'), 'base64 解码失败：长度非法（5 % 4 == 1）', 'parse');
    expectThrow(() => fromHex('0g'), 'hex 解码失败：非十六进制字符或奇数长度', 'parse');
  });
});

describe('digest.ts：格式钉五态文案全等（D2/I5）', () => {
  const HEX64 = 'a'.repeat(64);

  it('双空格/大写 hex/短 hex/未知标签（parse）/跨族（unsupported）全等', () => {
    expectThrow(
      () => verifyDigestHeader(`sha-256  ${HEX64}`, RSA_SUITE),
      `digest header "sha-256  ${HEX64}" 格式错误：算法标记与 hex 之间须恰好一个空格`,
      'parse',
    );
    expectThrow(
      () => verifyDigestHeader(`sha-256 ${'A'.repeat(64)}`, RSA_SUITE),
      `digest header "sha-256 ${'A'.repeat(64)}" 格式错误：hex 须为小写`,
      'parse',
    );
    expectThrow(
      () => verifyDigestHeader(`sha-256 ${'a'.repeat(63)}`, RSA_SUITE),
      `digest header "sha-256 ${'a'.repeat(63)}" 格式错误：hex 长度须为 64（SHA-256）`,
      'parse',
    );
    expectThrow(
      () => verifyDigestHeader(`sha256 ${HEX64}`, RSA_SUITE),
      `digest header "sha256 ${HEX64}" 格式错误：期望 <alg> <64 位小写 hex>，alg 随套件族（D2）`,
      'parse',
    );
    expectThrow(
      () => verifyDigestHeader(`sm3 ${HEX64}`, RSA_SUITE),
      `digest header "sm3 ${HEX64}" 与套件 WOP-RSA3072-SHA256 跨族：期望 sha-256（I5）`,
      'unsupported',
    );
  });
});

describe('envelope.ts：DEK 载荷段结构文案全等（§6.1）', () => {
  it('两段/空第三段 → 三段格式文案（段数守卫逐位可观测 + parse）', () => {
    expectThrow(
      () => parseDekPayload('AES-256-GCM$key'),
      'DEK 载荷格式错误："AES-256-GCM$key" 应为 alg$key$iv 三段',
      'parse',
    );
    expectThrow(
      () => parseDekPayload('AES-256-GCM$AAAA$'),
      'DEK 载荷格式错误："AES-256-GCM$AAAA$" 应为 alg$key$iv 三段',
      'parse',
    );
  });

  it('AES-256-GCM 密钥/IV 长度文案全等（32/12，parse）', () => {
    // 42 字符 b64 → 31 字节 key（%4==2 合法）；15 字符 → 11 字节 iv（%4==3 合法）
    expectThrow(
      () => parseDekPayload(`AES-256-GCM$${'A'.repeat(42)}$${'A'.repeat(16)}`),
      'DEK 载荷 AES-256-GCM 密钥长度非法：31 字节（须 32）',
      'parse',
    );
    expectThrow(
      () => parseDekPayload(`AES-256-GCM$${'A'.repeat(43)}$${'A'.repeat(15)}`),
      'DEK 载荷 AES-256-GCM IV 长度非法：11 字节（须 12）',
      'parse',
    );
  });
});

describe('client.ts：出向/入向错误文案全等（I7 纪律下协议类消息是契约）', () => {
  const makeClient = (overrides: Record<string, unknown> = {}): WopClient => {
    return new WopClient({
      appKey: 'ak',
      suite: 'WOP-RSA3072-SHA256',
      merchantPrivateKey: MERCH_PRIV,
      platformPublicKey: PLAT_PUB,
      ...overrides,
    } as ConstructorParameters<typeof WopClient>[0]);
  }

  it('sign 头无空格分隔 → 文案全等', async () => {
    const r = await makeClient().verifyResponse({ 'x-wop-sign': 'WOP-RSA3072-SHA256' }, '', '/p');
    expect(r.reason).toBe('x-wop-sign 格式错误：缺少 securityReq 与后续段的空格分隔');
  });

  it('构造器空密钥文案全等 + category parse（同步 throw 保留 WopError 对象）', () => {
    expectThrow(
      () => makeClient({ merchantPrivateKey: '' }),
      'merchantPrivateKey 不能为空（PKCS#8，PEM 或 Base64 单行）',
      'parse',
    );
    expectThrow(
      () => makeClient({ platformPublicKey: ' ' }),
      'platformPublicKey 不能为空（X.509 SPKI，PEM 或 Base64 单行）',
      'parse',
    );
  });

  it('serverRoot 未配置 send → 文案全等 + category configuration', async () => {
    await expect(makeClient().send('GET', '/p')).rejects.toMatchObject({
      message: 'serverRoot 未配置，无法发送（或直接消费 buildRequest 的 RequestDraft）',
      category: 'configuration',
    });
  });

  it('响应套件与配置不符 → 文案全等（套件一致性）', async () => {
    const headers: Record<string, string> = {
      'x-wop-sign': `WOP-RSA4096-SHA256 v1/1800/x-wop-nonce/${'A'.repeat(683)}`,
      'x-wop-nonce': 'n',
    };
    const r = await makeClient().verifyResponse(headers, '', '/p');
    expect(r.reason).toBe('响应套件 "WOP-RSA4096-SHA256" 与客户端配置 "WOP-RSA3072-SHA256" 不符');
  });

  it('有 body 缺 digest 头 → 文案全等（D2/I1）', async () => {
    const headers: Record<string, string> = {
      'x-wop-nonce': 'n',
      'x-wop-sign': `WOP-RSA3072-SHA256 v1/1800/x-wop-nonce/${'A'.repeat(512)}`,
    };
    const r = await makeClient().verifyResponse(headers, 'body-bytes', '/p');
    expect(r.reason).toBe('有 body 但缺少 x-wop-content-digest 头（D2/I1）');
  });

  it('签名解码字节 381 ≠ 384 → 定长文案全等（§3.3①）', async () => {
    const headers: Record<string, string> = {
      'x-wop-nonce': 'n',
      'x-wop-sign': `WOP-RSA3072-SHA256 v1/1800/x-wop-nonce/${'A'.repeat(508)}`, // 381B
    };
    const r = await makeClient().verifyResponse(headers, '', '/p');
    expect(r.reason).toBe('签名长度 381 字节与套件 WOP-RSA3072-SHA256 定长 384 字节不符');
  });

  it('L2 头缺 dek= → 文案全等', async () => {
    // 走到 L2 分支需要先过验签：平台私钥对（encrypt+nonce+timestamp）三头签名（无 body → 无 digest）
    const headers: Record<string, string> = {
      'x-wop-encrypt': 'L2-only',
      'x-wop-nonce': 'n',
      'x-wop-timestamp': '1',
    };
    const canonical = canonicalRequest({
      authString: 'v1/1800',
      method: 'POST',
      path: '/p',
      queryString: '',
      headers,
    });
    const sig = await rsaSign(fromBase64(vectors.keys.rsa3072!.privatePkcs8B64), utf8Encode(canonical));
    const signed = Object.keys(headers).sort().join(';');
    headers['x-wop-sign'] = `WOP-RSA3072-SHA256 v1/1800/${signed}/${toBase64Url(sig)}`;
    const r = await makeClient().verifyResponse(headers, '', '/p');
    expect(r.reason).toBe('x-wop-encrypt 格式错误：L2 须携带 dek=');
  });

  it('L2 body 非法 JSON / 缺 encrypted 字段 → 文案全等（F6⑤ 前置）', async () => {
    // 走到 L2 body 解析需要先过 DEK 解包（dek= 必须可解包且 alg 匹配）：
    const dek = fromBase64Url(vectors.inputs.aesKeyB64u!);
    const iv = fromBase64Url(vectors.inputs.aesIvB64u!);
    const wrapped = await oaepWrap(fromBase64(PLAT_PUB), utf8Encode(buildDekPayload('AES-256-GCM', dek, iv)));
    const mk = async (body: string): Promise<string> => {
      const h: Record<string, string> = {
        'x-wop-encrypt': `L2;dek=${toBase64Url(wrapped)}`,
        'x-wop-nonce': 'n',
        'x-wop-timestamp': '1',
      };
      if (body.length > 0) {
        h['x-wop-content-digest'] = await computeDigestHeader(body);
      }
      const names = Object.keys(h).sort();
      const canonical = canonicalRequest({
        authString: 'v1/1800',
        method: 'POST',
        path: '/p',
        queryString: '',
        headers: h,
      });
      const sig = await rsaSign(fromBase64(vectors.keys.rsa3072!.privatePkcs8B64), utf8Encode(canonical));
      h['x-wop-sign'] = `WOP-RSA3072-SHA256 v1/1800/${names.join(';')}/${toBase64Url(sig)}`;
      const r = await makeClient().verifyResponse(h, body, '/p');
      return r.reason ?? '';
    };
    expect(await mk('not-json')).toBe('L2 响应 body 不是合法 JSON（期望 {"encrypted":…}）');
    expect(await mk('{"other":1}')).toBe('L2 响应 body 缺少 encrypted 字段');
  });
  it('DEK alg 族不符 → 一致性文案全等（D8/I3/I5）', async () => {
    const { headers, body } = await platformRespond('/p', 'x', { level: 'L2', tamper: 'sm4alg' });
    const r = await makeClient().verifyResponse(headers, body, '/p');
    expect(r.reason).toBe(
      'DEK alg 与套件族不符：载荷 SM4-GCM，WOP-RSA3072-SHA256 期望 AES-256-GCM（I5/I3）',
    );
  });

  it('send 无签名响应：2xx 边界 299 ok / 300 拒（status 阈值双侧）', async () => {
    for (const [status, ok] of [[200, true], [299, true], [300, false], [400, false]] as const) {
      const client = makeClient({ gatewayBaseUrl: 'https://gw.test' });
      client.setTransport({
        send: async () => ({ status, headers: {}, body: '' }),
      });
      const r = await client.send('GET', '/p');
      expect(r.ok, `status=${status}`).toBe(ok);
      expect(r.status).toBe(status);
    }
  });
});

describe('transport：系统类错误 category 与流式 UTF-8 拼接（D4 注释契约）', () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('FetchTransport 网络错误：文案全等 + category system（杀 category 字面量变异）', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;
    const err = await new FetchTransport()
      .send({ method: 'GET', url: 'https://x', headers: {}, body: '' })
      .then(
        () => undefined,
        (e: unknown) => e,
      );
    expect((err as WopError).message).toBe('请求发送失败：fetch failed');
    expect((err as WopError).category).toBe('system');
  });

  it('AxiosTransport 网络错误 category === system（category 精确）', async () => {
    const request = vi.fn(async () => {
      throw new Error('connect ECONNREFUSED');
    });
    const t = new AxiosTransport({ request } as unknown as AxiosInstance);
    const p = t.send({ method: 'GET', url: 'https://x', headers: {}, body: '' });
    await expect(p).rejects.toMatchObject({ category: 'system' });
  });

  it('多字节 UTF-8 跨 chunk：stream 模式拼接正确（😀🚀 切 3+5 字节）', async () => {
    const bytes = new TextEncoder().encode('😀🚀');
    expect(bytes.length).toBe(8);
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(bytes.slice(0, 3)); // 切在第一个 emoji 的 UTF-8 序列中间
        c.enqueue(bytes.slice(3));
        c.close();
      },
    });
    globalThis.fetch = vi.fn(async () => new Response(stream, { status: 200 })) as unknown as typeof fetch;
    const resp = await new FetchTransport().send({ method: 'GET', url: 'https://x', headers: {}, body: '' });
    expect(resp.body).toBe('😀🚀');
  });
});

// Node 18 默认不启用全局 WebCrypto（Node 19+ 才默认开启），identity 断言仅在全局可用的运行时有意义；
// Node 18 下 crypto.ts 走 node:crypto.webcrypto 回退，由第二条用例覆盖。
const globalWebcrypto: Crypto | undefined = globalThis.crypto?.subtle ? globalThis.crypto : undefined;

describe.skipIf(!globalWebcrypto)('crypto.ts：webcrypto 直取全局（快路径 identity，Node ≥19）', () => {
  it('全局 subtle 存在时返回 globalThis.crypto 本体', async () => {
    expect(await webcrypto()).toBe(globalThis.crypto);
  });
});

describe('crypto.ts：webcrypto 回退契约（全 Node 版本）', () => {
  it('返回实现恒具备 subtle（Node 18 无全局时回退 node:crypto.webcrypto）', async () => {
    expect((await webcrypto()).subtle).toBeDefined();
  });
});
