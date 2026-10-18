import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { FetchTransport, MAX_RESPONSE_BYTES } from '../src/transport/fetch';
import type { Transport } from '../src/transport/types';
import { AxiosTransport } from '../src/transport/axios';
import { WopClient } from '../src/client';
import { rsaSign } from '../src/crypto';
import { canonicalRequest } from '../src/canonical';
import { computeDigestHeader } from '../src/digest';
import { WopError } from '../src/error';
import { fromBase64, toBase64Url, utf8Encode } from '../src/encode';
import vectors from './fixtures/crypto-vectors.json';

const PLAT_PRIV = vectors.keys.rsa3072!.privatePkcs8B64; // 套件一致纪律：响应签名套件须与客户端配置一致（interop n11）

describe('FetchTransport（原生 fetch 适配器）', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('透传 method/url/headers/body，响应头小写化', async () => {
    const fetchMock = vi.fn(async () =>
      new Response('{"ok":true}', {
        status: 200,
        headers: { 'X-Wop-Sign': 'WOP-RSA3072-SHA256 v1/1/a/AAAA', 'Content-Type': 'application/json' },
      }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const t = new FetchTransport();
    const resp = await t.send({
      method: 'POST',
      url: 'https://gw.example.com/v1/x',
      headers: { 'x-wop-appkey': 'ak' },
      body: '{"a":1}',
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://gw.example.com/v1/x');
    expect(init.method).toBe('POST');
    expect(init.headers).toEqual({ 'x-wop-appkey': 'ak' });
    expect(init.body).toBe('{"a":1}');
    expect(init.redirect).toBe('manual');
    expect(resp.status).toBe(200);
    expect(resp.headers['x-wop-sign']).toBe('WOP-RSA3072-SHA256 v1/1/a/AAAA');
    expect(resp.body).toBe('{"ok":true}');
  });

  it('空 body 时不携带 body 字段（GET 语义）', async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const resp = await new FetchTransport().send({
      method: 'GET',
      url: 'https://gw.example.com/p',
      headers: {},
      body: '',
    });
    const init = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1]!;
    expect(init.body).toBeUndefined();
    expect(resp.status).toBe(204);
    expect(resp.body).toBe('');
  });

  it('网络错误 → 系统类 WopError', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;
    await expect(
      new FetchTransport().send({ method: 'GET', url: 'https://x', headers: {}, body: '' }),
    ).rejects.toThrowError(/请求发送失败/);
  });
});

describe('FetchTransport 响应超时（防无限挂起）', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('send 恒携带 AbortSignal.timeout（默认与显式构造均接线）', async () => {
    const fetchMock = vi.fn(async () => new Response('ok', { status: 200 }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    await new FetchTransport().send({ method: 'GET', url: 'https://x', headers: {}, body: '' });
    await new FetchTransport(60_000).send({ method: 'GET', url: 'https://x', headers: {}, body: '' });
    for (const call of fetchMock.mock.calls as unknown as [string, RequestInit][]) {
      expect(call[1]!.signal).toBeInstanceOf(AbortSignal);
    }
  });

  it('挂起服务器 + readTimeoutMs=50 → 系统类错误快速失败（真实 fetch）', async () => {
    const server = http.createServer(() => {
      /* 收到请求但不响应：模拟网关挂起 */
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const { port } = server.address() as AddressInfo;
    const t0 = Date.now();
    let caught: unknown;
    try {
      await new FetchTransport(50).send({
        method: 'GET',
        url: `http://127.0.0.1:${port}/hang`,
        headers: {},
        body: '',
      });
    } catch (e) {
      caught = e;
    } finally {
      server.close();
    }
    expect(caught).toBeInstanceOf(WopError);
    expect((caught as WopError).category).toBe('system');
    expect((caught as WopError).message).toMatch(/请求发送失败/);
    expect(Date.now() - t0).toBeLessThan(5_000);
  });

  it('WopClient 默认传输接收配置 readTimeout（httpClient → AbortSignal）', async () => {
    const server = http.createServer(() => {
      /* 挂起 */
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const { port } = server.address() as AddressInfo;
    const client = new WopClient({
      appKey: 'ak',
      suite: 'WOP-RSA3072-SHA256',
      merchantPrivateKey: vectors.keys.rsa3072!.privatePkcs8B64,
      platformPublicKey: vectors.keys.rsa3072!.publicSpkiB64,
      gatewayBaseUrl: `http://127.0.0.1:${port}`,
      httpClient: { connectTimeout: 1_000, readTimeout: 50, maxRetryCount: 0 },
    });
    const t0 = Date.now();
    try {
      await expect(client.send('GET', '/hang')).rejects.toMatchObject({ category: 'system' });
    } finally {
      server.close();
    }
    expect(Date.now() - t0).toBeLessThan(5_000);
  });
});

describe('AxiosTransport（peer 适配器，mock axios）', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('透传请求并归一响应（2xx）', async () => {
    const request = vi.fn(async () => ({
      status: 200,
      headers: { 'X-Wop-Sign': 's', Set_Cookie: ['a=1', 'b=2'] },
      data: 'raw-text',
    }));
    const { AxiosTransport } = await import('../src/transport/axios');
    const t = new AxiosTransport({ request } as unknown as import('axios').AxiosInstance);
    const resp = await t.send({ method: 'POST', url: 'https://gw/v1', headers: { k: 'v' }, body: 'b' });
    expect(request).toHaveBeenCalledWith(
      expect.objectContaining({
        url: 'https://gw/v1',
        method: 'POST',
        responseType: 'text',
        maxContentLength: MAX_RESPONSE_BYTES,
      }),
    );
    expect(resp.status).toBe(200);
    expect(resp.headers['x-wop-sign']).toBe('s');
    expect(resp.headers['set_cookie']).toBe('a=1, b=2');
    expect(resp.body).toBe('raw-text');
  });

  it('非 2xx（axios 抛错带 response）降级为结构化返回', async () => {
    const request = vi.fn(async () => {
      throw Object.assign(new Error('Request failed with status code 500'), {
        response: { status: 500, headers: { 'X-Trace-Id': 't1' }, data: 'boom' },
      });
    });
    const { AxiosTransport } = await import('../src/transport/axios');
    const t = new AxiosTransport({ request } as unknown as import('axios').AxiosInstance);
    const resp = await t.send({ method: 'GET', url: 'https://gw/e', headers: {}, body: '' });
    expect(resp.status).toBe(500);
    expect(resp.headers['x-trace-id']).toBe('t1');
    expect(resp.body).toBe('boom');
  });

  it('网络错误（无 response）→ 系统类错误', async () => {
    const request = vi.fn(async () => {
      throw new Error('connect ECONNREFUSED');
    });
    const { AxiosTransport } = await import('../src/transport/axios');
    const t = new AxiosTransport({ request } as unknown as import('axios').AxiosInstance);
    await expect(t.send({ method: 'GET', url: 'https://x', headers: {}, body: '' })).rejects.toThrowError(
      /请求发送失败/,
    );
  });

  it('非字符串 data（transformResponse 被绕过时）序列化为文本', async () => {
    const request = vi.fn(async () => ({ status: 200, headers: {}, data: { a: 1 } }));
    const { AxiosTransport } = await import('../src/transport/axios');
    const t = new AxiosTransport({ request } as unknown as import('axios').AxiosInstance);
    const resp = await t.send({ method: 'GET', url: 'https://x', headers: {}, body: '' });
    expect(resp.body).toBe('{"a":1}');
  });
});

describe('响应体 11MiB 上限（与 dotnet MaxResponseBytes / Go maxResponseBytes 对齐）', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('FetchTransport：恰好 11MiB 收下（边界，=）', async () => {
    const body = 'a'.repeat(MAX_RESPONSE_BYTES);
    globalThis.fetch = vi.fn(async () => new Response(body, { status: 200 })) as unknown as typeof fetch;
    const resp = await new FetchTransport().send({ method: 'GET', url: 'https://x', headers: {}, body: '' });
    expect(resp.status).toBe(200);
    expect(resp.body).toHaveLength(MAX_RESPONSE_BYTES);
  });

  it('FetchTransport：无限流越限（11MiB+1 起）——读取过程中断流并抛协议类错误', async () => {
    const chunk = new Uint8Array(1024 * 1024).fill(0x61); // 1MiB
    let pulls = 0;
    let cancelled = false;
    const infinite = new ReadableStream<Uint8Array>({
      // 无限源：若非流式计数中途断流，本测试永不结束
      pull: (c) => {
        pulls++;
        c.enqueue(chunk);
      },
      cancel: () => {
        cancelled = true;
      },
    });
    globalThis.fetch = vi.fn(async () => new Response(infinite, { status: 200 })) as unknown as typeof fetch;
    let caught: unknown;
    try {
      await new FetchTransport().send({ method: 'GET', url: 'https://x', headers: {}, body: '' });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(WopError);
    expect((caught as WopError).category).toBe('parse');
    expect((caught as WopError).message).toContain(`响应体超过 ${MAX_RESPONSE_BYTES} 字节上限`);
    expect(cancelled).toBe(true); // 越限即取消下载，而非读完再查
    expect(pulls).toBeLessThanOrEqual(13); // 11MiB 恰不触发，第 12 个 chunk 越限即断（+1 预读水位）
  });

  it('FetchTransport：取消失败不掩盖超限语义（cancel reject 路径）', async () => {
    const chunk = new Uint8Array(1024 * 1024).fill(0x61);
    const infinite = new ReadableStream<Uint8Array>({
      pull: (c) => c.enqueue(chunk),
      cancel: () => {
        throw new Error('cancel failed');
      },
    });
    globalThis.fetch = vi.fn(async () => new Response(infinite, { status: 200 })) as unknown as typeof fetch;
    await expect(
      new FetchTransport().send({ method: 'GET', url: 'https://x', headers: {}, body: '' }),
    ).rejects.toThrowError(/响应体超过/);
  });

  it('AxiosTransport（真实 axios + 本地 HTTP）：越限（11MiB+1）映射为协议类错误', async () => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(Buffer.alloc(MAX_RESPONSE_BYTES + 1, 0x61));
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const { port } = server.address() as AddressInfo;
    let caught: unknown;
    try {
      await new AxiosTransport().send({ method: 'GET', url: `http://127.0.0.1:${port}/big`, headers: {}, body: '' });
    } catch (e) {
      caught = e;
    } finally {
      server.close();
    }
    expect(caught).toBeInstanceOf(WopError);
    expect((caught as WopError).category).toBe('parse');
    expect((caught as WopError).message).toContain(`响应体超过 ${MAX_RESPONSE_BYTES} 字节上限`);
  });

  it('AxiosTransport（真实 axios + 本地 HTTP）：恰好 11MiB 收下（边界，=）', async () => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(Buffer.alloc(MAX_RESPONSE_BYTES, 0x61));
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const { port } = server.address() as AddressInfo;
    try {
      const resp = await new AxiosTransport().send({
        method: 'GET',
        url: `http://127.0.0.1:${port}/exact`,
        headers: {},
        body: '',
      });
      expect(resp.status).toBe(200);
      expect(resp.body).toHaveLength(MAX_RESPONSE_BYTES);
    } finally {
      server.close();
    }
  });
});

describe('WopClient.send（Transport 编排）', () => {
  it('serverRoot 未配置 → configuration 错误', async () => {
    const client = new WopClient({
      appKey: 'ak',
      suite: 'WOP-RSA3072-SHA256',
      merchantPrivateKey: vectors.keys.rsa3072!.privatePkcs8B64,
      platformPublicKey: vectors.keys.rsa3072!.publicSpkiB64,
    });
    await expect(client.send('POST', '/p', '{"a":1}')).rejects.toMatchObject({ category: 'configuration' });
  });

  it('默认 FetchTransport：全链路 send→verify（mock fetch 返回已签名响应）', async () => {
    const client = new WopClient({
      appKey: 'ak',
      suite: 'WOP-RSA3072-SHA256',
      merchantPrivateKey: vectors.keys.rsa3072!.privatePkcs8B64,
      platformPublicKey: vectors.keys.rsa3072!.publicSpkiB64,
      gatewayBaseUrl: 'https://gw.example.com',
    });
    const PATH = '/v1/order/create';
    const respBody = JSON.stringify({ code: 'SUCCESS' });
    // 平台侧签名响应
    const headers: Record<string, string> = {
      'x-wop-nonce': 'pn',
      'x-wop-timestamp': '1',
      'x-wop-content-digest': await computeDigestHeader(respBody),
    };
    const signed = Object.keys(headers).sort();
    const canonical = canonicalRequest({
      authString: 'v1/1800',
      method: 'POST',
      path: PATH,
      queryString: '',
      headers,
    });
    const sig = await rsaSign(fromBase64(PLAT_PRIV), utf8Encode(canonical));
    headers['x-wop-sign'] = `WOP-RSA3072-SHA256 v1/1800/${signed.join(';')}/${toBase64Url(sig)}`;

    const fetchMock = vi.fn(async () =>
      new Response(respBody, { status: 200, headers }),
    );
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    try {
      const result = await client.send('POST', PATH, '{"orderId":"o1"}', { timestamp: 1, nonce: 'n' });
      expect(result.status).toBe(200);
      expect(result.ok).toBe(true);
      expect(result.plaintext).toBe(respBody);
      const [url] = (fetchMock.mock.calls[0] as unknown as [string, RequestInit]);
      expect(url).toBe(`https://gw.example.com${PATH}`);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('自定义 Transport 注入 + 非 2xx 无签名响应 → ok=false 不抛', async () => {
    const client = new WopClient({
      appKey: 'ak',
      suite: 'WOP-RSA3072-SHA256',
      merchantPrivateKey: vectors.keys.rsa3072!.privatePkcs8B64,
      platformPublicKey: vectors.keys.rsa3072!.publicSpkiB64,
      gatewayBaseUrl: 'https://gw',
    });
    const mockTransport: Transport = {
      send: async () => ({ status: 503, headers: {}, body: 'service unavailable' }),
    };
    client.setTransport(mockTransport);
    const result = await client.send('GET', '/health');
    expect(result.status).toBe(503);
    expect(result.ok).toBe(false);
    expect(result.body).toBe('service unavailable');
  });
});
