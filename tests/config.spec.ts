import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  load,
  loadDefault,
  clearCache,
  parseConfigJson,
  joinUrl,
  validateApiPath,
  CONFIG_FILE_ENV,
  CONFIG_FILE_ENV_OVERRIDE,
} from '../src/config';
import { WopClient } from '../src/client';
import { WopError } from '../src/error';
import { WopGatewayResponseError } from '../src/gatewayResponseError';
import { FetchTransport } from '../src/transport/fetch';
import { rsaSign } from '../src/crypto';
import { canonicalRequest } from '../src/canonical';
import { computeDigestHeader } from '../src/digest';
import { fromBase64, toBase64Url, utf8Encode } from '../src/encode';
import vectors from './fixtures/crypto-vectors.json';

const MERCH_PRIV = vectors.keys.rsa3072!.privatePkcs8B64;
const PLAT_PUB = vectors.keys.rsa3072!.publicSpkiB64;
const PLAT_PRIV = vectors.keys.rsa3072!.privatePkcs8B64;

export function validConfigJson(overrides: Record<string, unknown> = {}): string {
  const base = {
    appKey: 'app_001',
    suite: 'WOP-RSA3072-SHA256',
    merchantPrivateKey: MERCH_PRIV,
    platformPublicKey: PLAT_PUB,
    serverRoot: 'https://gw.example.com/gateway',
    backupServerRoots: ['https://gw-backup.example.com/gateway'],
    expiredSeconds: 1800,
    httpClient: { connectTimeout: 10000, readTimeout: 30000, maxRetryCount: 3 },
  };
  return JSON.stringify({ ...base, ...overrides });
}

function writeTempConfig(content: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wop-config-'));
  const file = path.join(dir, 'wopSdkConfig.json');
  fs.writeFileSync(file, content, 'utf8');
  return file;
}

describe('配置 JSON 解析与校验', () => {
  it('合法配置解析并归一化 serverRoot 尾斜杠', () => {
    const cfg = parseConfigJson(validConfigJson({ serverRoot: 'https://gw.example.com/gateway/' }));
    expect(cfg.serverRoot).toBe('https://gw.example.com/gateway');
    expect(cfg.backupServerRoots[0]).toBe('https://gw-backup.example.com/gateway');
    expect(cfg.httpClient.connectTimeout).toBe(10000);
  });

  it('重复键 fail-fast', () => {
    expect(() => parseConfigJson('{"appKey":"a","appKey":"b","suite":"WOP-RSA3072-SHA256"}')).toThrowError(
      /配置字段 appKey 重复/,
    );
  });

  it('缺少必填项 appKey', () => {
    expect(() =>
      parseConfigJson(
        JSON.stringify({
          suite: 'WOP-RSA3072-SHA256',
          merchantPrivateKey: MERCH_PRIV,
          platformPublicKey: PLAT_PUB,
          serverRoot: 'https://gw.example.com/gateway',
        }),
      ),
    ).toThrowError(/缺少必填项: appKey/);
  });

  it('serverRoot 非 HTTPS 拒绝', () => {
    expect(() => parseConfigJson(validConfigJson({ serverRoot: 'http://gw.example.com/gateway' }))).toThrowError(
      /须为 HTTPS 绝对 URL/,
    );
  });

  it('serverRoot 含 query 拒绝', () => {
    expect(() =>
      parseConfigJson(validConfigJson({ serverRoot: 'https://gw.example.com/gateway?x=1' })),
    ).toThrowError(/不得含 query 或 fragment/);
  });

  it('backupServerRoots 逐项校验索引', () => {
    expect(() =>
      parseConfigJson(validConfigJson({ backupServerRoots: ['http://bad.example.com/gateway'] })),
    ).toThrowError(/backupServerRoots\[0\] 须为 HTTPS 绝对 URL/);
  });

  it('expiredSeconds 非正整数拒绝', () => {
    expect(() => parseConfigJson(validConfigJson({ expiredSeconds: 0 }))).toThrowError(
      /配置字段 expiredSeconds 类型非法/,
    );
  });

  it('BOM 容忍', () => {
    const cfg = parseConfigJson('\uFEFF' + validConfigJson());
    expect(cfg.appKey).toBe('app_001');
  });

  it('成员间缺逗号拒绝（Sourcery CR：畸形 JSON 不得静默接受）', () => {
    expect(() => parseConfigJson('{"appKey":"a" "suite":"WOP-RSA3072-SHA256"}')).toThrowError(
      /期望 ',' 或 '}'/,
    );
  });

  it('尾随逗号拒绝', () => {
    expect(() => parseConfigJson('{"appKey":"a",}')).toThrowError(/尾随逗号/);
    // 合法单成员应通过解析阶段（缺其余必填项属后续语义校验）
    expect(() => parseConfigJson('{"appKey":"a"}')).not.toThrowError(/尾随逗号/);
  });

  it('根对象后尾随内容拒绝', () => {
    expect(() => parseConfigJson(validConfigJson() + 'garbage')).toThrowError(/根对象后存在多余内容/);
    expect(() => parseConfigJson(validConfigJson() + '\n\n  ')).not.toThrow(); // 尾部空白合法
  });
});

describe('ConfigLoader 缓存与发现', () => {
  const savedEnv = { ...process.env };

  beforeEach(() => {
    clearCache();
    WopClient.resetDefault();
    delete process.env[CONFIG_FILE_ENV];
    delete process.env[CONFIG_FILE_ENV_OVERRIDE];
  });

  afterEach(() => {
    process.env = { ...savedEnv };
    clearCache();
    WopClient.resetDefault();
  });

  it('load(path) 同一位置返回同一实例', () => {
    const file = writeTempConfig(validConfigJson());
    const a = load(file);
    const b = load(file);
    expect(a).toBe(b);
  });

  it('clearCache 后重新解析', () => {
    const file = writeTempConfig(validConfigJson({ appKey: 'first' }));
    const a = load(file);
    clearCache();
    fs.writeFileSync(file, validConfigJson({ appKey: 'second' }), 'utf8');
    const b = load(file);
    expect(a.appKey).toBe('first');
    expect(b.appKey).toBe('second');
    expect(a).not.toBe(b);
  });

  it('WOP_SDK_CONFIG_FILE 显式不可读立即报错', () => {
    process.env[CONFIG_FILE_ENV_OVERRIDE] = path.join(os.tmpdir(), 'missing-wop-config.json');
    expect(() => loadDefault()).toThrowError(/显式配置文件不可读/);
  });

  it('loadDefault 经 WOP_SDK_CONFIG 发现', () => {
    const file = writeTempConfig(validConfigJson({ appKey: 'from-env' }));
    process.env[CONFIG_FILE_ENV] = file;
    const cfg = loadDefault();
    expect(cfg.appKey).toBe('from-env');
  });
});

describe('WopClient 一站式入口', () => {
  beforeEach(() => {
    clearCache();
    WopClient.resetDefault();
  });

  afterEach(() => {
    clearCache();
    WopClient.resetDefault();
  });

  it('fromConfig 构造客户端', () => {
    const client = WopClient.fromConfig(parseConfigJson(validConfigJson()));
    expect(client.config.serverRoot).toBe('https://gw.example.com/gateway');
  });

  it('toString 私钥打码（K16）', () => {
    const client = WopClient.fromConfig(parseConfigJson(validConfigJson()));
    const text = client.toString();
    expect(text).not.toContain(MERCH_PRIV);
    expect(text).toContain('merchantPrivateKey=****');
  });

  it('defaultClient 缓存复用 + resetDefault 后重建', () => {
    const file = writeTempConfig(validConfigJson({ appKey: 'v1' }));
    process.env[CONFIG_FILE_ENV] = file;
    clearCache();
    const c1 = WopClient.defaultClient();
    const c2 = WopClient.defaultClient();
    expect(c1).toBe(c2);

    clearCache();
    WopClient.resetDefault();
    fs.writeFileSync(file, validConfigJson({ appKey: 'v2' }), 'utf8');
    const c3 = WopClient.defaultClient();
    expect(c3).not.toBe(c1);
    expect(c3.config.appKey).toBe('v2');
  });

  it('clearCache → resetDefault 后并发 defaultClient 加载新配置（K26）', async () => {
    const file = writeTempConfig(validConfigJson({ appKey: 'before' }));
    process.env[CONFIG_FILE_ENV] = file;
    clearCache();
    WopClient.resetDefault();
    WopClient.defaultClient();

    clearCache();
    WopClient.resetDefault();
    fs.writeFileSync(file, validConfigJson({ appKey: 'after' }), 'utf8');

    const clients = await Promise.all(
      Array.from({ length: 8 }, async () => WopClient.defaultClient()),
    );
    for (const c of clients) {
      expect(c.config.appKey).toBe('after');
    }
    expect(new Set(clients).size).toBe(1);
  });
});

describe('path 语法与 URL 拼接（§7.7）', () => {
  it('joinUrl 保留 context-path', () => {
    expect(joinUrl('https://gw.example.com/gateway', '/gateway/order/create')).toBe(
      'https://gw.example.com/gateway/gateway/order/create',
    );
  });

  it('拒绝 // 开头 path', () => {
    expect(() => validateApiPath('//attacker.example/path')).toThrowError(/不得 \/\/ 开头/);
  });

  it('path 含控制字符拒绝（CR/LF/NUL/DEL/其余 <0x20），不回显原值只回显码点', () => {
    const cases = ['/p\nFAKE', '/p\rFAKE', '/p\tFAKE', '/p\x00FAKE', '/p\x7FFAKE'];
    for (const bad of cases) {
      let err: WopError | undefined;
      try {
        validateApiPath(bad);
      } catch (e) {
        err = e as WopError;
      }
      expect(err, `path=${JSON.stringify(bad)}`).toBeInstanceOf(WopError);
      expect(err!.category, `path=${JSON.stringify(bad)}`).toBe('configuration');
      expect(err!.message, `path=${JSON.stringify(bad)}`).toMatch(/控制字符/);
      expect(err!.message, `path=${JSON.stringify(bad)}`).not.toContain('FAKE'); // 原值不回显（防日志二次注入）
    }
  });

  it('非字符串 path 抛 WopError 而非原生 TypeError（Sourcery CR）', () => {
    for (const bad of [null, undefined, 42, {}]) {
      expect(() => validateApiPath(bad as unknown as string)).toThrowError(WopError);
      expect(() => validateApiPath(bad as unknown as string)).not.toThrowError(TypeError);
    }
  });
});

describe('WopClient.execute', () => {
  it('非 2xx 抛 WopGatewayResponseError 且不内嵌 body 全文', async () => {
    const client = WopClient.fromConfig(parseConfigJson(validConfigJson()));
    const fetchMock = vi.fn(async () => new Response('error-body', { status: 502 }));
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    try {
      await expect(client.execute('POST', '/gateway/order/create', '{}')).rejects.toBeInstanceOf(
        WopGatewayResponseError,
      );
      try {
        await client.execute('POST', '/gateway/order/create', '{}');
      } catch (e) {
        expect((e as WopGatewayResponseError).statusCode).toBe(502);
        expect((e as WopGatewayResponseError).body).toBe('error-body');
        expect((e as Error).message).toMatch(/502/);
        expect((e as Error).message).not.toContain('error-body');
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('2xx 全链路 execute→verify', async () => {
    const client = WopClient.fromConfig(parseConfigJson(validConfigJson()));
    const PATH = '/gateway/order/create';
    const respBody = JSON.stringify({ code: 'SUCCESS' });
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

    const fetchMock = vi.fn(async () => new Response(respBody, { status: 200, headers }));
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    try {
      const result = await client.execute('POST', PATH, '{"orderId":"o1"}', { timestamp: 1, nonce: 'n' });
      expect(result.ok).toBe(true);
      expect(result.plaintext).toBe(respBody);
      const init = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1]!;
      expect(init.redirect).toBe('manual');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('serverRoot 未配置 → configuration', async () => {
    const client = new WopClient({
      appKey: 'ak',
      suite: 'WOP-RSA3072-SHA256',
      merchantPrivateKey: MERCH_PRIV,
      platformPublicKey: PLAT_PUB,
    });
    await expect(client.execute('POST', '/p', '{}')).rejects.toMatchObject({ category: 'configuration' });
  });
});

describe('FetchTransport 重定向关闭', () => {
  it('fetch 传 redirect manual', async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 302 }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    await new FetchTransport().send({ method: 'GET', url: 'https://x', headers: {}, body: '' });
    const init = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1]!;
    expect(init.redirect).toBe('manual');
  });
});
