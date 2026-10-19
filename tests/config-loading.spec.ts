import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { parseConfigJson } from '../src/config/configJsonParser';
import { buildConfig, validateAndNormalize } from '../src/config/configValidator';
import {
  load,
  loadDefault,
  clearCache,
  CONFIG_FILE_ENV,
  CONFIG_FILE_ENV_OVERRIDE,
} from '../src/config/loader';
import { validateGatewayUrl, validateApiPath, joinUrl } from '../src/config/url';
import { WopClient } from '../src/client';
import { WopError } from '../src/error';
import { validConfigJson } from './config.spec';

// validator 密钥解析的 String(e) 分支：非 Error 抛出物归一
vi.mock('../src/keys', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../src/keys')>();
  return {
    ...orig,
    keyMaterialToDer: (input: Parameters<typeof orig.keyMaterialToDer>[0]) => {
      if (input === 'not-an-error') {
        throw 'plain-string';
      }
      return orig.keyMaterialToDer(input);
    },
  };
});

function writeConfig(dir: string, name: string, content: string): string {
  fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, 'utf8');
  return file;
}

beforeEach(() => clearCache());
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe('parser：文本与转义', () => {
  it.each([
    [null, '空内容'],
    [undefined, '空内容'],
    ['   ', '空文件'],
    ['[1,2]', '{'],
  ])('畸形输入 %p 被拒', (input, msg) => {
    expect(() => parseConfigJson(input as string)).toThrowError(new RegExp(msg));
  });

  it('全转义序列 round-trip', () => {
    const cfg = parseConfigJson(validConfigJson({ appKey: 'a"b\\c/d\be\ff\ng\rh\ti' }));
    expect(cfg.appKey).toBe('a"b\\c/d\be\ff\ng\rh\ti');
  });

  it('unicode 转义与多层转义', () => {
    const raw = JSON.stringify({
      appKey: '中A',
      suite: 'WOP-RSA3072-SHA256',
      merchantPrivateKey: JSON.parse(validConfigJson()).merchantPrivateKey,
      platformPublicKey: JSON.parse(validConfigJson()).platformPublicKey,
      serverRoot: 'https://gw.example.com/gateway',
    }).replace('中A', '\\u4e2d\\u0041');
    expect(parseConfigJson(raw).appKey).toBe('中A');
  });

  it.each([
    ['\\u12', '转义非法'],
    ['\\uZZZZ', '转义非法'],
    ['\\x41', '非法转义'],
    ['\\q', '非法转义'],
  ])('转义负例 %p', (esc, msg) => {
    const raw = validConfigJson().replace('app_001', esc);
    expect(() => parseConfigJson(raw)).toThrowError(new RegExp(msg));
  });

  it('字符串未闭合', () => {
    const raw = validConfigJson().slice(0, -2);
    expect(() => parseConfigJson(raw)).toThrowError(/解析失败/);
  });
});

describe('parser：结构与数值', () => {
  it('backupServerRoots 空数组与多元素', () => {
    expect(parseConfigJson(validConfigJson({ backupServerRoots: [] })).backupServerRoots).toEqual([]);
    const multi = parseConfigJson(
      validConfigJson({ backupServerRoots: ['https://a.example.com/gw', 'https://b.example.com/gw'] }),
    );
    expect(multi.backupServerRoots).toHaveLength(2);
  });

  it('httpClient 各键与未知键并存', () => {
    const cfg = parseConfigJson(
      validConfigJson({
        httpClient: { connectTimeout: 1, readTimeout: 2, maxRetryCount: 0, unknown: { nested: [true, false, null, 's', 42] } },
      }),
    );
    expect(cfg.httpClient).toEqual({ connectTimeout: 1, readTimeout: 2, maxRetryCount: 0 });
  });

  it.each([
    ['1e5', '解析失败'],
    ['1.5', '解析失败'],
    ['-1', '类型非法'],
    ['0', '类型非法'],
  ])('readLong 拒 %p', (num, msg) => {
    const raw = validConfigJson().replace('"expiredSeconds":1800', `"expiredSeconds":${num}`);
    expect(() => parseConfigJson(raw)).toThrowError(new RegExp(msg));
  });

  it('readInt 越界拒', () => {
    const raw = validConfigJson().replace('"connectTimeout":10000', '"connectTimeout":2147483648');
    expect(() => parseConfigJson(raw)).toThrowError('数值越界');
  });

  it('值意外结束', () => {
    expect(() => parseConfigJson('{"appKey": ')).toThrowError();
  });
});

describe('validator：必填与语义', () => {
  const base = () => JSON.parse(validConfigJson());

  it.each(['appKey', 'suite', 'merchantPrivateKey', 'platformPublicKey', 'serverRoot'])(
    '缺必填 %s',
    (field) => {
      const raw = { ...base(), [field]: '  ' };
      expect(() => validateAndNormalize(raw)).toThrowError(new RegExp(field));
    },
  );

  it.each([
    ['expiredSeconds', -1, 'expiredSeconds'],
    ['suite', 'WOP-FAKE-1', '不支持的算法套件'],
    ['merchantPrivateKey', 'not-a-key', '密钥解析失败'],
  ])('语义负例 %s', (field, value, msg) => {
    const raw = { ...base(), [field]: value };
    expect(() => validateAndNormalize(raw)).toThrowError(new RegExp(msg as string));
  });

  it('backupServerRoots 逐项校验并携带下标', () => {
    const raw = { ...base(), backupServerRoots: ['https://ok.example.com/gw', 'ftp://bad.example.com'] };
    expect(() => validateAndNormalize(raw)).toThrowError(/backupServerRoots\[1\]/);
  });

  it('httpClient 越界与 transport 透传', () => {
    const raw = { ...base(), httpClient: { connectTimeout: -1, readTimeout: 30, maxRetryCount: 0 } };
    expect(() => validateAndNormalize(raw)).toThrowError('httpClient');
    const sentinel = {} as never;
    const cfg = buildConfig({ ...base(), transport: sentinel });
    expect(cfg.transport).toBe(sentinel);
    expect(Object.isFrozen(cfg.backupServerRoots)).toBe(true);
  });
});

describe('loader：发现与读取', () => {
  it('空路径拒', () => {
    expect(() => load('')).toThrowError('路径不能为空');
  });

  it('env override 与 env 命中', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wop-loader-'));
    const file = writeConfig(dir, 'cfg.json', validConfigJson());
    process.env[CONFIG_FILE_ENV_OVERRIDE] = file;
    clearCache();
    expect(loadDefault().appKey).toBe('app_001');
    delete process.env[CONFIG_FILE_ENV_OVERRIDE];
    process.env[CONFIG_FILE_ENV] = file;
    clearCache();
    expect(loadDefault().appKey).toBe('app_001');
    delete process.env[CONFIG_FILE_ENV];
    expect(load(file).appKey).toBe('app_001');
  });

  it('cwd 候选命中', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wop-cwd-'));
    writeConfig(dir, 'wopSdkConfig.json', validConfigJson());
    const cwd = process.cwd();
    process.chdir(dir);
    try {
      clearCache();
      expect(loadDefault().appKey).toBe('app_001');
    } finally {
      process.chdir(cwd);
    }
  });

  it('候选存在但不可读则跳过', () => {
    // chmod 0o000 在 windows 无 POSIX 语义：改拦 accessSync（平台无关）
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wop-noperm-'));
    writeConfig(dir, 'config/wopSdkConfig.json', '{ bad');
    writeConfig(dir, 'wopSdkConfig.json', validConfigJson());
    const cwd = process.cwd();
    process.chdir(dir);
    const acc = vi.spyOn(fs, 'accessSync').mockImplementation((p) => {
      if (String(p).includes(`config${path.sep}`)) throw new Error('EACCES: mocked');
    });
    try {
      clearCache();
      expect(loadDefault().appKey).toBe('app_001');
    } finally {
      acc.mockRestore();
      process.chdir(cwd);
    }
  });

  it('显式路径不存在', () => {
    expect(() => load(path.join(os.tmpdir(), 'wop-none', 'no.json'))).toThrowError('显式配置文件不可读');
  });

  it('readFileSync 失败归一', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wop-io-'));
    const file = writeConfig(dir, 'cfg.json', validConfigJson());
    vi.spyOn(fs, 'readFileSync').mockImplementation(() => {
      throw new Error('disk');
    });
    clearCache();
    expect(() => load(file)).toThrowError('读取失败');
  });

  it('全部来源缺失时 fail-fast', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'wop-empty-'));
    vi.stubEnv('HOME', empty);
    vi.stubEnv(CONFIG_FILE_ENV_OVERRIDE, '');
    vi.stubEnv(CONFIG_FILE_ENV, '');
    clearCache();
    expect(() => loadDefault()).toThrowError('未找到可读的配置文件');
  });

});

describe('url：校验与归一', () => {
  it.each([
    [null],
    ['  '],
    ['not a url'],
  ])('validateGatewayUrl 拒 %p', (v) => {
    expect(() => validateGatewayUrl(v as string, 'serverRoot')).toThrowError('不是合法 URL');
  });

  it('协议与端口归一', () => {
    expect(validateGatewayUrl('https://GW.Example.com:8443/gateway/', 'x')).toBe(
      'https://gw.example.com:8443/gateway',
    );
    expect(() => validateGatewayUrl('http://gw.example.com', 'x')).toThrowError('HTTPS');
    expect(() => validateGatewayUrl('https://gw.example.com/?q=1', 'x')).toThrowError('query');
    expect(() => validateGatewayUrl('https://gw.example.com/#f', 'x')).toThrowError('fragment');
  });

  it('validateApiPath 语法域', () => {
    expect(() => validateApiPath('/a?b')).toThrowError('query');
    expect(() => validateApiPath('/a#b')).toThrowError('fragment');
    expect(() => validateApiPath('HTTPS://x.com/p')).toThrowError('绝对 URL');
    expect(validateApiPath('/v1/order')).toBeUndefined();
    expect(joinUrl('https://gw.example.com/gateway', '/v1/order')).toBe(
      'https://gw.example.com/gateway/v1/order',
    );
  });
});

describe('client：fromConfig 与 toString 默认兜底', () => {
  it('fromConfig 透传 transport', () => {
    const cfg = buildConfig(JSON.parse(validConfigJson()));
    const client = WopClient.fromConfig({ ...cfg, transport: { send: vi.fn() } as never });
    expect(client).toBeInstanceOf(WopClient);
  });

  it('toString 打码且缺省字段兜底不抛', () => {
    const raw = JSON.parse(validConfigJson());
    delete raw.backupServerRoots;
    delete raw.expiredSeconds;
    delete raw.httpClient;
    const client = WopClient.fromConfig(buildConfig(raw));
    const text = client.toString();
    expect(text).not.toContain(raw.merchantPrivateKey.slice(0, 16));
    expect(text).toContain('connectTimeout');
  });
});

describe('WopError cause 分支', () => {
  it('携带 cause 与默认 category', () => {
    const cause = new Error('root');
    const err = new WopError('m', 'configuration', cause);
    expect(err.name).toBe('WopError');
    expect(err.category).toBe('configuration');
    expect((err as WopError & { cause?: unknown }).cause).toBe(cause);
    expect(new WopError('m').category).toBe('parse');
  });
});

describe('残余分支闭合', () => {
  it('顶层未知键经 skipValue 跳过', () => {
    const cfg = parseConfigJson(validConfigJson({ extraTop: { a: [1, 2], b: true } }));
    expect(cfg.appKey).toBe('app_001');
  });

  it('字符串中途截断/转义截断', () => {
    const raw = validConfigJson();
    const cut = raw.indexOf('app_001') + 3;
    expect(() => parseConfigJson(raw.slice(0, cut))).toThrowError();
    const escCut = raw.replace('app_001', 'a\\').indexOf('\\') ;
    expect(() => parseConfigJson(raw.replace('app_001', 'a\\').slice(0, escCut + 1))).toThrowError(/转义不完整|未闭合|解析失败/);
  });

  it('readUnicode 大小写十六进制全分支', () => {
    const base = JSON.parse(validConfigJson());
    const raw = JSON.stringify({ ...base, appKey: 'x' }).replace('"x"', '"\\u00AB\\u00cd\\u0090"');
    expect(parseConfigJson(raw).appKey).toBe('\u00AB\u00cd\u0090');
  });

  it('skipValue 意外结束', () => {
    expect(() => parseConfigJson('{"extraTop": ')).toThrowError();
  });

  it('NaN/Infinity 字面量拒', () => {
    const raw = validConfigJson().replace('"expiredSeconds":1800', '"expiredSeconds":NaN');
    expect(() => parseConfigJson(raw)).toThrowError(/NaN|解析失败/);
  });

  it('期望字符语法错', () => {
    expect(() => parseConfigJson('{"appKey" "x"}')).toThrowError();
  });

  it('默认 requestId 在无 randomUUID 环境走 getRandomValues 回退', async () => {
    const client = WopClient.fromConfig(buildConfig(JSON.parse(validConfigJson())));
    const orig = globalThis.crypto;
    const shim = {
      subtle: orig.subtle,
      getRandomValues: orig.getRandomValues.bind(orig),
    } as Crypto;
    vi.stubGlobal('crypto', shim);
    const draft = await client.buildRequest('GET', '/v1/x');
    expect(draft.headers['x-wop-request-id']).toMatch(/^[0-9a-f]{32}$/);
  });

  it('旧式 WopConfig 构造 toString 兜底默认字段', () => {
    const raw = JSON.parse(validConfigJson());
    const client = new WopClient({
      appKey: raw.appKey,
      suite: raw.suite,
      merchantPrivateKey: raw.merchantPrivateKey,
      platformPublicKey: raw.platformPublicKey,
      gatewayBaseUrl: 'https://gw.example.com',
    } as never);
    const text = client.toString();
    expect(text).toContain('connectTimeout');
    expect(text).not.toContain(raw.merchantPrivateKey.slice(0, 16));
  });

  it('loader：readUtf8 阶段文件消失/无读权归一', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wop-race-'));
    const file = writeConfig(dir, 'cfg.json', validConfigJson());
    // existsSync 首查(discover/exists)真,再查(readUtf8)假:模拟竞态删除
    // env 显式路径在 discover 阶段不查存在性,readUtf8 首查即 false:模拟文件消失
    const spy = vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    clearCache();
    process.env[CONFIG_FILE_ENV] = file;
    try {
      expect(() => loadDefault()).toThrowError('显式配置文件不可读');
    } finally {
      delete process.env[CONFIG_FILE_ENV];
      spy.mockRestore();
    }
    const spy2 = vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    const spy3 = vi.spyOn(fs, 'accessSync').mockImplementation(() => {
      throw new Error('eperm');
    });
    clearCache();
    try {
      expect(() => load(file)).toThrowError('显式配置文件不可读');
    } finally {
      spy2.mockRestore();
      spy3.mockRestore();
    }
  });

  it('bundled 兜底候选命中(moduleDir 相对仓库)', () => {
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'wop-bundled2-'));
    const cwd = process.cwd();
    process.chdir(empty);
    try {
      clearCache();
      // 仓库自带占位模板 → 必填非空但密钥是占位,应抛密钥错误而非"未找到"
      expect(() => loadDefault()).toThrowError(/密钥解析失败|必填项/);
    } finally {
      process.chdir(cwd);
    }
  });

  it('validateGatewayUrl 空 hostname', () => {
    expect(() => validateGatewayUrl('https:', 'serverRoot')).toThrowError('不是合法 URL');
  });
});

describe('分支残余第二轮', () => {
  it('httpClient 部分字段走默认', () => {
    const cfg = parseConfigJson(validConfigJson({ httpClient: { connectTimeout: 1 } }));
    expect(cfg.httpClient).toEqual({ connectTimeout: 1, readTimeout: 30000, maxRetryCount: 3 });
  });

  it('Infinity 字面量拒', () => {
    const raw = validConfigJson().replace('"expiredSeconds":1800', '"expiredSeconds":Infinity');
    expect(() => parseConfigJson(raw)).toThrowError();
  });

  it('旧式构造无 gatewayBaseUrl 时 toString root 兜底', () => {
    const raw = JSON.parse(validConfigJson());
    const client = new WopClient({
      appKey: raw.appKey, suite: raw.suite,
      merchantPrivateKey: raw.merchantPrivateKey, platformPublicKey: raw.platformPublicKey,
    } as never);
    expect(client.toString()).toContain('serverRoot');
  });

  it('buildRequest 显式 options 分支', async () => {
    const client = WopClient.fromConfig(buildConfig(JSON.parse(validConfigJson())));
    const t0 = 1234567890;
    const draft = await client.buildRequest('GET', '/v1/x', undefined, {
      level: 'L0', expiredSeconds: 60, timestamp: t0, nonce: 'n1', requestId: 'rid-branch',
    });
    expect(draft.headers['x-wop-timestamp']).toBe(String(t0));
    expect(draft.headers['x-wop-request-id']).toBe('rid-branch');
  });

  it('cwd 候选读取竞态：readUtf8 阶段消失/无权(非显式分支)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wop-race2-'));
    writeConfig(dir, 'config/wopSdkConfig.json', validConfigJson());
    const cwd = process.cwd();
    process.chdir(dir);
    try {
      // discover 首查真、readUtf8 复查假：模拟候选被并发删除
      let calls = 0;
      const spy = vi.spyOn(fs, 'existsSync').mockImplementation(() => (calls += 1) === 1);
      clearCache();
      // 消息全等而非正则前缀：击杀 loader 非显式「配置文件不可读」字符串追加变异（#47）
      let raceErr: unknown;
      try {
        loadDefault();
      } catch (e) {
        raceErr = e;
      }
      // process.cwd()：chdir 后 macOS 解析 /private 前缀，与 discover 的 path.resolve 同构
      expect((raceErr as WopError).message).toBe(`配置文件不可读: ${path.join(process.cwd(), 'config', 'wopSdkConfig.json')}`);
      // category 全等：loader.ts:102 的 string 变异点是 'configuration'（模板串不被 string 算子捕获），杀 #47
      expect((raceErr as WopError).category).toBe('configuration');
      spy.mockRestore();
      // discover 可读、readUtf8 阶段失权：模拟并发 chmod
      let acc = 0;
      const spy2 = vi.spyOn(fs, 'existsSync').mockReturnValue(true);
      const spy3 = vi.spyOn(fs, 'accessSync').mockImplementation(() => {
        acc += 1;
        if (acc > 1) {
          throw new Error('eperm');
        }
      });
      clearCache();
      // category 全等：同上，杀 loader.ts:102 string 变异（#47）
      let raceErr2: unknown;
      try {
        loadDefault();
      } catch (e) {
        raceErr2 = e;
      }
      expect((raceErr2 as WopError).message).toBe(`配置文件不可读: ${path.join(process.cwd(), 'config', 'wopSdkConfig.json')}`);
      expect((raceErr2 as WopError).category).toBe('configuration');
      spy2.mockRestore();
      spy3.mockRestore();
    } finally {
      process.chdir(cwd);
    }
  });

  it('未找到消息全等（空白 env 仍列出该来源；杀 loader.ts:140/144 string 变异 #41/#42）', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    vi.stubEnv(CONFIG_FILE_ENV_OVERRIDE, '   ');
    vi.stubEnv(CONFIG_FILE_ENV, ' ');
    clearCache();
    let nfErr: unknown;
    try {
      loadDefault();
    } catch (e) {
      nfErr = e;
    }
    // bundledDiscovery 三元读原始（未 trim）env 值，空白串仍列出变量名
    expect((nfErr as WopError).message).toBe(
      [
        '未找到可读的配置文件，已尝试：',
        `${CONFIG_FILE_ENV_OVERRIDE}=${process.env[CONFIG_FILE_ENV_OVERRIDE]}`,
        `${CONFIG_FILE_ENV}=${process.env[CONFIG_FILE_ENV]}`,
        path.join(process.cwd(), 'config', 'wopSdkConfig.json'),
        path.join(process.cwd(), 'wopSdkConfig.json'),
        path.join(os.homedir(), '.wop', 'wopSdkConfig.json'),
        'config/wopSdkConfig.json',
      ].join('\n'),
    );
  });

  it('joinUrl 尾斜杠归一', () => {
    expect(joinUrl('https://gw.example.com/gateway/', '/v1/order')).toBe(
      'https://gw.example.com/gateway/v1/order',
    );
  });

  it('readUnicode 边界：串尾 \\u 截断', () => {
    const raw = validConfigJson().replace('app_001', 'a\\u12').slice(0, -1);
    expect(() => parseConfigJson(raw)).toThrowError();
  });
});

describe('分支残余第三轮', () => {
  it('BOM 前缀被剥离', () => {
    expect(parseConfigJson('\uFEFF' + validConfigJson()).appKey).toBe('app_001');
  });

  it('httpClient 只给 readTimeout：connect/maxRetry 走默认', () => {
    const cfg = parseConfigJson(validConfigJson({ httpClient: { readTimeout: 5000 } }));
    expect(cfg.httpClient).toEqual({ connectTimeout: 10000, readTimeout: 5000, maxRetryCount: 3 });
  });

  it('串尾 \\u 位数不足', () => {
    expect(() => parseConfigJson('{"appKey":"a\\u12')).toThrowError('\\u 转义不完整');
  });

  it('未知字段值 NaN 走宽松扫描不阻断解析', () => {
    const raw = validConfigJson().replace(/\}$/, ',"x":NaN}');
    expect(parseConfigJson(raw).appKey).toBe('app_001');
  });

  it('密钥解析抛非 Error 时归一为字符串', () => {
    const raw = { ...JSON.parse(validConfigJson()), merchantPrivateKey: 'not-an-error' };
    expect(() => validateAndNormalize(raw as never)).toThrowError(
      '密钥解析失败: plain-string',
    );
  });
});
