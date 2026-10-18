import { describe, it, expect, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { WopClient } from '../src/client';
import { WopError, SIGNATURE_FAILED, DECRYPT_FAILED } from '../src/error';
import { fromBase64Url, fromHex, utf8Decode, utf8Encode } from '../src/encode';
import fixture from './fixtures/interop-cases.json';
import vectors from './fixtures/crypto-vectors.json';
import type * as WopCrypto from '../src/crypto';
import { oaepUnwrap, oaepWrap } from '../src/crypto';

/**
 * interop conformance（协议编排跨仓一致性合同消费端，wop-specs/interop/v1）。
 *
 * - fixture 为真源字节副本（禁手改）：tests/fixtures/interop-cases.json，
 *   测试内 sha256 与真源指纹对账 + 条数/已知 id 哨兵防漂移静默通过
 * - build 方向：同 input（timestamp/nonce/randomHex）必须复现同 draft；
 *   byte-exact 全量比对，deterministic-fields 按 opaque 剥离密钥参与段
 * - verify 方向：positive 断言明文一致；negative 断言错误分类
 *   （本仓对外错误语义 → canonical class 显式映射表见 REASON_TO_CLASS）
 * - 随机流消费顺序合同：[16B nonce 池（nonce 已注入，跳过）][CEK][12B IV]
 *   [k…各仓自定义]——OAEP seed 取 IV 后 32B（SHA-256 hLen）
 *
 * SM2 边界（Q7 路线图）：WOP-SM2-SM3 套件本仓暂未支持，相关 8 条样本
 * （build 2 / positive 2 / negative 4）以"构造即明确拒绝（unsupported）"
 * 消费——这是本仓当前的真实合同行为；SM2 落地后须改为按样本语义全量消费。
 */

// —— WithRandom 等价物：注入随机流（vi.mock 覆盖 src/crypto 的 CSPRNG 出口）——
// hoisted 状态供 mock 工厂与用例两侧共享游标
const interopRandom = vi.hoisted(() => {
  const state: { stream: Uint8Array; pos: number } = { stream: new Uint8Array(0), pos: 0 };
  return {
    reset(stream: Uint8Array): void {
      state.stream = stream;
      state.pos = 0;
    },
    read(n: number): Uint8Array {
      const end = Math.min(state.pos + n, state.stream.length);
      const out = state.stream.slice(state.pos, end);
      state.pos = end;
      return out;
    },
  };
});

vi.mock('../src/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof WopCrypto>();
  const { subtle } = await actual.webcrypto();

  const toBig = (b: Uint8Array): bigint => {
    let hex = '0x';
    for (const x of b) hex += x.toString(16).padStart(2, '0');
    return BigInt(hex);
  };
  const fromBig = (v: bigint, len: number): Uint8Array => {
    const hex = v.toString(16).padStart(len * 2, '0');
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
  };
  const b64uToBytes = (s: string): Uint8Array => {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  };

  const mgf1Sha256 = async (seed: Uint8Array, len: number): Promise<Uint8Array> => {
    const out = new Uint8Array(len);
    let pos = 0;
    for (let counter = 0; pos < len; counter++) {
      const input = new Uint8Array(seed.length + 4);
      input.set(seed);
      new DataView(input.buffer).setUint32(seed.length, counter);
      const h = new Uint8Array(await subtle.digest('SHA-256', input as unknown as BufferSource));
      out.set(h.subarray(0, Math.min(32, len - pos)), pos);
      pos += 32;
    }
    return out;
  }

  const powMod = (x: bigint, e: bigint, n: bigint): bigint => {
    let result = 1n;
    let base = x % n;
    let exp = e;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % n;
      base = (base * base) % n;
      exp >>= 1n;
    }
    return result;
  }

  /** RSA-OAEP（双 SHA-256 + 空 label）确定性包装：seed 取自注入流。
   *  WebCrypto 无法注入 OAEP seed；此标准等价实现（EME-OAEP + BigInt RSAEP）
   *  由两条路径交叉验证：roundtrip 通过真实 WebCrypto oaepUnwrap，且字节级
   *  对拍 Go rsa.EncryptOAEP 生成的真源 fixture（build:L2 全头比对）。 */
  const oaepWrapFromStream = async (pubSpki: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> => {
    const key = await subtle.importKey(
      'spki',
      pubSpki as unknown as BufferSource,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['encrypt'],
    );
    const jwk = (await subtle.exportKey('jwk', key)) as JsonWebKey;
    const n = toBig(b64uToBytes(jwk.n!));
    const e = toBig(b64uToBytes(jwk.e!));
    const k = b64uToBytes(jwk.n!).length;
    const hLen = 32;
    const seed = interopRandom.read(hLen); // 随机流合同：IV 后 hLen 字节
    const lHash = new Uint8Array(await subtle.digest('SHA-256', new Uint8Array(0) as unknown as BufferSource));
    const psLen = k - plaintext.length - 2 * hLen - 2;
    if (psLen < 0) throw new WopError('OAEP 载荷过长', 'parse');
    const db = new Uint8Array(k - hLen - 1);
    db.set(lHash, 0);
    db[hLen + psLen] = 1;
    db.set(plaintext, hLen + psLen + 1);
    const dbMask = await mgf1Sha256(seed, k - hLen - 1);
    const maskedDB = db.map((b, i) => b ^ dbMask[i]!);
    const seedMask = await mgf1Sha256(maskedDB, hLen);
    const maskedSeed = seed.map((b, i) => b ^ seedMask[i]!);
    const em = new Uint8Array(1 + hLen + (k - hLen - 1));
    em.set(maskedSeed, 1);
    em.set(maskedDB, 1 + hLen);
    return fromBig(powMod(toBig(em), e, n), k);
  }

  return {
    ...actual,
    randomBytes: async (n: number) => interopRandom.read(n),
    oaepWrap: (pub: Uint8Array, plaintext: Uint8Array) => oaepWrapFromStream(pub, plaintext),
  };
});

// —— fixture 类型（JSON 推断按最宽联合收窄）——
interface InteropInput {
  method: string;
  path: string;
  appKey: string;
  plaintextB64: string;
  timestampMs: number;
  nonce: string;
  randomHex: string;
}
interface InteropExpected {
  reproduceMode: 'byte-exact' | 'deterministic-fields';
  wireBodyB64: string;
  headers: Record<string, string>;
  opaque?: string[];
}
interface InteropResponse {
  method: string;
  path: string;
  appKey: string;
  headers: Record<string, string>;
  wireBodyB64: string;
}
interface InteropExpect {
  ok: boolean;
  plaintextB64?: string;
  errorClass?: string;
}
interface InteropCase {
  id: string;
  kind: 'build' | 'verify-positive' | 'verify-negative';
  suite?: string;
  level?: 'L0' | 'L2';
  input?: InteropInput;
  expected?: InteropExpected;
  response?: InteropResponse;
  verifyPath?: string;
  expect?: InteropExpect;
}

const CASES = (fixture as { _meta: { format: string; caseCount: number }; cases: InteropCase[] }).cases;

const SM2 = 'WOP-SM2-SM3';
const FIXTURE_SHA256 = 'c920ca1a93ccb3899a659f59fed6ec4652cf9e1b3b58bbdac23c45ac3ed2353e'; // 真源 wop-specs/interop/v1/interop-cases.json（30 条含 n17，2026-09-02 冻结）

// 已知 id 哨兵：新增/漂移用例必须显式登记（防 fixture 静默变更）
const KNOWN_IDS = new Set([
  'build:WOP-RSA3072-SHA256:L0',
  'build:WOP-RSA3072-SHA256:L2',
  'build:WOP-RSA4096-SHA256:L0',
  'build:WOP-RSA4096-SHA256:L2',
  'build:WOP-SM2-SM3:L0',
  'build:WOP-SM2-SM3:L2',
  'p07',
  'p08',
  'p09',
  'p10',
  'p11',
  'p12',
  'p13',
  'n01-encrypted-char-damage',
  'n02-wire-tampered-after-signing',
  'n03-digest-tag-cross-family',
  'n04-dek-alg-cross-family',
  'n05-dek-c1c2c3-order',
  'n06-signature-b64-padding',
  'n07-signature-63b',
  'n08-signature-65b',
  'n09-digest-missing',
  'n10-digest-not-signed',
  'n11-suite-mismatch',
  'n12-envelope-missing-field',
  'n13-dek-key-length',
  'n14-missing-signed-header',
  'n15-digest-without-body',
  'n16-replay-cross-path',
  'n17-encrypt-missing-dek',
]);

// canonical class（合同错误分类表，wop-specs/interop/v1 README）
type CanonicalClass = 'verify-failed' | 'decrypt-failed' | 'digest-mismatch' | 'alg-mismatch' | 'protocol';

/**
 * 本仓对外错误语义（VerifyResult.reason）→ canonical class 显式映射表。
 * 模糊二态（I7）以常量文案精确匹配；明确类按可辨识前缀归类；
 * protocol 族同样逐条锚定文案前缀（防回归漂移：任意/错误分类文案不得静默落入
 * protocol——与 Go classOf 的 default 桶分类结果一致，但拒绝未知文案）。
 */
const REASON_TO_CLASS: ReadonlyArray<readonly [RegExp, CanonicalClass]> = [
  // spec:interop-fuzzy 验签模糊：n16 重放等签名层故障
  [new RegExp(`^${SIGNATURE_FAILED}$`), 'verify-failed'],
  // spec:interop-fuzzy 解密模糊：n01 密文损伤 / n13 DEK 载荷结构畸形（I7 保守默认）
  [new RegExp(`^${DECRYPT_FAILED}$`), 'decrypt-failed'],
  // spec:interop-digest 完整性明确：n02 篡改 / n09 缺 digest 头（D2）
  [/^摘要不匹配/, 'digest-mismatch'],
  [/^有 body 但缺少 x-wop-content-digest/, 'digest-mismatch'],
  // spec:interop-alg 一致性明确（D8）：n04 dek alg 跨族
  [/^DEK alg 与套件族不符/, 'alg-mismatch'],
  // spec:interop-protocol 结构明确拒绝：逐条锚定（n03 digest 跨族 / n06 b64 padding）
  [/^digest header ".*" 与套件 .* 跨族/, 'protocol'],
  [/^base64url 解码失败/, 'protocol'],
  // spec:interop-protocol 结构明确拒绝：n10 digest 未签名 / n11 响应套件不符
  [/^x-wop-content-digest 未列入 signedHeaders/, 'protocol'],
  [/^响应套件 ".*" 与客户端配置 ".*" 不符/, 'protocol'],
  // spec:interop-protocol 结构明确拒绝：n12 信封缺字段 / n14 声明头缺失 / n15 无 body 携 digest
  [/^L2 响应 body 缺少 encrypted 字段/, 'protocol'],
  [/^signedHeaders 声明了未提供的头/, 'protocol'],
  [/^无响应体不应携带 x-wop-content-digest/, 'protocol'],
  // spec:interop-protocol 结构明确拒绝：n17 L2 加密头缺 dek 段
  [/^x-wop-encrypt 格式错误：L2 须携带 dek=/, 'protocol'],
];

function classOf(reason: string | undefined): CanonicalClass {
  expect(reason, '负样本必须携带对外失败语义 reason').toBeTruthy();
  if (reason === '系统繁忙，请稍后重试') {
    throw new Error(`负样本触达系统类兜底文案，不属于合同分类域：${reason}`);
  }
  for (const [re, cls] of REASON_TO_CLASS) {
    if (re.test(reason!)) return cls;
  }
  // spec:interop-protocol 未知文案拒绝：protocol 不作兜底桶，回归漂移必须显式登记
  throw new Error(`未知 reason 文案，须在 REASON_TO_CLASS 显式登记后归类：${reason}`);
}

/** 套件 → 客户端（密钥与黄金向量同源：fixture 密钥体系 == crypto-vectors.json） */
function clientFor(suite: string, appKey: string): WopClient {
  const k = suite === 'WOP-RSA4096-SHA256' ? vectors.keys.rsa4096! : vectors.keys.rsa3072!;
  return new WopClient({
    appKey,
    suite,
    merchantPrivateKey: k.privatePkcs8B64,
    platformPublicKey: k.publicSpkiB64,
  });
}

/** opaque 剥离（deterministic-fields 模式）：签名末段 / dek 包装值为密钥参与段 */
function stripSignatureSegment(sign: string): string {
  const i = sign.lastIndexOf('/');
  return i >= 0 ? sign.slice(0, i + 1) : sign;
}
function stripDekValue(encrypt: string): string {
  const i = encrypt.indexOf('dek=');
  return i >= 0 ? encrypt.slice(0, i + 4) : encrypt;
}

describe('interop fixture 完整性（真源一致性哨兵）', () => {
  it('字节副本 sha256 与真源一致（禁手改）', () => {
    const raw = readFileSync(new URL('./fixtures/interop-cases.json', import.meta.url));
    expect(createHash('sha256').update(raw).digest('hex')).toBe(FIXTURE_SHA256);
  });

  it('格式/caseCount 元数据一致 + 条数哨兵 30', () => {
    const meta = (fixture as { _meta: { format: string; caseCount: number } })._meta;
    expect(meta.format).toBe('wop-interop-1');
    expect(CASES.length).toBe(30);
    expect(meta.caseCount).toBe(CASES.length);
  });

  it('已知 id 哨兵：全部命中且无未登记用例', () => {
    const seen = new Set<string>();
    for (const c of CASES) {
      expect(KNOWN_IDS.has(c.id), `未登记的用例 id：${c.id}（fixture 漂移，须显式登记后消费）`).toBe(true);
      seen.add(c.id);
    }
    expect(seen.size).toBe(KNOWN_IDS.size);
  });
});

describe('interop 消费：build 方向（同输入复现同 draft）', () => {
  it('RSA 族 byte-exact：全部头与 wire body 字节级一致', async () => {
    let rsaBuilds = 0;
    for (const c of CASES) {
      if (c.kind !== 'build') continue;
      if (c.suite === SM2) continue;
      rsaBuilds++;
      const input = c.input!;
      const expected = c.expected!;
      expect(expected.reproduceMode).toBe('byte-exact');
      interopRandom.reset(fromHex(input.randomHex));
      const client = clientFor(c.suite!, input.appKey);
      const draft = await client.buildRequest(
        input.method,
        input.path,
        utf8Decode(fromBase64Url(input.plaintextB64)),
        {
          ...(c.level ? { level: c.level } : {}),
          timestamp: input.timestampMs,
          nonce: input.nonce,
          // dek/iv 不注入：经 mock 随机流按合同顺序消费（CEK→IV→OAEP seed）
        },
      );
      expect(draft.wireBody, `${c.id}: wire body 字节不一致`).toBe(utf8Decode(fromBase64Url(expected.wireBodyB64)));
      const opaque = new Set(expected.opaque ?? []);
      for (const [name, wantRaw] of Object.entries(expected.headers)) {
        let got = draft.headers[name];
        let want = wantRaw;
        if (opaque.has('x-wop-sign.signatureSegment') && name === 'x-wop-sign') {
          if (got !== undefined) got = stripSignatureSegment(got);
          want = stripSignatureSegment(want);
        }
        if (opaque.has('x-wop-encrypt.dekValue') && name === 'x-wop-encrypt') {
          if (got !== undefined) got = stripDekValue(got);
          want = stripDekValue(want);
        }
        expect(got, `${c.id}: 头 ${name} = ${got}, want ${want}`).toBe(want);
      }
      // x-wop-request-id 是规格附录 I 的可选透传头（恒不入签、网关日志关联用），
      // 不属于 interop 冻结的协议头合同（fixture sha256 钉死不可改），比对前剥离
      const protocolHeaders = { ...draft.headers };
      delete protocolHeaders['x-wop-request-id'];
      expect(Object.keys(protocolHeaders).length, `${c.id}: 头集合不一致`).toBe(
        Object.keys(expected.headers).length,
      );
    }
    expect(rsaBuilds).toBe(4); // 条数哨兵：RSA build 4 条
  });

  it('SM2 族：明确拒绝（Q7 暂未支持，构造即 unsupported）', () => {
    const sm2 = CASES.filter((c) => c.kind === 'build' && c.suite === SM2);
    expect(sm2.length).toBe(2); // 条数哨兵：SM2 build 2 条
    for (const c of sm2) {
      expect(() => clientFor(SM2, c.input!.appKey)).toThrowError(/SM2-SM3 套件暂未支持/);
    }
  });
});

describe('interop 消费：verify 方向（冻结样本，错误分类逐条对账）', () => {
  it('positive：校验通过且明文一致（含 P7 混合大小写头）', async () => {
    let pos = 0;
    let sm2Pos = 0;
    for (const c of CASES) {
      if (c.kind !== 'verify-positive') continue;
      if (c.suite === SM2) {
        sm2Pos++;
        expect(() => clientFor(SM2, c.response!.appKey)).toThrowError(/SM2-SM3 套件暂未支持/);
        continue;
      }
      pos++;
      const res = await clientFor(c.suite!, c.response!.appKey).verifyResponse(
        c.response!.headers,
        utf8Decode(fromBase64Url(c.response!.wireBodyB64)),
        c.verifyPath ?? c.response!.path,
      );
      expect(res.ok, `${c.id}: 应通过（reason=${res.reason}）`).toBe(true);
      expect(res.plaintext, `${c.id}: 明文不一致`).toBe(utf8Decode(fromBase64Url(c.expect!.plaintextB64!)));
    }
    expect(pos).toBe(5); // 条数哨兵：RSA positive 5 条
    expect(sm2Pos).toBe(2); // 条数哨兵：SM2 positive 2 条（明确拒绝消费）
  });

  it('negative：必须拒绝且错误分类逐条对账', async () => {
    let neg = 0;
    let sm2Neg = 0;
    for (const c of CASES) {
      if (c.kind !== 'verify-negative') continue;
      if (c.suite === SM2) {
        sm2Neg++;
        expect(() => clientFor(SM2, c.response!.appKey)).toThrowError(/SM2-SM3 套件暂未支持/);
        continue;
      }
      neg++;
      const res = await clientFor(c.suite!, c.response!.appKey).verifyResponse(
        c.response!.headers,
        utf8Decode(fromBase64Url(c.response!.wireBodyB64)),
        c.verifyPath ?? c.response!.path,
      );
      expect(res.ok, `${c.id}: 应拒绝`).toBe(false);
      expect(classOf(res.reason), `${c.id}: 错误分类 = ${classOf(res.reason)}（reason=${res.reason}）`).toBe(
        c.expect!.errorClass,
      );
    }
    expect(neg).toBe(13); // 条数哨兵：RSA negative 13 条
    expect(sm2Neg).toBe(4); // 条数哨兵：SM2 negative 4 条（明确拒绝消费）
  });
});

describe('classOf 分类表自证（未知文案拒绝）', () => {
  // spec:interop-protocol 否定式条款：protocol 不作兜底桶，未登记文案必须显式失败而非静默归类
  it('未知 reason 文案：抛错拒绝（防回归漂移静默落入 protocol）', () => {
    expect(() => classOf('完全未登记的失败文案')).toThrowError(/未知 reason 文案/);
  });
});

describe('interop 消费：确定性 OAEP mock 的自证（标准等价性）', () => {
  it('流内 seed 包装 → 真实 WebCrypto oaepUnwrap 回环 == 载荷', async () => {
    // 经 vi.mock：oaepWrap 为确定性流实现、oaepUnwrap 为真实 WebCrypto
    const K = vectors.keys.rsa3072!;
    const payload = utf8Encode('AES-256-GCM$' + vectors.inputs.aesKeyB64u + '$' + vectors.inputs.aesIvB64u);
    interopRandom.reset(fromHex('11'.repeat(64)));
    // 密钥材料向量以标准 base64 存储，转 b64url 字母表后解码
    const toB64u = (s: string) => s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const wrapped = await oaepWrap(fromBase64Url(toB64u(K.publicSpkiB64)), payload);
    interopRandom.reset(new Uint8Array(0));
    const roundtrip = await oaepUnwrap(fromBase64Url(toB64u(K.privatePkcs8B64)), wrapped);
    expect(utf8Decode(roundtrip)).toBe(utf8Decode(payload));
  });
});
