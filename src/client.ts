import { loadDefault } from './config/loader';
import type { HttpClientSettings, WopSdkConfig } from './config/types';
import { maskConfigForLog, DEFAULT_READ_TIMEOUT } from './config/types';
import { joinUrl, validateApiPath } from './config/url';
import { WopError, SIGNATURE_FAILED, DECRYPT_FAILED } from './error';
import { WopGatewayResponseError } from './gatewayResponseError';
import { parseSecurityReq } from './suite';
import type { AlgorithmSuite } from './suite';
import { canonicalRequest } from './canonical';
import { computeDigestHeader, verifyDigestHeader } from './digest';
import { keyMaterialToDer } from './keys';
import {
  rsaSign,
  rsaVerify,
  oaepWrap,
  oaepUnwrap,
  aesGcmEncrypt,
  aesGcmDecrypt,
  randomBytes,
  webcrypto,
} from './crypto';
import { buildDekPayload, parseDekPayload } from './envelope';
import { toHex, toBase64Url, fromBase64Url, utf8Encode, utf8Decode } from './encode';
import type { Bytes } from './encode';
import type { Transport } from './transport/types';
import { FetchTransport } from './transport/fetch';

/** 客户端配置：商户身份、算法套件、密钥材料与网关地址 */
export interface WopConfig {
  appKey: string;
  /** securityReq，如 WOP-RSA3072-SHA256 */
  suite: string;
  /** 商户私钥（PKCS#8，PEM 或 Base64 单行）——请求加签 / 响应 DEK 解包 */
  merchantPrivateKey: string;
  /** 平台公钥（X.509 SPKI，PEM 或 Base64 单行）——响应/回调验签 / 请求 DEK 包装 */
  platformPublicKey: string;
  /** 主网关根地址（HTTPS 绝对 URL） */
  serverRoot?: string;
  /** 备用网关根地址（有序，仅全局） */
  backupServerRoots?: readonly string[];
  /** 出向签名有效窗口（秒） */
  expiredSeconds?: number;
  /** HTTP 客户端全局设置 */
  httpClient?: HttpClientSettings;
  /** @deprecated 使用 serverRoot */
  gatewayBaseUrl?: string;
  /** 可选注入传输；缺省时走默认 fetch 适配器 */
  transport?: Transport;
}

/** 请求级可选项:加密等级、签名窗口与测试注入点(生产留空走默认/CSPRNG) */
export interface RequestOptions {
  /** L0 明文（默认）/ L2 数字信封 */
  level?: 'L0' | 'L2';
  /** 签名有效窗口（秒），默认 1800 */
  expiredSeconds?: number;
  /** 测试注入点：生产留空走系统时钟 */
  timestamp?: number;
  /** 测试注入点：生产留空走 CSPRNG（16B → 32 hex） */
  nonce?: string;
  /** 测试注入点：L2 数据密钥（32B），生产留空 CSPRNG */
  dek?: Uint8Array;
  /** 测试注入点：L2 IV（12B），生产留空 CSPRNG（I4：同 key 下永不复用） */
  iv?: Uint8Array;
  /**
   * 商户请求标识（wop-specs 附录 I：x-wop-request-id 透传头，恒不入签；须为不含个人数据的
   * 不透明关联标识）。null/undefined/空白 → 缺省生成 UUID 去连字符（头恒存在）；
   * 显式传值 → trim 后原值上行，除 trim 外禁止任何改写。构造即校验：
   * 控制字符（trim 前原值扫描，CR/LF/NUL/DEL）与超长（trim 后 UTF-8 字节 > 128）均拒。
   */
  requestId?: string;
}

/** buildRequest 产物:可直接交任意 HTTP 栈发送的(method, path, headers, wireBody) */
export interface RequestDraft {
  method: string;
  path: string;
  /** 含 x-wop-sign 在内的全部请求头 */
  headers: Record<string, string>;
  /** 线上请求体：L0 原文 / L2 密文载体（JSON 单字段 encrypted，值 base64url） */
  wireBody: string;
}

/** 响应/回调校验结果:ok + 成功时明文 / 失败时 reason(失败原因语义见成员注释) */
export interface VerifyResult {
  ok: boolean;
  /** L0 为原文 body，L2 为解密明文 */
  plaintext?: string;
  /** 失败原因：验签/解密类模糊（I7），其余明确 */
  reason?: string;
}

/** send() 返回:VerifyResult 之上附加 HTTP 原始 status/headers/body */
export interface SendResult extends VerifyResult {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** 默认签名有效窗口（秒），RequestOptions.expiredSeconds 缺省值 */
export const DEFAULT_EXPIRED_SECONDS = 1800;

/** 模块级默认客户端缓存（K15/K26） */
let defaultClientInstance: WopClient | null = null;
/** L2 数字信封 x-wop-encrypt 头前缀(小写),识别该头必入签 */
const ENCRYPT_HEADER_PREFIX = 'l2';

/** 附录 I 透传头名（恒不入签；签名计算完成后写入） */
const REQUEST_ID_HEADER = 'x-wop-request-id';

/** 附录 I/I2 trim 集 = 附录 G2 TrimAll 空白类（空格、\t、\n、\x0B、\f、\r）。
 * 逐字符扫描去两端（CodeQL：正则量词在超长重复串上有回溯放大面，线性扫描等价且无此面）；
 * 不用 String.trim（Unicode 空白超集）。
 */
function trimAll(s: string): string {
  const isWs = (cp: number) =>
    cp === 0x20 || (cp >= 0x09 && cp <= 0x0d); // \t \n \x0B \f \r
  let start = 0;
  let end = s.length;
  while (start < end && isWs(s.charCodeAt(start))) start++;
  while (end > start && isWs(s.charCodeAt(end - 1))) end--;
  return s.slice(start, end);
}

/**
 * 缺省 requestId 生成（附录 I/I3）：UUID 去连字符（小写 32 hex，v4 语义）。
 * 走 webcrypto（不消费 src/crypto 的 randomBytes——interop 确定性随机流不得被透传头污染）。
 */
async function generateDefaultRequestId(): Promise<string> {
  const c = await webcrypto();
  if (typeof c.randomUUID === 'function') {
    return c.randomUUID().replace(/-/g, '');
  }
  const b = new Uint8Array(16);
  c.getRandomValues(b);
  b[6] = (b[6]! & 0x0f) | 0x40; // v4
  b[8] = (b[8]! & 0x3f) | 0x80; // RFC 4122 variant
  return toHex(b);
}

/**
 * 附录 I/I2 requestId 校验（构造即拒，configuration 类）：
 * 1. trim 前按**原值**逐码点扫描控制字符（< 0x20 或 == 0x7F，含 CR/LF/NUL/DEL）——防头注入；
 * 2. trim（G2 TrimAll 同集）后为空 → 视为未设置（走缺省生成）；
 * 3. trim 后 UTF-8 编码字节 > 128 → 拒（网关 header 缓冲按字节计）。
 * 返回 trim 后上行值；null = 未设置（缺省生成）。
 */
function resolveRequestId(raw: string | undefined): string | null {  if (raw === undefined || raw === null) return null;
  for (const ch of raw) {
    const cp = ch.codePointAt(0)!;
    if (cp < 0x20 || cp === 0x7f) {
      throw new WopError(`requestId 含控制字符（防头注入）: ${cp}`, 'configuration');
    }
  }
  const trimmed = trimAll(raw);
  if (trimmed === '') return null;
  const utf8Len = utf8Encode(trimmed).length;
  if (utf8Len > 128) {
    throw new WopError(`requestId UTF-8 字节长度不能超过 128（实际 ${utf8Len}）`, 'configuration');
  }
  return trimmed;
}

/** 签名 base64url 定长（字符）→ 解码字节定长（§3.3①：2048→256B，3072→384B，4096→512B） */
const SIGNATURE_RAW_LENGTH: Record<AlgorithmSuite['signatureB64uLength'], number> = {
  342: 256,
  512: 384,
  683: 512,
};

/**
 * WopClient:商户侧协议编排(spec §2 概念 API 的 TS 映射)。
 *
 * - buildRequest:canonicalRequest → 商户私钥加签 → RequestDraft(L0/L2)
 * - verifyResponse / verifyCallback:F6 固定顺序
 *   结构前置校验(套件一致、D2/I1 digest 规则)→ 验签 → digest 复核
 *   → DEK 解包 → alg 族比对(bulk 前)→ bulk 解密
 * - 确定性:同输入同输出,CSPRNG 项(nonce/IV/DEK)与时间戳可注入(测试/重放)
 */
export class WopClient {
  readonly config: WopConfig;
  readonly suite: AlgorithmSuite;
  private readonly merchantPriv: Bytes;
  private readonly platformPub: Bytes;
  private transport: Transport | null = null;

  /**
   * 附录 I/I3：缺省 requestId 生成器（商户未传 requestId 时每次 buildRequest 调用）。
   * 可整体替换（测试确定性锚，与 timestamp/nonce 注入同级）；生产保持缺省实现。
   */
  static requestIdGenerator: () => Promise<string> = generateDefaultRequestId;

  /** 惰性：loadDefault → 传输发现 → 构造；缓存复用 */
  static defaultClient(): WopClient {
    if (!defaultClientInstance) {
      defaultClientInstance = WopClient.fromConfig(loadDefault());
    }
    return defaultClientInstance;
  }

  /** 显式配置构造（不进默认实例缓存） */
  static fromConfig(config: WopSdkConfig | WopConfig): WopClient {
    const client = new WopClient(config);
    if (config.transport) {
      client.setTransport(config.transport);
    }
    return client;
  }

  /** 丢弃默认实例与初始化状态（轮换须先 clearCache） */
  static resetDefault(): void {
    defaultClientInstance = null;
  }

  constructor(config: WopConfig) {
    if (!config || typeof config !== 'object') {
      throw new WopError('WopConfig 不能为空', 'parse');
    }
    if (!config.appKey || !config.appKey.trim()) {
      throw new WopError('appKey 不能为空', 'parse');
    }
    this.suite = parseSecurityReq(config.suite); // 空值/非法/SM2-SM3 在此明确抛错
    if (!config.merchantPrivateKey || !config.merchantPrivateKey.trim()) {
      throw new WopError('merchantPrivateKey 不能为空（PKCS#8，PEM 或 Base64 单行）', 'parse');
    }
    if (!config.platformPublicKey || !config.platformPublicKey.trim()) {
      throw new WopError('platformPublicKey 不能为空（X.509 SPKI，PEM 或 Base64 单行）', 'parse');
    }
    const {
      serverRoot: cfgRoot,
      gatewayBaseUrl,
      httpClient,
      transport,
      backupServerRoots,
      expiredSeconds,
      ...rest
    } = config;
    const resolvedRoot = cfgRoot ?? gatewayBaseUrl;
    this.config = {
      ...rest,
      backupServerRoots: backupServerRoots ?? [],
      expiredSeconds: expiredSeconds ?? DEFAULT_EXPIRED_SECONDS,
      ...(resolvedRoot !== undefined ? { serverRoot: resolvedRoot, gatewayBaseUrl: resolvedRoot } : {}),
      ...(httpClient !== undefined ? { httpClient } : {}),
      ...(transport !== undefined ? { transport } : {}),
    };
    this.merchantPriv = keyMaterialToDer(config.merchantPrivateKey);
    this.platformPub = keyMaterialToDer(config.platformPublicKey);
  }

  /** K16：日志/toString 私钥打码 */
  toString(): string {
    const root = this.resolvedServerRoot();
    return maskConfigForLog({
      appKey: this.config.appKey,
      suite: this.config.suite,
      serverRoot: root ?? '',
      // 构造器已归一为非空（backupServerRoots=[]/expiredSeconds=默认）
      backupServerRoots: this.config.backupServerRoots!,
      expiredSeconds: this.config.expiredSeconds!,
      httpClient: this.config.httpClient ?? {
        connectTimeout: 10_000,
        readTimeout: 30_000,
        maxRetryCount: 3,
      },
    });
  }

  /** 注入 HTTP 适配层；默认 fetch 原生适配器 */
  setTransport(transport: Transport): void {
    this.transport = transport;
  }

  /**
   * 构造请求（F2–F5/F9）：产出 (headers, wireBody)，零网络 IO。
   * 有 body 必产 digest 且必入 signedHeaders（I1）；L2 时 encrypt 头同样入签。
   */
  async buildRequest(
    method: string,
    path: string,
    body?: string,
    options: RequestOptions = {},
  ): Promise<RequestDraft> {
    const level = options.level ?? 'L0';
    const expired = options.expiredSeconds ?? this.config.expiredSeconds!;
    const hasBody = body !== undefined && body !== '';

    validateApiPath(path);
    // 附录 I/I2：requestId 构造即校验（fail-fast，不延迟到发送前）
    const resolvedRequestId = resolveRequestId(options.requestId);
    if (level === 'L2' && !hasBody) {
      throw new WopError('L2 加密需要非空 body', 'parse');
    }

    // 1. 线上请求体与 L2 信封（§3.3②③/§6）：摘要对象 = wire 原始字节
    let wireBody = '';
    const nonce = options.nonce ?? toHex(await randomBytes(16));
    const headers: Record<string, string> = {
      'x-wop-appkey': this.config.appKey,
      'x-wop-nonce': nonce,
      'x-wop-timestamp': String(options.timestamp ?? Date.now()),
    };
    if (level === 'L2') {
      const dek = options.dek ?? (await randomBytes(32));
      const iv = options.iv ?? (await randomBytes(12));
      const cipherTag = await aesGcmEncrypt(dek, iv, utf8Encode(body!));
      wireBody = JSON.stringify({ encrypted: toBase64Url(cipherTag) });
      const wrapped = await oaepWrap(
        this.platformPub,
        utf8Encode(buildDekPayload('AES-256-GCM', dek, iv)),
      );
      headers['x-wop-encrypt'] = `L2;dek=${toBase64Url(wrapped)}`;
    } else {
      wireBody = body ?? '';
    }
    if (hasBody || level === 'L2') {
      headers['x-wop-content-digest'] = await computeDigestHeader(utf8Encode(wireBody));
    }

    // 2. canonicalRequest → 商户私钥加签（F3）
    const authString = `v1/${expired}`;
    const canonical = canonicalRequest({
      authString,
      method,
      path,
      queryString: '',
      headers,
    });
    const signature = toBase64Url(await rsaSign(this.merchantPriv, utf8Encode(canonical)));
    const signedNames = Object.keys(headers).sort().join(';');
    headers['x-wop-sign'] = `${this.suite.securityReq} ${authString}/${signedNames}/${signature}`;

    // 3. requestId 透传头（附录 I）：在签名落盘**之后**写入，保证不在 signedHeaders 冻结清单中；
    //    商户未传（含 trim 后为空）→ 缺省生成，最终头恒存在
    headers[REQUEST_ID_HEADER] = resolvedRequestId ?? (await WopClient.requestIdGenerator());
    // 附录 I/I3 日志义务：INFO 级打印最终透传头值（非敏感，豁免脱敏），供网关 AccessLog 关联排查
    console.info(`x-wop-request-id=${headers[REQUEST_ID_HEADER]} ${method.toUpperCase()} ${path}`);

    return { method: method.toUpperCase(), path, headers, wireBody };
  }

  /**
   * 校验网关同步响应（F6）。requestPath = 发起请求的 API path（canonical 的 URI 段）。
   */
  async verifyResponse(
    headers: Record<string, string>,
    body: string,
    requestPath: string,
  ): Promise<VerifyResult> {
    return this.verifyIncoming(headers, body, requestPath);
  }

  /**
   * 校验平台异步回调（F6）。callbackPath 接受完整回调 URL（取 pathname）或纯 path。
   */
  async verifyCallback(
    headers: Record<string, string>,
    body: string,
    callbackPath: string,
  ): Promise<VerifyResult> {
    const path = /^https?:\/\//i.test(callbackPath) ? new URL(callbackPath).pathname : callbackPath;
    return this.verifyIncoming(headers, body, path);
  }

  /**
   * 一站式 execute：签名 → 发送 → 非 2xx 拦截 → 验签解密（§2）。
   */
  async execute(
    method: string,
    path: string,
    body?: string,
    options: RequestOptions = {},
  ): Promise<VerifyResult> {
    const serverRoot = this.resolvedServerRoot();
    if (!serverRoot) {
      throw new WopError('serverRoot 未配置，无法 execute', 'configuration');
    }
    const transport = this.ensureTransport();
    const draft = await this.buildRequest(method, path, body, options);
    const resp = await transport.send({
      method: draft.method,
      url: joinUrl(serverRoot, path),
      headers: draft.headers,
      body: draft.wireBody,
    });
    if (resp.status < 200 || resp.status >= 300) {
      throw new WopGatewayResponseError(resp.status, resp.body);
    }
    return this.verifyResponse(resp.headers, resp.body, draft.path);
  }

  /**
   * 发送请求并校验响应（Transport 编排便利入口）。
   * 响应含 x-wop-sign 头时自动执行 F6 校验。
   */
  async send(
    method: string,
    path: string,
    body?: string,
    options: RequestOptions = {},
  ): Promise<SendResult> {
    const serverRoot = this.resolvedServerRoot();
    if (!serverRoot) {
      throw new WopError('serverRoot 未配置，无法发送（或直接消费 buildRequest 的 RequestDraft）', 'configuration');
    }
    const transport = this.ensureTransport();
    const draft = await this.buildRequest(method, path, body, options);
    const resp = await transport.send({
      method: draft.method,
      url: joinUrl(serverRoot, path),
      headers: draft.headers,
      body: draft.wireBody,
    });
    if (resp.headers['x-wop-sign'] !== undefined) {
      const verified = await this.verifyResponse(resp.headers, resp.body, draft.path);
      return { ...verified, status: resp.status, headers: resp.headers, body: resp.body };
    }
    return { ok: resp.status >= 200 && resp.status < 300, status: resp.status, headers: resp.headers, body: resp.body };
  }

  private resolvedServerRoot(): string | undefined {
    return this.config.serverRoot ?? this.config.gatewayBaseUrl;
  }

  /** F6 固定顺序：验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密 */
  private async verifyIncoming(
    rawHeaders: Record<string, string>,
    body: string,
    path: string,
  ): Promise<VerifyResult> {
    try {
      const headers = lowercaseHeaders(rawHeaders);
      const signHeader = headers['x-wop-sign'];
      if (signHeader === undefined) {
        throw new WopError('响应缺少 x-wop-sign 头', 'parse');
      }

      // —— 解析结构化签名头（§7.3）——
      const spaceIdx = signHeader.indexOf(' ');
      if (spaceIdx <= 0) {
        throw new WopError('x-wop-sign 格式错误：缺少 securityReq 与后续段的空格分隔', 'parse');
      }
      const securityReq = signHeader.slice(0, spaceIdx);
      const suite = parseSecurityReq(securityReq);
      if (securityReq !== this.suite.securityReq) {
        throw new WopError(
          `响应套件 "${securityReq}" 与客户端配置 "${this.suite.securityReq}" 不符`,
          'parse',
        );
      }
      const seg = signHeader.slice(spaceIdx + 1).split('/');
      if (seg.length !== 4) {
        throw new WopError(
          `x-wop-sign 格式错误：应为 <protocolVersion>/<expiredSeconds>/<signedHeaders>/<signature> 四段，实际 ${seg.length} 段`,
          'parse',
        );
      }
      const [protocolVersion, expiredSeconds, signedNamesRaw, sigB64u] = seg as [string, string, string, string];
      if (protocolVersion !== 'v1' || !/^\d+$/.test(expiredSeconds)) {
        throw new WopError('x-wop-sign 格式错误：authString 应为 v1/<expiredSeconds>', 'parse');
      }

      const signedNames = signedNamesRaw.split(';').map((s) => s.trim()).filter(Boolean);

      // —— 结构前置校验（公开协议知识，明确拒绝，先于验签）——
      // D2 有 body 必传 digest；I1 digest 必入 signedHeaders；无 body 不得携带 digest
      const hasBody = body.length > 0;
      const digestHeader = headers['x-wop-content-digest'];
      if (hasBody) {
        if (digestHeader === undefined) {
          throw new WopError('有 body 但缺少 x-wop-content-digest 头（D2/I1）', 'integrity');
        }
        if (!signedNames.includes('x-wop-content-digest')) {
          throw new WopError('x-wop-content-digest 未列入 signedHeaders（I1）', 'parse');
        }
      } else if (digestHeader !== undefined) {
        throw new WopError('无响应体不应携带 x-wop-content-digest 头', 'parse');
      }

      // signedHeaders 声明的头必须齐备（canonical 重建材料）
      const signedValues: Record<string, string> = {};
      for (const name of signedNames) {
        const value = headers[name];
        if (value === undefined) {
          throw new WopError(`signedHeaders 声明了未提供的头：${name}`, 'parse');
        }
        signedValues[name] = value;
      }

      // —— F6① 验签（平台公钥）——
      // 签名段结构前置校验（公开知识，明确拒绝）：b64url 严格解码（'=' 等
      // 非法结构 → 协议类，interop 合同 n06 裁决）+ 解码后定长（§3.3①）
      const sigBytes = fromBase64Url(sigB64u);
      const sigRawLen = SIGNATURE_RAW_LENGTH[suite.signatureB64uLength]!;
      if (sigBytes.length !== sigRawLen) {
        throw new WopError(
          `签名长度 ${sigBytes.length} 字节与套件 ${suite.securityReq} 定长 ${sigRawLen} 字节不符`,
          'parse',
        );
      }
      const canonical = canonicalRequest({
        authString: `${protocolVersion}/${expiredSeconds}`,
        method: 'POST', // 响应/回调出站语义固定 POST（与网关 SignFilter 对齐）
        path,
        queryString: '',
        headers: signedValues,
      });
      let sigOk = true;
      try {
        sigOk = await rsaVerify(this.platformPub, sigBytes, utf8Encode(canonical));
      } catch {
        sigOk = false;
      }
      if (!sigOk) {
        // I7：对外模糊，不区分密钥不符/值错
        return { ok: false, reason: SIGNATURE_FAILED };
      }

      // —— F6② digest 复核（摘要对象 = wire 原始字节；L2 即密文载体）——
      if (hasBody) {
        const dh = digestHeader as string;
        verifyDigestHeader(dh, suite); // 格式/跨族 → 明确抛错
        const computed = await computeDigestHeader(body);
        if (computed !== dh) {
          throw new WopError('摘要不匹配：body 可能被篡改或传输不完整', 'integrity');
        }
      }

      // —— L2：F6③ DEK 解包 → F6④ alg 族比对（bulk 前，D8）→ F6⑤ bulk 解密 ——
      const encryptHeader = headers['x-wop-encrypt'];
      if (encryptHeader !== undefined && encryptHeader.toLowerCase().startsWith(ENCRYPT_HEADER_PREFIX)) {
        const dekIdx = encryptHeader.indexOf('dek=');
        if (dekIdx < 0) {
          throw new WopError('x-wop-encrypt 格式错误：L2 须携带 dek=', 'parse');
        }
        const wrapped = fromBase64Url(encryptHeader.slice(dekIdx + 4).trim()); // 失败 → parse 明确
        let payload: string;
        try {
          payload = utf8Decode(await oaepUnwrap(this.merchantPriv, wrapped)); // 失败 → 模糊
        } catch (e) {
          return { ok: false, reason: (e as WopError).message };
        }
        let dek;
        try {
          dek = parseDekPayload(payload);
        } catch {
          // 载荷结构在解包后才可见，属密钥参与层；除 alg 族不符（D8 明确）外
          // 一律归入解密类模糊（I7 保守默认，interop 合同 n13 裁决）
          return { ok: false, reason: DECRYPT_FAILED };
        }
        if (dek.alg !== suite.expectedDekAlg) {
          throw new WopError(
            `DEK alg 与套件族不符：载荷 ${dek.alg}，${suite.securityReq} 期望 ${suite.expectedDekAlg}（I5/I3）`,
            'consistency',
          );
        }
        let wire: { encrypted?: unknown };
        try {
          wire = JSON.parse(body) as { encrypted?: unknown };
        } catch {
          throw new WopError('L2 响应 body 不是合法 JSON（期望 {"encrypted":…}）', 'parse');
        }
        if (typeof wire.encrypted !== 'string' || wire.encrypted === '') {
          throw new WopError('L2 响应 body 缺少 encrypted 字段', 'parse');
        }
        let cipherTag;
        try {
          cipherTag = fromBase64Url(wire.encrypted);
        } catch (e) {
          return { ok: false, reason: (e as WopError).message };
        }
        let plain: Bytes;
        try {
          plain = await aesGcmDecrypt(dek.key, dek.iv, cipherTag); // tag 失败 → 模糊
        } catch (e) {
          return { ok: false, reason: (e as WopError).message };
        }
        return { ok: true, plaintext: utf8Decode(plain) };
      }

      return { ok: true, plaintext: body };
    } catch (e) {
      if (e instanceof WopError) {
        return { ok: false, reason: e.message };
      }
      return { ok: false, reason: '系统繁忙，请稍后重试' }; // SYS 模糊 + 可重试
    }
  }

  private ensureTransport(): Transport {
    if (!this.transport) {
      // readTimeout 从配置传入；未配置时由 FetchTransport 落到配置模型默认值
      this.transport = new FetchTransport(this.config.httpClient?.readTimeout ?? DEFAULT_READ_TIMEOUT);
    }
    return this.transport;
  }
}

/** header 名统一 trim + 小写化、值 trim(响应/回调头规范化,canonical 重建前置) */
function lowercaseHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k.trim().toLowerCase()] = String(v).trim();
  }
  return out;
}
