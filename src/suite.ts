import { WopError } from './error';

/**
 * securityReq 解析与算法套件推导（F1，gateway spec §2/§3.2）。
 *
 * 合法取值共四种：WOP-RSA2048-SHA256 / WOP-RSA3072-SHA256 / WOP-RSA4096-SHA256 / WOP-SM2-SM3。
 * TS 首版按 Q7 裁决仅实现 RSA 套件；SM2-SM3 明确抛"暂未支持"。
 * 映射集中注册于代码，无运行时配置入口（D13）。
 */

/** 不可变算法套件：一次请求的算法上下文（§4.4） */
export interface AlgorithmSuite {
  readonly securityReq: string;
  readonly keyAlgorithm: 'RSA';
  readonly keyLength: 2048 | 3072 | 4096;
  readonly digestAlgorithm: 'SHA256';
  readonly signAlgorithm: 'SHA256withRSA';
  readonly messageAlgorithm: 'AES-256-GCM';
  readonly keyWrapAlgorithm: string;
  readonly digestLabel: 'sha-256';
  /** 签名 base64url 定长（§3.3①：2048→342 字符，3072→512 字符，4096→683 字符），格式校验可前置 */
  readonly signatureB64uLength: 342 | 512 | 683;
  /** DEK 载荷期望 alg（§6.2 一致性比对，bulk 解密前） */
  readonly expectedDekAlg: 'AES-256-GCM';
}

/** WOP-RSA2048-SHA256 套件单例(冻结,§4.4 一次请求的算法上下文) */
const RSA2048_SUITE: AlgorithmSuite = Object.freeze({
  securityReq: 'WOP-RSA2048-SHA256',
  keyAlgorithm: 'RSA',
  keyLength: 2048,
  digestAlgorithm: 'SHA256',
  signAlgorithm: 'SHA256withRSA',
  messageAlgorithm: 'AES-256-GCM',
  keyWrapAlgorithm: 'RSA-2048-OAEP(SHA-256/MGF1-SHA-256)',
  digestLabel: 'sha-256',
  signatureB64uLength: 342,
  expectedDekAlg: 'AES-256-GCM',
});

/** WOP-RSA3072-SHA256 套件单例(冻结,§4.4 一次请求的算法上下文) */
const RSA3072_SUITE: AlgorithmSuite = Object.freeze({
  securityReq: 'WOP-RSA3072-SHA256',
  keyAlgorithm: 'RSA',
  keyLength: 3072,
  digestAlgorithm: 'SHA256',
  signAlgorithm: 'SHA256withRSA',
  messageAlgorithm: 'AES-256-GCM',
  keyWrapAlgorithm: 'RSA-3072-OAEP(SHA-256/MGF1-SHA-256)',
  digestLabel: 'sha-256',
  signatureB64uLength: 512,
  expectedDekAlg: 'AES-256-GCM',
});

/** WOP-RSA4096-SHA256 套件单例(冻结) */
const RSA4096_SUITE: AlgorithmSuite = Object.freeze({
  securityReq: 'WOP-RSA4096-SHA256',
  keyAlgorithm: 'RSA',
  keyLength: 4096,
  digestAlgorithm: 'SHA256',
  signAlgorithm: 'SHA256withRSA',
  messageAlgorithm: 'AES-256-GCM',
  keyWrapAlgorithm: 'RSA-4096-OAEP(SHA-256/MGF1-SHA-256)',
  digestLabel: 'sha-256',
  signatureB64uLength: 683,
  expectedDekAlg: 'AES-256-GCM',
});

/** 密钥算法 → 密码族（I5 跨族校验与支持列表的单一事实源，与 DIGEST_ALG_FAMILY 成对维护） */
const KEY_ALG_FAMILY: Record<string, 'RSA' | 'SM2'> = { RSA2048: 'RSA', RSA3072: 'RSA', RSA4096: 'RSA', SM2: 'SM2' };
/** 摘要算法 → 密码族(与 KEY_ALG_FAMILY 同源维护,I5 跨族校验) */
const DIGEST_ALG_FAMILY: Record<string, 'RSA' | 'SM2'> = { SHA256: 'RSA', SM3: 'SM2' };

/** 已解析套件缓存:securityReq → 套件单例,免重复解析 */
const SUITE_CACHE: Record<string, AlgorithmSuite> = {
  'WOP-RSA2048-SHA256': RSA2048_SUITE,
  'WOP-RSA3072-SHA256': RSA3072_SUITE,
  'WOP-RSA4096-SHA256': RSA4096_SUITE,
};
/**
 * 解析 securityReq。失败分类：
 * - 解析类（parse）：空值、非三段式/空段、前缀非 WOP —— 对外语义明确
 * - 支持类（unsupported）：算法不在列表、跨族、SM2-SM3 暂未支持 —— 对外语义明确
 */
export function parseSecurityReq(securityReq: string): AlgorithmSuite {
  const cached = SUITE_CACHE[securityReq];
  if (cached) return cached;

  if (typeof securityReq !== 'string' || securityReq.trim() === '') {
    throw new WopError(`securityReq 为空或空白，期望格式 WOP-<密钥算法>-<摘要算法>`, 'parse');
  }
  const parts = securityReq.split('-');
  if (parts.length !== 3 || parts[0] !== 'WOP' || parts[1] === '' || parts[2] === '') {
    throw new WopError(
      `securityReq "${securityReq}" 格式错误：应为 WOP-<密钥算法>-<摘要算法> 三段式且前缀为 WOP`,
      'parse',
    );
  }
  const [, keyAlg, digestAlg] = parts as [string, string, string];
  const keyFamily = KEY_ALG_FAMILY[keyAlg];
  const digestFamily = DIGEST_ALG_FAMILY[digestAlg];
  if (!keyFamily || !digestFamily) {
    throw new WopError(
      `不支持的算法组合 "${securityReq}"：密钥算法或摘要算法不在支持列表`,
      'unsupported',
    );
  }
  if (keyFamily !== digestFamily) {
    throw new WopError(
      `不支持的算法组合 "${securityReq}"：国际/国密跨族组合禁止（I5）`,
      'unsupported',
    );
  }
  // 走到这里的合法组合只剩 SM2-SM3（Q7：TS 首版暂未支持）
  throw new WopError('SM2-SM3 套件暂未支持，见 README 路线图', 'unsupported');
}
