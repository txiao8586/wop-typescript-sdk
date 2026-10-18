/**
 * WOP SDK 错误类型。
 *
 * 分类对齐 gateway spec §10.2：
 * - parse / unsupported / integrity / consistency：鉴权前可判定的公开协议知识 → 对外语义**明确**
 * - signature / decrypt：依赖密钥参与的判定 → 对外语义**模糊**（I7 防 oracle）
 * - system：密钥缺失、内部异常
 */
export type WopErrorCategory =
  | 'parse'
  | 'unsupported'
  | 'integrity'
  | 'signature'
  | 'decrypt'
  | 'consistency'
  | 'configuration'
  | 'system';

/** SDK 统一错误:category 取 WopErrorCategory,对外语义明确/模糊按分类规则 */
export class WopError extends Error {
  readonly category: WopErrorCategory;

  constructor(message: string, category: WopErrorCategory = 'parse', cause?: unknown) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = 'WopError';
    this.category = category;
  }
}

/** I7：验签失败对外模糊语义 */
export const SIGNATURE_FAILED = '签名验证失败';

/** I7：解密失败对外模糊语义（DEK 解包失败 / GCM tag 失败不区分） */
export const DECRYPT_FAILED = '解密失败';
