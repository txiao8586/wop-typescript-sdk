import { WopError } from '../error';
import { keyMaterialToDer } from '../keys';
import { parseSecurityReq } from '../suite';
import type { WopSdkConfig } from './types';
import { validateGatewayUrl } from './url';

/** §3.4 语义校验与字段归一化 */
export function validateAndNormalize(raw: WopSdkConfig): WopSdkConfig {
  if (!raw.appKey?.trim()) {
    throw new WopError('配置文件缺少必填项: appKey', 'configuration');
  }
  if (!raw.suite?.trim()) {
    throw new WopError('配置文件缺少必填项: suite', 'configuration');
  }
  if (!raw.merchantPrivateKey?.trim()) {
    throw new WopError('配置文件缺少必填项: merchantPrivateKey', 'configuration');
  }
  if (!raw.platformPublicKey?.trim()) {
    throw new WopError('配置文件缺少必填项: platformPublicKey', 'configuration');
  }
  if (!raw.serverRoot?.trim()) {
    throw new WopError('配置文件缺少必填项: serverRoot', 'configuration');
  }
  if (raw.expiredSeconds <= 0) {
    throw new WopError('expiredSeconds 须为正整数', 'configuration');
  }
  let suite;
  try {
    suite = parseSecurityReq(raw.suite);
  } catch (e) {
    throw new WopError(`不支持的算法套件: ${raw.suite}`, 'configuration', e);
  }
  try {
    keyMaterialToDer(raw.merchantPrivateKey);
    keyMaterialToDer(raw.platformPublicKey);
    void suite;
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    throw new WopError(`密钥解析失败: ${message}`, 'configuration', e);
  }
  const serverRoot = validateGatewayUrl(raw.serverRoot, 'serverRoot');
  const backups: string[] = [];
  for (let i = 0; i < raw.backupServerRoots.length; i++) {
    backups.push(validateGatewayUrl(raw.backupServerRoots[i], `backupServerRoots[${i}]`));
  }
  const http = raw.httpClient;
  if (http.connectTimeout <= 0 || http.readTimeout <= 0 || http.maxRetryCount < 0) {
    throw new WopError('配置字段 httpClient 类型非法: 超时须为正整数，maxRetryCount 须非负', 'configuration');
  }
  return {
    appKey: raw.appKey.trim(),
    suite: raw.suite.trim(),
    merchantPrivateKey: raw.merchantPrivateKey.trim(),
    platformPublicKey: raw.platformPublicKey.trim(),
    serverRoot,
    backupServerRoots: Object.freeze([...backups]),
    expiredSeconds: raw.expiredSeconds,
    httpClient: { ...http },
    ...(raw.transport !== undefined ? { transport: raw.transport } : {}),
  };
}

/** 程序化构造（K11），build() 执行与 JSON 路径等价的 §3.4 校验 */
export function buildConfig(input: Partial<WopSdkConfig> & Pick<WopSdkConfig, 'appKey' | 'suite' | 'merchantPrivateKey' | 'platformPublicKey' | 'serverRoot'>): WopSdkConfig {
  return validateAndNormalize({
    ...input,
    backupServerRoots: input.backupServerRoots ?? [],
    expiredSeconds: input.expiredSeconds ?? 1800,
    httpClient: input.httpClient ?? {
      connectTimeout: 10_000,
      readTimeout: 30_000,
      maxRetryCount: 3,
    },
  });
}
