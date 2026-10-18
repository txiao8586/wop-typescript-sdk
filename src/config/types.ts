import type { Transport } from '../transport/types';

/** HTTP 客户端全局设置（§3.3 httpClient 对象，不可变） */
export interface HttpClientSettings {
  connectTimeout: number;
  readTimeout: number;
  maxRetryCount: number;
}

export const DEFAULT_CONNECT_TIMEOUT = 10_000;
export const DEFAULT_READ_TIMEOUT = 30_000;
export const DEFAULT_MAX_RETRY_COUNT = 3;
export const DEFAULT_EXPIRED_SECONDS = 1800;

/** 默认超时与重试上限 */
export function defaultHttpClientSettings(): HttpClientSettings {
  return {
    connectTimeout: DEFAULT_CONNECT_TIMEOUT,
    readTimeout: DEFAULT_READ_TIMEOUT,
    maxRetryCount: DEFAULT_MAX_RETRY_COUNT,
  };
}

/** 配置不可变快照（§3，camelCase 字段与 JSON 一致） */
export interface WopSdkConfig {
  appKey: string;
  suite: string;
  merchantPrivateKey: string;
  platformPublicKey: string;
  serverRoot: string;
  backupServerRoots: readonly string[];
  expiredSeconds: number;
  httpClient: HttpClientSettings;
  /** 可选注入传输；缺省时走默认 fetch 适配器 */
  transport?: Transport;
}

/** K16：日志/toString 私钥打码 */
export function maskConfigForLog(config: Pick<WopSdkConfig, 'appKey' | 'suite' | 'serverRoot' | 'backupServerRoots' | 'expiredSeconds' | 'httpClient'>): string {
  return `WopSdkConfig[appKey=${config.appKey}, suite=${config.suite}, merchantPrivateKey=****, platformPublicKey=****, serverRoot=${config.serverRoot}, backupServerRoots=${JSON.stringify(config.backupServerRoots)}, expiredSeconds=${config.expiredSeconds}, httpClient=${JSON.stringify(config.httpClient)}]`;
}
