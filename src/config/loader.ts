import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WopError } from '../error';
import { parseConfigJson } from './configJsonParser';
import type { WopSdkConfig } from './types';

export const CONFIG_FILE_ENV_OVERRIDE = 'WOP_SDK_CONFIG_FILE';
export const CONFIG_FILE_ENV = 'WOP_SDK_CONFIG';
const PACKAGED_CONFIG = 'config/wopSdkConfig.json';

const cache = new Map<string, WopSdkConfig>();

/** 按 §4.2 自动发现并加载；同一位置缓存解析结果 */
export function loadDefault(): WopSdkConfig {
  const discovery = discover();
  return loadCached(discovery.cacheKey, discovery.readUtf8);
}

/** 显式文件系统路径加载 */
export function load(location: string): WopSdkConfig {
  if (!location) {
    throw new WopError('配置文件路径不能为空', 'configuration');
  }
  const normalized = path.resolve(location);
  return loadCached(`file:${normalized}`, () => readFileUtf8(normalized, true));
}

/** 清除加载缓存（测试 / 配置轮换编排） */
export function clearCache(): void {
  cache.clear();
}

function loadCached(key: string, reader: () => string): WopSdkConfig {
  const cached = cache.get(key);
  if (cached) {
    return cached;
  }
  const parsed = parseConfigJson(reader());
  cache.set(key, parsed);
  return parsed;
}

interface DiscoveryResult {
  cacheKey: string;
  readUtf8: () => string;
}

function discover(): DiscoveryResult {
  const explicitOverride = process.env[CONFIG_FILE_ENV_OVERRIDE]?.trim();
  if (explicitOverride) {
    const resolved = path.resolve(explicitOverride);
    return fileDiscovery(resolved, true);
  }
  const env = process.env[CONFIG_FILE_ENV]?.trim();
  if (env) {
    const resolved = path.resolve(env);
    return fileDiscovery(resolved, true);
  }
  const cwd = process.cwd();
  const home = os.homedir();
  const candidates = [
    path.join(cwd, 'config', 'wopSdkConfig.json'),
    path.join(cwd, 'wopSdkConfig.json'),
    path.join(home, '.wop', 'wopSdkConfig.json'),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      try {
        fs.accessSync(candidate, fs.constants.R_OK);
        return fileDiscovery(candidate, false);
      } catch {
        // 不可读则继续尝试下一候选
      }
    }
  }
  return bundledDiscovery();
}

function fileDiscovery(resolved: string, explicit: boolean): DiscoveryResult {
  const cacheKey = `file:${resolved}`;
  return {
    cacheKey,
    readUtf8: () => readFileUtf8(resolved, explicit),
  };
}

function readFileUtf8(resolved: string, explicit: boolean): string {
  if (!fs.existsSync(resolved)) {
    if (explicit) {
      throw new WopError(`显式配置文件不可读: ${resolved}`, 'configuration');
    }
    throw new WopError(`配置文件不可读: ${resolved}`, 'configuration');
  }
  try {
    fs.accessSync(resolved, fs.constants.R_OK);
  } catch (e) {
    if (explicit) {
      throw new WopError(`显式配置文件不可读: ${resolved}`, 'configuration', e);
    }
    throw new WopError(`配置文件不可读: ${resolved}`, 'configuration', e);
  }
  try {
    return fs.readFileSync(resolved, 'utf8');
  } catch (e) {
    throw new WopError(`配置文件读取失败: ${resolved}`, 'configuration', e);
  }
}

function moduleDirectory(): string {
  // CJS 产物由 tsup 注入 __dirname；ESM 使用 import.meta.url
  if (typeof __dirname !== 'undefined') {
    return __dirname;
  }
  return path.dirname(fileURLToPath(import.meta.url));
}

function bundledDiscovery(): DiscoveryResult {
  const moduleDir = moduleDirectory();
  const candidates = [
    path.resolve(moduleDir, '../../config/wopSdkConfig.json'),
    path.resolve(moduleDir, '../../config/wopSdkConfigDefault.json'),
    path.resolve(process.cwd(), 'config/wopSdkConfigDefault.json'),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      try {
        fs.accessSync(candidate, fs.constants.R_OK);
        return fileDiscovery(candidate, false);
      } catch {
        // 继续
      }
    }
  }
  const cwd = process.cwd();
  const home = os.homedir();
  throw new WopError(
    [
      '未找到可读的配置文件，已尝试：',
      process.env[CONFIG_FILE_ENV_OVERRIDE] ? `${CONFIG_FILE_ENV_OVERRIDE}=${process.env[CONFIG_FILE_ENV_OVERRIDE]}` : null,
      process.env[CONFIG_FILE_ENV] ? `${CONFIG_FILE_ENV}=${process.env[CONFIG_FILE_ENV]}` : null,
      path.join(cwd, 'config', 'wopSdkConfig.json'),
      path.join(cwd, 'wopSdkConfig.json'),
      path.join(home, '.wop', 'wopSdkConfig.json'),
      PACKAGED_CONFIG,
    ]
      .filter(Boolean)
      .join('\n'),
    'configuration',
  );
}
