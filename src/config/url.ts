import { WopError } from '../error';

/** K20：HTTPS 绝对 URL，拒绝 query/fragment */
export function validateGatewayUrl(value: string | null | undefined, fieldName: string): string {
  if (value == null || value.trim() === '') {
    throw new WopError(`${fieldName} 不是合法 URL: ${value ?? ''}`, 'configuration');
  }
  const trimmed = value.trim();
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new WopError(`${fieldName} 不是合法 URL: ${trimmed}`, 'configuration');
  }
  if (url.protocol !== 'https:') {
    throw new WopError(`${fieldName} 须为 HTTPS 绝对 URL: ${trimmed}`, 'configuration');
  }
  if (url.search !== '' || url.hash !== '') {
    throw new WopError(`${fieldName} 不得含 query 或 fragment: ${trimmed}`, 'configuration');
  }
  if (!url.hostname) {
    throw new WopError(`${fieldName} 不是合法 URL: ${trimmed}`, 'configuration');
  }
  let normalized = `https://${url.hostname.toLowerCase()}`;
  if (url.port) {
    normalized += `:${url.port}`;
  }
  normalized += url.pathname;
  if (normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

/** §7.7 API path 语法校验 */
export function validateApiPath(path: string): void {
  // JS 调用方可能传入 null/undefined 等非字符串（Sourcery CR）：先做运行时类型防护，
  // 抛 SDK 定义的 WopError 而非原生 TypeError
  if (typeof path !== 'string' || !path) {
    throw new WopError('请求路径为空', 'configuration');
  }
  // 控制字符扫描须先于任何回显原值的错误：否则 CR/LF/<0x20/0x7F 可通过校验并在签名后的日志行伪造条目
  for (const ch of path) {
    const cp = ch.codePointAt(0)!;
    if (cp < 0x20 || cp === 0x7f) {
      // 不回显原值，只回显码点（防错误信息本身被注入）
      throw new WopError(
        `path 含控制字符（码点 U+${cp.toString(16).toUpperCase().padStart(4, '0')}），已拒绝`,
        'configuration',
      );
    }
  }
  if (!path.startsWith('/')) {
    throw new WopError(`path 须以 / 开头: ${path}`, 'configuration');
  }
  if (path.startsWith('//')) {
    throw new WopError(`path 不得 // 开头: ${path}`, 'configuration');
  }
  if (path.includes('?') || path.includes('#')) {
    throw new WopError(`path 不得含 query 或 fragment: ${path}`, 'configuration');
  }
  if (/^https?:/i.test(path)) {
    throw new WopError(`path 不得为绝对 URL: ${path}`, 'configuration');
  }
}

/** §7.7 字符串拼接 serverRoot + path */
export function joinUrl(serverRoot: string, path: string): string {
  validateApiPath(path);
  const root = serverRoot.endsWith('/') ? serverRoot.slice(0, -1) : serverRoot;
  const trimmedPath = path.startsWith('/') ? path : `/${path}`;
  return root + trimmedPath;
}
