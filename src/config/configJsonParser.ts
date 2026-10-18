import { WopError } from '../error';
import {
  DEFAULT_EXPIRED_SECONDS,
  defaultHttpClientSettings,
  type HttpClientSettings,
  type WopSdkConfig,
} from './types';
import { validateAndNormalize } from './configValidator';

/** 配置专用极简 JSON 解析器（K8/K21）：忽略未知顶层字段；检测重复键；支持一层嵌套 httpClient */
export function parseConfigJson(json: string | null | undefined): WopSdkConfig {
  if (json == null) {
    throw new WopError('配置文件 JSON 解析失败: 空内容', 'configuration');
  }
  const trimmed = stripBom(json.trim());
  if (trimmed === '') {
    throw new WopError('配置文件 JSON 解析失败: 空文件', 'configuration');
  }
  return new ConfigJsonParser(trimmed).parseRoot();
}

function stripBom(text: string): string {
  return text.startsWith('\uFEFF') ? text.slice(1) : text;
}

class ConfigJsonParser {
  private pos = 0;

  constructor(private readonly json: string) {}

  parseRoot(): WopSdkConfig {
    this.expect('{');
    let appKey: string | null = null;
    let suite: string | null = null;
    let merchantPrivateKey: string | null = null;
    let platformPublicKey: string | null = null;
    let serverRoot: string | null = null;
    let backupServerRoots: string[] = [];
    let expiredSeconds: number | null = null;
    let httpClient: HttpClientSettings | null = null;
    const seen = new Set<string>();
    this.skipWhitespace();
    if (!this.tryConsume('}')) {
      do {
        const key = this.readString();
        this.requireDuplicateFree(seen, key);
        this.expect(':');
        switch (key) {
          case 'appKey':
            appKey = this.readString();
            break;
          case 'suite':
            suite = this.readString();
            break;
          case 'merchantPrivateKey':
            merchantPrivateKey = this.readString();
            break;
          case 'platformPublicKey':
            platformPublicKey = this.readString();
            break;
          case 'serverRoot':
            serverRoot = this.readString();
            break;
          case 'backupServerRoots':
            backupServerRoots = this.readStringArray();
            break;
          case 'expiredSeconds':
            expiredSeconds = this.readLong('expiredSeconds');
            break;
          case 'httpClient':
            httpClient = this.readHttpClient();
            break;
          default:
            this.skipValue();
        }
      } while (this.memberSeparator('}'));
    }
    // 根对象闭合后只允许空白（Sourcery CR：缺逗号/尾随垃圾不得静默接受）
    this.skipWhitespace();
    if (this.pos !== this.json.length) {
      throw this.syntax('根对象后存在多余内容');
    }
    const raw: WopSdkConfig = {
      appKey: appKey ?? '',
      suite: suite ?? '',
      merchantPrivateKey: merchantPrivateKey ?? '',
      platformPublicKey: platformPublicKey ?? '',
      serverRoot: serverRoot ?? '',
      backupServerRoots,
      expiredSeconds: expiredSeconds ?? DEFAULT_EXPIRED_SECONDS,
      httpClient: httpClient ?? defaultHttpClientSettings(),
    };
    return validateAndNormalize(raw);
  }

  private readHttpClient(): HttpClientSettings {
    this.expect('{');
    let connect: number | null = null;
    let read: number | null = null;
    let maxRetry: number | null = null;
    const seen = new Set<string>();
    this.skipWhitespace();
    if (!this.tryConsume('}')) {
      do {
        const key = this.readString();
        this.requireDuplicateFree(seen, key);
        this.expect(':');
        switch (key) {
          case 'connectTimeout':
            connect = this.readInt('connectTimeout');
            break;
          case 'readTimeout':
            read = this.readInt('readTimeout');
            break;
          case 'maxRetryCount':
            // validator 语义为非负:0(禁用重试)合法,其余字段仍须 >0
            maxRetry = this.readInt('maxRetryCount', true);
            break;
          default:
            this.skipValue();
        }
      } while (this.memberSeparator('}'));
    }
    const defaults = defaultHttpClientSettings();
    return {
      connectTimeout: connect ?? defaults.connectTimeout,
      readTimeout: read ?? defaults.readTimeout,
      maxRetryCount: maxRetry ?? defaults.maxRetryCount,
    };
  }

  private readStringArray(): string[] {
    this.expect('[');
    const values: string[] = [];
    this.skipWhitespace();
    if (!this.tryConsume(']')) {
      do {
        values.push(this.readString());
      } while (this.memberSeparator(']'));
    }
    return values;
  }

  private requireDuplicateFree(seen: Set<string>, key: string): void {
    if (seen.has(key)) {
      throw new WopError(`配置字段 ${key} 重复: ${key}`, 'configuration');
    }
    seen.add(key);
  }

  private readString(): string {
    this.skipWhitespace();
    if (this.pos >= this.json.length || this.json[this.pos] !== '"') {
      throw this.syntax('期望字符串');
    }
    this.pos++;
    let out = '';
    while (this.pos < this.json.length) {
      const c = this.json[this.pos++]!;
      if (c === '"') {
        return out;
      }
      if (c === '\\') {
        if (this.pos >= this.json.length) {
          throw this.syntax('字符串转义不完整');
        }
        const esc = this.json[this.pos++]!;
        switch (esc) {
          case '"':
          case '\\':
          case '/':
            out += esc;
            break;
          case 'b':
            out += '\b';
            break;
          case 'f':
            out += '\f';
            break;
          case 'n':
            out += '\n';
            break;
          case 'r':
            out += '\r';
            break;
          case 't':
            out += '\t';
            break;
          case 'u':
            out += this.readUnicode();
            break;
          default:
            throw this.syntax(`非法转义 \\${esc}`);
        }
      } else {
        out += c;
      }
    }
    throw this.syntax('字符串未闭合');
  }

  private readUnicode(): string {
    if (this.pos + 4 > this.json.length) {
      throw this.syntax('\\u 转义不完整');
    }
    let code = 0;
    for (let i = 0; i < 4; i++) {
      const h = this.json[this.pos++]!;
      code <<= 4;
      if (h >= '0' && h <= '9') {
        code += h.charCodeAt(0) - 48;
      } else if (h >= 'a' && h <= 'f') {
        code += h.charCodeAt(0) - 97 + 10;
      } else if (h >= 'A' && h <= 'F') {
        code += h.charCodeAt(0) - 65 + 10;
      } else {
        throw this.syntax('\\u 转义非法');
      }
    }
    return String.fromCharCode(code);
  }

  private readLong(fieldName: string, allowZero = false): number {
    this.skipWhitespace();
    const start = this.pos;
    if (this.pos < this.json.length && this.json[this.pos] === '-') {
      this.pos++;
    }
    while (this.pos < this.json.length && /\d/.test(this.json[this.pos]!)) {
      this.pos++;
    }
    if (start === this.pos) {
      throw this.syntax('期望数字');
    }
    const num = this.json.slice(start, this.pos);
    const value = Number(num);
    if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1)) {
      throw new WopError(`配置字段 ${fieldName} 类型非法: ${num}`, 'configuration');
    }
    return value;
  }

  private readInt(fieldName: string, allowZero = false): number {
    const value = this.readLong(fieldName, allowZero);
    if (value > 0x7fff_ffff) {
      throw new WopError(`配置字段 httpClient 类型非法: 数值越界`, 'configuration');
    }
    return value;
  }

  private skipValue(): void {
    this.skipWhitespace();
    if (this.pos >= this.json.length) {
      throw this.syntax('意外结束');
    }
    const c = this.json[this.pos]!;
    if (c === '"') {
      this.readString();
    } else if (c === '{') {
      this.skipObject();
    } else if (c === '[') {
      this.skipArray();
    } else if (c === 't' || c === 'f' || c === 'n') {
      this.skipLiteral();
    } else {
      while (this.pos < this.json.length && !',]}'.includes(this.json[this.pos]!)) {
        this.pos++;
      }
    }
  }

  private skipObject(): void {
    this.expect('{');
    this.skipWhitespace();
    if (!this.tryConsume('}')) {
      do {
        this.readString();
        this.expect(':');
        this.skipValue();
      } while (this.memberSeparator('}'));
    }
  }

  private skipArray(): void {
    this.expect('[');
    this.skipWhitespace();
    if (!this.tryConsume(']')) {
      do {
        this.skipValue();
      } while (this.memberSeparator(']'));
    }
  }

  private skipLiteral(): void {
    while (this.pos < this.json.length && /[a-zA-Z]/.test(this.json[this.pos]!)) {
      this.pos++;
    }
  }

  private expect(ch: string): void {
    this.skipWhitespace();
    if (this.pos >= this.json.length || this.json[this.pos] !== ch) {
      throw this.syntax(`期望 '${ch}'`);
    }
    this.pos++;
  }

  private tryConsume(ch: string): boolean {
    this.skipWhitespace();
    if (this.pos < this.json.length && this.json[this.pos] === ch) {
      this.pos++;
      return true;
    }
    return false;
  }

  /**
   * 成员分隔符严格判定（RFC 8259）：成员之间必须有逗号，且逗号后不得紧跟闭合符
   * （拒绝尾随逗号）。返回 true = 还有下一个成员；false = 容器闭合（已消费闭合符）。
   */
  private memberSeparator(closing: string): boolean {
    this.skipWhitespace();
    if (this.pos < this.json.length && this.json[this.pos] === ',') {
      this.pos++;
      this.skipWhitespace();
      if (this.pos < this.json.length && this.json[this.pos] === closing) {
        throw this.syntax(`尾随逗号（'${closing}' 前不得有逗号）`);
      }
      return true;
    }
    if (this.pos < this.json.length && this.json[this.pos] === closing) {
      this.pos++;
      return false;
    }
    throw this.syntax(`期望 ',' 或 '${closing}'`);
  }

  private skipWhitespace(): void {
    while (this.pos < this.json.length && /\s/.test(this.json[this.pos]!)) {
      this.pos++;
    }
  }

  private syntax(detail: string): WopError {
    return new WopError(`配置文件 JSON 解析失败: ${detail}`, 'configuration');
  }
}
