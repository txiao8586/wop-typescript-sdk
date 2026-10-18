import { WopError } from '../error';
import { DEFAULT_READ_TIMEOUT } from '../config/types';
import type { Transport, TransportRequest, TransportResponse } from './types';

/**
 * 响应体读取上限：10MB 线上体上限 + 信封膨胀余量，防失控读
 * （对齐 dotnet MaxResponseBytes / Go maxResponseBytes = 11 << 20）。
 */
export const MAX_RESPONSE_BYTES = 11 << 20;

/**
 * fetch 原生适配器（零依赖，Node ≥18 / 浏览器）。
 */
export class FetchTransport implements Transport {
  // shortcut: fetch无connect/read分离超时,总时长按readTimeout近似,待P2拆分
  constructor(private readonly readTimeoutMs: number = DEFAULT_READ_TIMEOUT) {}

  /** 发送请求并结构化返回;发送失败抛 system,越限语义见类注释 */
  async send(request: TransportRequest): Promise<TransportResponse> {
    const init: RequestInit = {
      method: request.method,
      headers: request.headers,
      redirect: 'manual', // §7.4.1：不跟随重定向，避免改写已签名语义
      signal: AbortSignal.timeout(this.readTimeoutMs), // 防无限挂起；超时随 fetch 抛出归入 system
    };
    if (request.body !== '') {
      init.body = request.body;
    }
    let resp: Response;
    try {
      resp = await fetch(request.url, init);
    } catch (e) {
      throw new WopError(`请求发送失败：${(e as Error).message ?? e}`, 'system');
    }
    const headers: Record<string, string> = {};
    resp.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    return { status: resp.status, headers, body: await this.readBody(resp) };
  }

  /**
   * 流式读取响应体：计数在读取过程中生效，越限立即取消下载并抛协议类错误，
   * 而非读满后再检查（防超大/无限响应体撑爆内存）。
   * TextDecoder stream 模式保证多字节 UTF-8 跨 chunk 正确拼接。
   */
  private async readBody(resp: Response): Promise<string> {
    if (!resp.body) {
      return resp.text(); // 204/304 等无体语义（body 恒为空）
    }
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let received = 0;
    let out = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value!.byteLength;
      if (received > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined); // 取消失败不掩盖超限语义
        throw new WopError(`响应体超过 ${MAX_RESPONSE_BYTES} 字节上限`, 'parse');
      }
      out += decoder.decode(value!, { stream: true });
    }
    return out + decoder.decode();
  }
}
