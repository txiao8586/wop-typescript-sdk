/** execute 链路非 2xx 网关响应异常（§7.5） */
export class WopGatewayResponseError extends Error {
  readonly statusCode: number;
  readonly body: string;

  constructor(statusCode: number, body: string) {
    const bytes = new TextEncoder().encode(body).byteLength;
    super(`WOP 网关返回 HTTP ${statusCode}（响应体 ${bytes} 字节）`);
    this.name = 'WopGatewayResponseError';
    this.statusCode = statusCode;
    this.body = body;
  }
}
