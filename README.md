# wop-typescript-sdk

[![npm](https://img.shields.io/npm/v/@wanlianyida%2Fwop-typescript-sdk)](https://www.npmjs.com/package/@wanlianyida/wop-typescript-sdk) [![Release](https://img.shields.io/github/v/release/wop-platform/wop-typescript-sdk)](https://github.com/wop-platform/wop-typescript-sdk/releases)
[![CI](https://github.com/wop-platform/wop-typescript-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/wop-platform/wop-typescript-sdk/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/github/license/wop-platform/wop-typescript-sdk)](LICENSE)
[![Node 20+](https://img.shields.io/badge/node-20%2B-339933?logo=node.js&logoColor=white)](https://nodejs.org/) [![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/wop-platform/wop-typescript-sdk) [![Gherkin](https://img.shields.io/badge/bdd-15%20scenarios-orange)](tests/features/merchant-journey.feature) ![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/wop-platform/wop-typescript-sdk?utm_source=oss&utm_medium=github&utm_campaign=wop-platform-foss&utm_content=badge)


> **WOP · 万联易达开放平台** 官方 TypeScript SDK —— 协议与黄金向量真源：[wop-specs](https://github.com/wop-platform/wop-specs)

WOP 商户侧官方 TypeScript SDK：封装协议核心（结构化签名 / 报文摘要 / L2 数字信封 / 验签解密），
使商户无需理解 canonicalRequest、套件推导与线上字节格式即可安全对接 WOP 网关。

- 协议真源：[crypto-strategy-spec.md](https://github.com/wop-platform/wop-specs/blob/main/crypto/crypto-strategy-spec.md)（v0.3-reviewed）+ [wop-sdk-spec.md](https://github.com/wop-platform/wop-specs/blob/main/sdk/wop-sdk-spec.md)（v1.0-ratified）
- 向量真源：[crypto-vectors.json](https://github.com/wop-platform/wop-specs/blob/main/crypto/crypto-vectors.json)（本仓 fixture 为字节级副本，禁手改）
- **零运行时依赖**：全部密码学走 WebCrypto（`globalThis.crypto`，Node ≥20 / 浏览器安全上下文）
- **协议核心 + 可插拔传输**：`fetch` 原生适配器内置，`axios` 以 peer 适配器独立入口交付
- **兼容性矩阵 CI 验证**：Node 20–24 × **Linux / macOS / Windows** × axios 1.0–latest × TypeScript **5.0–7.0**（类型消费下界 5.0，前瞻至最新大版本），发布物 ESM/CJS × node10/node16/bundler 四解析模式 + API 快照门禁
- **行 / 分支 / 函数 / 语句覆盖率 100%**，黄金测试向量字节级锚定

## 支持的算法套件

| securityReq | 签名 | 报文加密（L2） | 密钥包装 | 摘要 |
|---|---|---|---|---|
| `WOP-RSA2048-SHA256` | SHA256withRSA | AES-256-GCM | RSA-2048-OAEP（双 SHA-256） | SHA-256 |
| `WOP-RSA3072-SHA256` | SHA256withRSA | AES-256-GCM | RSA-3072-OAEP（双 SHA-256） | SHA-256 |
| `WOP-RSA4096-SHA256` | SHA256withRSA | AES-256-GCM | RSA-4096-OAEP（双 SHA-256） | SHA-256 |
| `WOP-SM2-SM3` | ❌ 暂未支持（见下方路线图） | | | |

传入 `WOP-SM2-SM3` 会抛出 `WopError('SM2-SM3 套件暂未支持，见 README 路线图')`。

### 国密路线图

按 WOP SDK 统一规格（Q7 裁决），TypeScript 首版仅实现 RSA 套件；SM2-SM3 国密套件已列入路线图，
将以纯 TypeScript 实现（SM2 / SM3 / SM4-GCM）在后续版本交付，届时保持 API 兼容，仅扩展套件矩阵。

## 快速开始

```bash
npm install @wanlianyida/wop-typescript-sdk
```

```ts
import { WopClient } from '@wanlianyida/wop-typescript-sdk'; // 或 require('@wanlianyida/wop-typescript-sdk')

const client = new WopClient({
  appKey: 'your-app-key',
  suite: 'WOP-RSA3072-SHA256',        // securityReq
  merchantPrivateKey: '...',           // 商户私钥（PKCS#8）
  platformPublicKey: '...',            // 平台公钥（X.509 SPKI）
  gatewayBaseUrl: 'https://gw.example.com',
});

// L0 明文请求 + 自动验签解密响应
const resp = await client.send('POST', '/v1/order/create', JSON.stringify({ amount: 100 }));
if (resp.ok) {
  console.log(resp.plaintext);         // 已验签 + 已解密的响应明文
}

// 回调验签（canonical 的 URI 取回调 URL 的 path）
const result = await client.verifyCallback(callbackHeaders, callbackBody, callbackUrl);
```

## 密钥准备（D12 格式）

| 密钥 | 格式 | 说明 |
|---|---|---|
| 商户私钥 | **PKCS#8 DER 的 Base64**（PEM 或单行 Base64/Base64url 均可） | 请求加签（SHA256withRSA）+ 响应 DEK 解包（RSA-OAEP） |
| 平台公钥 | **X.509 SubjectPublicKeyInfo DER 的 Base64**（同上） | 响应/回调验签 + 请求 DEK 包装 |

- RSA 密钥长度必须与套件一致（3072/4096），签名定长 512 / 683 字符（base64url）
- PEM 包装（`-----BEGIN PRIVATE KEY-----`）会被自动剥离，密钥材料等价

## L0 / L2 示例

```ts
// L0：仅签名，body 明文上送
const draft = await client.buildRequest('POST', '/v1/order/create', body);
// draft.headers → 自行携带发送；draft.wireBody → 原 body

// L2：全文数字信封（AES-256-GCM + RSA-OAEP 包 DEK）
const draftL2 = await client.buildRequest('POST', '/v1/order/create', body, { level: 'L2' });
// draftL2.wireBody = {"encrypted":"<base64url(ct||tag)>"}；headers 含 x-wop-encrypt: L2;dek=…

// GET 无 body：x-wop-content-digest 自动缺席（D2）
// 当前版本 path 不支持 query 参数：含 ? 的 path 会在构造期直接抛错（见下方「破坏性变更」）
const draftGet = await client.buildRequest('GET', '/v1/order/query');

// 使用 axios 传输（peer 可选）
import { AxiosTransport } from '@wanlianyida/wop-typescript-sdk/axios';
client.setTransport(new AxiosTransport());
```

## 破坏性变更

- **path 含 `?` 从「拆分入 canonical」改为构造期拒绝**：`buildRequest` / `send` / `execute` 对含 `?` 或 `#` 的 path 直接抛错（configuration 类）。网关 canonical 本就不支持 query 参数，fail-fast 早于签名与发送；带筛选条件的接口请改用 body 表达。
- **错误类目 `system` → `configuration` 及文案变更**：path 校验类错误（空 path、非 `/` 前缀、`//` 前缀、绝对 URL、含控制字符 CR/LF/NUL/DEL 等 <0x20/0x7F——错误信息只回显码点、不回显原值）由 system 调整为 configuration，文案同步变更。按 `category === 'system'` 做可重试判定的调用方需更新分支。
- **新增恒定请求头 `x-wop-request-id`**（恒存在、恒不入签，wop-specs 附录 I）：使用 CORS 精确 allowlist 的浏览器侧部署须在 `Access-Control-Allow-Headers` 中追加该头，否则预检（OPTIONS）失败、请求无法发出。

## 预留字段

- **`httpClient.maxRetryCount` / `backupServerRoots` 为预留字段，当前版本不生效**（P2）：传输层仅消费 `readTimeout` 超时（且为 fetch 总时长近似，见 transport 实现注释）；配置重试上限或备用网关根不会产生任何重试或切换行为。

## 向量自测（conformance）

本仓 `tests/fixtures/crypto-vectors.json` 为协议黄金向量全量副本（只读，禁止手改）。
克隆仓库后运行 conformance 套件（RSA 段字节级断言 + SM 段"必须拒"负测试）：

```bash
git clone https://github.com/wop-platform/wop-typescript-sdk
cd wop-typescript-sdk
npm install
npm test          # 全量测试（含向量 conformance）
npm run coverage  # 覆盖率报告（行+分支 ≥98% 门禁，当前 100%）
```

向量覆盖：RSA3072/4096 签名、OAEP 包装/解包（含 MGF1-SHA-1 陷阱负向量）、AES-256-GCM 定 IV、
SHA-256 摘要与 digest header 格式规则（D2 恰一空格 / 小写 hex / 跨族拒绝 / base64url 严格无填充）。

## 错误处理与模糊化（I7）

| 类别 | 对外语义 | 示例 |
|---|---|---|
| 解析 / 支持 / 完整性 / 一致性 | **明确**（帮助集成自查） | `securityReq 格式错误…`、`摘要不匹配…`、`DEK alg 与套件族不符…` |
| 验签 / 解密 | **模糊**（防 oracle） | 统一 `签名验证失败` / `解密失败`，不区分 tag 失败、密钥不符等细节 |
| 系统 | `系统繁忙，请稍后重试` | 密钥缺失、运行时缺 WebCrypto |

`WopError` 携带 `category` 字段（`parse` / `unsupported` / `integrity` / `signature` / `decrypt` / `consistency` / `system`）。

## 🧩 WOP 生态导航 | Ecosystem

| 类别 | 组件 |
|------|------|
| 协议与向量真源 | [wop-specs](https://github.com/wop-platform/wop-specs) —— crypto-strategy-spec · wop-sdk-spec · 黄金测试向量 |
| 官方 SDK（六语言） | [Java](https://github.com/wop-platform/wop-java-sdk) · [Go](https://github.com/wop-platform/wop-go-sdk) · [Python](https://github.com/wop-platform/wop-python-sdk) · [PHP](https://github.com/wop-platform/wop-php-sdk) · [.NET](https://github.com/wop-platform/wop-dotnet-sdk) · [TypeScript](https://github.com/wop-platform/wop-typescript-sdk) |
| 浏览器工作台 | [wop-web-tools](https://github.com/wop-platform/wop-web-tools) —— 密钥生成 · 报文联调 · 国密 · 六语言代码片段 |
| Agent 技能包 | [wop-skills](https://github.com/wop-platform/wop-skills) —— 零代码调用 · 联调对拍 · 62 错误码排错 |
| 平台服务（企业内部） | 统一接入网关 · 核心逻辑服务 · 回调服务 · 开发者门户 · 文档中心 |

## License

MIT © wop-platform
