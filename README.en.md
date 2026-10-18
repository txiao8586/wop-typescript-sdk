# wop-typescript-sdk

[![npm](https://img.shields.io/npm/v/@wanlianyida%2Fwop-typescript-sdk)](https://www.npmjs.com/package/@wanlianyida/wop-typescript-sdk) [![Release](https://img.shields.io/github/v/release/wop-platform/wop-typescript-sdk)](https://github.com/wop-platform/wop-typescript-sdk/releases)
[![CI](https://github.com/wop-platform/wop-typescript-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/wop-platform/wop-typescript-sdk/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/github/license/wop-platform/wop-typescript-sdk)](LICENSE)
[![Node 20+](https://img.shields.io/badge/node-20%2B-339933?logo=node.js&logoColor=white)](https://nodejs.org/) [![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/wop-platform/wop-typescript-sdk) [![Gherkin](https://img.shields.io/badge/bdd-15%20scenarios-orange)](tests/features/merchant-journey.feature) ![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/wop-platform/wop-typescript-sdk?utm_source=oss&utm_medium=github&utm_campaign=wop-platform-foss&utm_content=badge)


Official merchant-side TypeScript SDK for the WOP gateway: encapsulates the protocol core
(structured signing, body digest, L2 digital envelope, signature verification & decryption)
so merchants can integrate securely without knowing canonicalRequest, suite derivation,
or wire byte formats.

- **Zero runtime dependencies**: all cryptography via WebCrypto (`globalThis.crypto`, Node ≥20 / browser secure context)
- **Protocol core + pluggable transport**: built-in native `fetch` adapter; `axios` shipped as a peer adapter behind a separate entry point
- **CI-verified compatibility matrix**: Node 20–24 × axios 1.0–latest × TypeScript **5.0–7.0** (type-consumer floor 5.0, forward-probing to the latest major), published artifacts checked across ESM/CJS × node10/node16/bundler resolutions + API snapshot gate
- **100% line / branch / function / statement coverage**, byte-level anchored to golden test vectors

## Supported algorithm suites

| securityReq | Signature | Message (L2) | Key wrap | Digest |
|---|---|---|---|---|
| `WOP-RSA3072-SHA256` | SHA256withRSA | AES-256-GCM | RSA-3072-OAEP (dual SHA-256) | SHA-256 |
| `WOP-RSA4096-SHA256` | SHA256withRSA | AES-256-GCM | RSA-4096-OAEP (dual SHA-256) | SHA-256 |
| `WOP-SM2-SM3` | ❌ Not yet supported (see roadmap below) | | | |

Passing `WOP-SM2-SM3` throws `WopError('SM2-SM3 套件暂未支持，见 README 路线图')`.

### SM (Chinese national cryptography) roadmap

Per the unified WOP SDK spec (decision Q7), the first TypeScript release ships RSA suites only.
The SM2-SM3 national-crypto suite is on the roadmap and will arrive as a pure TypeScript
implementation (SM2 / SM3 / SM4-GCM) in a later release, extending the suite matrix without breaking the API.

## Quick start

```bash
npm install @wanlianyida/wop-typescript-sdk
```

```ts
import { WopClient } from '@wanlianyida/wop-typescript-sdk'; // or require('@wanlianyida/wop-typescript-sdk')

const client = new WopClient({
  appKey: 'your-app-key',
  suite: 'WOP-RSA3072-SHA256',        // securityReq
  merchantPrivateKey: '...',           // merchant private key (PKCS#8)
  platformPublicKey: '...',            // platform public key (X.509 SPKI)
  gatewayBaseUrl: 'https://gw.example.com',
});

// L0 plaintext request + automatic response verification/decryption
const resp = await client.send('POST', '/v1/order/create', JSON.stringify({ amount: 100 }));
if (resp.ok) {
  console.log(resp.plaintext);         // verified + decrypted response plaintext
}

// Callback verification (canonical URI is the callback URL's path)
const result = await client.verifyCallback(callbackHeaders, callbackBody, callbackUrl);
```

## Key preparation (D12 formats)

| Key | Format | Usage |
|---|---|---|
| Merchant private key | **PKCS#8 DER, Base64** (PEM or single-line Base64/Base64url accepted) | Request signing (SHA256withRSA) + response DEK unwrap (RSA-OAEP) |
| Platform public key | **X.509 SubjectPublicKeyInfo DER, Base64** (same) | Response/callback verification + request DEK wrap |

- RSA key length must match the suite (3072/4096); signatures are fixed-length 512 / 683 chars (base64url)
- PEM wrappers (`-----BEGIN PRIVATE KEY-----`) are stripped automatically; key material is equivalent

## L0 / L2 examples

```ts
// L0: signature only, body sent in plaintext
const draft = await client.buildRequest('POST', '/v1/order/create', body);
// draft.headers → send yourself; draft.wireBody → the original body

// L2: full digital envelope (AES-256-GCM + RSA-OAEP wrapped DEK)
const draftL2 = await client.buildRequest('POST', '/v1/order/create', body, { level: 'L2' });
// draftL2.wireBody = {"encrypted":"<base64url(ct||tag)>"}; headers include x-wop-encrypt: L2;dek=…

// GET without body: x-wop-content-digest is absent by design (D2)
// Note: paths containing `?` are rejected at build time (see Breaking changes)
const draftGet = await client.buildRequest('GET', '/v1/order/query');

// Use axios transport (optional peer)
import { AxiosTransport } from '@wanlianyida/wop-typescript-sdk/axios';
client.setTransport(new AxiosTransport());
```

## Vector self-test (conformance)

`tests/fixtures/crypto-vectors.json` in this repo is a full read-only copy of the protocol golden vectors.
Run the conformance suite (byte-level RSA assertions + SM "must-reject" negative tests):

```bash
git clone https://github.com/wop-platform/wop-typescript-sdk
cd wop-typescript-sdk
npm install
npm test          # full suite (includes vector conformance)
npm run coverage  # coverage report (line+branch ≥98% gate, currently 100%)
```

Vector coverage: RSA2048/3072/4096 signatures, OAEP wrap/unwrap (including the MGF1-SHA-1 trap negative vector),
AES-256-GCM with fixed IV, SHA-256 digest and digest-header format rules (D2 single space / lowercase hex /
cross-family rejection / strict unpadded base64url).

## Error handling & fuzzing (I7)

| Category | External semantics | Example |
|---|---|---|
| Parse / support / integrity / consistency | **Explicit** (aids integration debugging) | `securityReq 格式错误…`, `摘要不匹配…`, `DEK alg 与套件族不符…` |
| Signature / decryption | **Fuzzy** (oracle-safe) | uniform `签名验证失败` / `解密失败`; no detail on tag failure, key mismatch, etc. |
| System | `系统繁忙，请稍后重试` | missing keys, no WebCrypto runtime |

`WopError` carries a `category` field (`parse` / `unsupported` / `integrity` / `signature` / `decrypt` / `consistency` / `system`).

## License

MIT © wop-platform
