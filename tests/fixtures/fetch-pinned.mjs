import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// 黄金向量钉版拉取（对齐 java-sdk 构建期模式）：真源 wop-platform/wop-specs，
// 副本不落库，按 ref+sha256 拉取校验，mismatch 即失败（fail-closed）。
// 升级流程见 CONTRIBUTING：先合 wop-specs PR，再同步 WOP_SPECS_REF 与下方 sha256。
// 消费方：vitest globalSetup（default export）与 package.json 各 test 脚本 CLI 前置。
const WOP_SPECS_REF = 'a1f7feb5b4af5c9052149e2adfd2063caa102677';
const WOP_SPECS_SHA256 = {
  'crypto/crypto-vectors.json': 'c7dd65740a1da9a5cfb804bca0c8b1bd7d4ab967adeb075297677a4bef148736',
  'interop/v1/interop-cases.json': 'c920ca1a93ccb3899a659f59fed6ec4652cf9e1b3b58bbdac23c45ac3ed2353e',
};
const fixturesDir = dirname(fileURLToPath(import.meta.url));

export default async function fetchPinnedSpecs() {
  for (const [src, expected] of Object.entries(WOP_SPECS_SHA256)) {
    const url = `https://raw.githubusercontent.com/wop-platform/wop-specs/${WOP_SPECS_REF}/${src}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`wop-specs ${src} 拉取失败：HTTP ${res.status}`);
    }
    const data = Buffer.from(await res.arrayBuffer());
    const digest = createHash('sha256').update(data).digest('hex');
    if (digest !== expected) {
      throw new Error(`wop-specs ${src} sha256 mismatch：期望 ${expected}，实得 ${digest}；向量升级须先合 wop-specs PR 再同步钉版`);
    }
    await writeFile(join(fixturesDir, basename(src)), data);
  }
}

if (process.argv[1] && [import.meta.url, fileURLToPath(import.meta.url)].includes(`file://${process.argv[1]}`)) {
  await fetchPinnedSpecs();
}
