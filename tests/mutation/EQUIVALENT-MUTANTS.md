# 变异测试幸存体归档：15 个等价变异证明（2026-08-31 定局轮）

> 击杀率 94.27%（247/262，门禁 ≥90% 通过）。以下 15 个幸存体均为**黑盒行为等价**——
> 即不存在任何不改 src 语义的测试能区分它们（证明附后）。它们不是测试缺口，
> 而是（a）防御性冗余代码、（b）I7 模糊化纪律的固有代价、（c）环境等价、（d）语义保真分支。
>
> 历史轮次：08-29 第四轮 263/250/95.06%；08-31 定局轮在 main 侧 code-scanning 修复
> （commit cb51dbd，fromBase64 正则剥填充 → trimBase64Padding 线性扫描）与测试增补后重测。

| # | 位置 | 算子 | 锚 | 等价原因 |
|---|------|------|----|---------|
| 1 | client.ts:533 | cond-lt `dekIdx < 0` → `<= 0` | `if (dekIdx < 0)` | `dekIdx === 0` 不可达：进入该分支要求头以 `l2` 开头（`startsWith`），而 `indexOf('dek=') === 0` 要求头以 `dek=` 开头，二者互斥 | |
| 2 | `client.ts:502` | bool `sigOk = true` → `false` | `authString: `${protocolV` | 初值唯一读取点在 `rsaVerify` 返回后立即覆盖；rsaVerify 抛错路径经 catch 显式赋 `false`，两初值在所有路径终值一致 | |
| 3 | client.ts:435 | string `'parse'` category 追加 | `throw new WopError('响应缺少 x-wop-sign 头'` | `verifyResponse` 捕获 WopError 后仅外显 `e.message`；内部 category 无任何可观测通道（对外契约是 VerifyResult{ok,reason}） | |
| 4 | `client.ts:548` | string `'consistency'` category 追加 | `// 一律归入解密类模糊（I7 保守默认，int` | 同上 | |
| 5 | crypto.ts:146 | cond-lt `len < 16` → `<= 16` | `if (cipherTag.length < 1` | 16B 输入：短路路径抛 `DECRYPT_FAILED`；非短路走 WebCrypto GCM（空明文+16B tag）tag 校验失败同抛 `DECRYPT_FAILED`（I7 模糊化使两路径文案恒同） | |
| 6 | crypto.ts:146 | numeric `16` → `17` | `if (cipherTag.length < 1` | 15/16B 输入两路径同文案（同上）；17B+ 输入不受阈值影响 | |
| 7 | crypto.ts:146 | stmt-del 删除短路 if | `if (cipherTag.length < 1` | 15B 输入走 WebCrypto 失败 → 同文案（同上） | |
| 8 | crypto.ts:28 | stmt-del 删除 `if (g?.subtle) return g` | `if (g?.subtle) return g;` | Node ≥19 中 `globalThis.crypto` 与 `node:crypto.webcrypto` 为同一对象，快路径与回退路径返回值不可区分（`toBe` 已断言通过）；浏览器目标中该 if 生效，vitest 无法在 Node 下构造区分（环境等价） | |
| 9 | encode.ts:67 | cond-gt `end > 0` → `>= 0`（换行探测） | `function trimBase64Paddi` | `end === 0`（空串）时：原版跳过 if；变异进入后 `s[-1]` 为 undefined ≠ `'\n'`，同样无操作。空串两版可观测行为一致 | |
| 10 | encode.ts:67 | stmt-del 删除换行探测 if | `function trimBase64Paddi` | `trimBase64Padding` 的换行探测是**语义保真分支**：任何含 `\n` 的输入，无论是否先剥换行再剥 `=`，trimmed 最终必含 `\n` 或 `=`，均被下游正则 `/^[A-Za-z0-9+/]*$/` 以同一文案拒绝；不含 `\n` 的输入两版剥填充结果逐位相同。黑盒不可区分（cb51dbd 引入） | |
| 11 | encode.ts:71 | cond-gt `end > 0` → `>= 0`（剥 = 循环下界） | `trailingNl = 1;` | `end === 0` 时 `s[-1]` 为 undefined ≠ `'='`，循环立即退出，无行为差异 | |
| 12 | encode.ts:90 | cond-lt `i < out.length` → `<=`（fromHex） | `throw new WopError('hex ` | 多出的一次迭代对 `out[out.length]` 赋值，Uint8Array 越界写静默丢弃，输出不变 | |
| 13 | encode.ts:131 | cond-lt `i < len` → `<=`（decodeWith） | `/** 通用 base64 家族解码（无 pad` | 同上：污染的 acc 产出的字节写入 `out[pos]`（pos 已达上限）被静默丢弃 | |
| 14 | encode.ts:12 | string STD_ALPHABET 追加 | `const B64URL_RE = /^[A-Z` | 追加在索引 ≥64 处，编码只用 0-63；解码表反向索引不受尾部影响；非法字符已被正则预检拒绝 | |
| 15 | encode.ts:13 | string B64U_ALPHABET 追加 | `/** 标准 base64 字母表(密钥材料,含` | 同上 | |

## 死代码信号（回溯 main 侧建议，依 D6 条款）

- `suite.ts` SUPPORTED 表的 `RSA3072/RSA4096` 项被 `SUITE_CACHE` 预注册短路（黑盒不可达，
  08-29 轮幸存体实证）；本轮采样未含该点，信号保留。建议经 PR 简化或加注释明示。

## 击杀资产说明

- 击杀资产 = vitest 全量套件（13 文件 177 测试，含 08-31 用户增补），不含 cucumber-js BDD（独立运行器）。
- 门禁：`npm run test:mutation`，击杀率 < 90% 时 exit 1；报告 `report.json` 落盘路径为相对路径（跨机器可移植）。
- 每轮结束 src 恢复完整性由脚本末尾字节校验保证。
