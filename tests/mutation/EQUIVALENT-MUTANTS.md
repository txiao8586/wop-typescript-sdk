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
## 2026-10-18 增量轮：37 个等价变异证明（src 演进 262→425 变异点，击杀率 91.29%）

> 背景：08-31 定局轮后 src 演进（RSA2048 套件表、L2 回程、crypto-provider、
> config 三件套），变异点 262→425，旧 report 陈旧致门禁假红（82.59%）。
> 本轮经 tests/mutation-killers.spec.ts 两轮增量击杀（cjp 负值包装消息、
> 套件表字段全等、url/serverRoot 校验消息、默认值、协议边界、家族表守卫）
> 74→37 幸存后，剩余 37 个逐个论证黑盒等价。行号以本轮 src 为准；
> 与 08-31 轮同名论证标注「移位」。报告见 tests/mutation/report.json（388/425）。

### A. 越界读 charCodeAt/索引 → NaN/undefined 行为一致（configJsonParser 手写解析）

判定基础：`pos < len` → `<=` 后多出的一轮迭代读到 `s[pos] === undefined`。
字符串比较（`=== '"'`、`=== closing` 等）对 undefined 恒 false；正则
`/\d/` 对 undefined 字符串化后的 'undefined' 不匹配。多消费的 pos 使
后续所有 `pos < length` 检查同样立即退出，循环退出后的 EOF 路径与原版
逐位一致，无任何消息差异。

| # | 位置 | 算子 | 等价原因 |
|---|------|------|---------|
| 16 | configJsonParser.ts:158 | cond-lt | readString 主循环：undefined 不匹配 `"` 与 `\`，退出后照抛「字符串未闭合」 |
| 17 | configJsonParser.ts:229 | cond-lt | 数字扫描：`/\d/.test(undefined)` false，立即退出 |
| 18 | configJsonParser.ts:295 | cond-lt | skipLiteral：`/[a-zA-Z]/` 虽匹配 'undefined'，但 pos 越界后下游边界检查全退出 |
| 19 | configJsonParser.ts:310 | cond-lt | tryConsume：`undefined === ch` false，不误消费 |
| 20 | configJsonParser.ts:326 | cond-lt | 尾随逗号检查：`undefined === closing` false，不误抛 |
| 21 | configJsonParser.ts:331 | cond-lt | 闭括号消费：同上不误消费 |

### B. 08-31 轮已论证等价的移位与环境等价

| # | 位置 | 算子 | 等价原因 |
|---|------|------|---------|
| 22 | client.ts:498 | string | #3 移位：'parse' category 追加——verifyResponse 捕获后仅外显 message，category 无可观测通道（对外契约 VerifyResult{ok,reason}） |
| 23 | client.ts:534 | string | #4 移位：'consistency' category 追加——同上（I7 保守默认归入解密模糊） |
| 24 | client.ts:508 | bool | #2 移位：sigOk 初值唯一读取点立即覆盖 |
| 25 | client.ts:533 | cond-lt | #1 移位：dekIdx===0 不可达（l2 前缀与 dek=0 互斥） |
| 26 | client.ts:136 | numeric | #8 同构：Node ≥19 `randomUUID` 快路径短路（client.ts:131），手写 v4 位构造为回退分支，vitest/Node 下不可达 |
| 27 | client.ts:137 | numeric | 同上（variant 位 0x80） |
| 28 | crypto.ts:28 | stmt-del | #8 移位：Node≥19 globalThis.crypto 与 webcrypto 同对象 |
| 29 | crypto.ts:146 | cond-lt | #5 移位：16B 输入两路径同文案（I7 模糊化） |
| 30 | crypto.ts:146 | numeric | #6 移位：15/16B 输入两路径同文案 |
| 31 | crypto.ts:146 | stmt-del | #7 移位：15B 输入走 WebCrypto 失败同文案 |
| 32 | encode.ts:70 | cond-gt | #9 移位：空串 s[-1]=undefined ≠ '\n'，换行探测无操作差异 |
| 33 | encode.ts:70 | stmt-del | #10 移位：换行探测语义保真（剥序不影响下游正则拒绝） |
| 34 | encode.ts:74 | cond-gt | #11 移位：end===0 时 s[-1]=undefined ≠ '='，循环立即退出 |
| 35 | encode.ts:93 | cond-lt | #12 移位：越界写 Uint8Array 静默丢弃 |
| 36 | encode.ts:138 | cond-lt | #13 移位：同上 |
| 37 | encode.ts:14 | string | #14 移位：字母表尾部追加，编码只用 0-63/解码正则预检拒绝 |
| 38 | encode.ts:16 | string | #15 移位：同上 |

### C. 结构性不可达（JSON 语法/显式语义保证）

| # | 位置 | 算子 | 等价原因 |
|---|------|------|---------|
| 39 | configJsonParser.ts:203 | cond-gt | `\u` 转义起点 pos 后按 JSON 语法至少存在 4 个 hex + 闭合 `"` + 闭合 `}`（≥6 字符），`pos+4 > len` 与 `pos+4 >= len` 均恒 false，分支不可达 |
| 40 | configJsonParser.ts:203 | numeric 4→5 | 同上几何：`\u` 后至少 6 字符使 `pos+5 > len` 恒 false |
| 41 | loader.ts:140 | string | 「未找到配置文件」消息组装仅在两个 env 均未设时到达（loader.ts:51-62：任一 env 已设即 explicit=true，读失败走「显式配置文件不可读」直接抛）；该行 env 名三元恒 false，@mut 追加不求值 |
| 42 | loader.ts:144 | string | 同上（CONFIG_FILE_ENV 同为 explicit 语义） |

### D. 环境等价与防御性冗余

| # | 位置 | 算子 | 等价原因 |
|---|------|------|---------|
| 43 | client.ts:120 | cond-lt | trim 双指针：end===start 时 s[-1]=undefined，charCodeAt→NaN，isWs(NaN) false 立即退环（08-31 #9 同构） |
| 44 | client.ts:121 | cond-gt | 同上对称端 |
| 45 | loader.ts:113 | neq | 反转仅在纯 ESM 运行时可观测；vitest 运行时 __dirname 由 vite CJS 兼容层注入且与 import.meta 指向同目录，两分支返回值相同 |
| 46 | loader.ts:113 | string | 'undefined'@mut 使条件恒真 → 恒走 __dirname 分支 → vitest 下与原版同返回值 |
| 47 | loader.ts:102 | string | 非显式「配置文件不可读」分支：触发需 existsSync 通过后 accessSync 失败——文件系统权限竞态窗口，测试无法稳定构造（防御性双检查） |
| 48 | configValidator.ts:36 | stmt-del | `void suite;` 为纯标记语句（表明已校验），无任何可观测副作用 |
| 49 | configValidator.ts:68 | numeric | expiredSeconds `?? 1800` 右侧死代码：parseConfigJson 层已填默认（默认值用例走全链断言通过，?? 右侧不可达） |
| 50 | configValidator.ts:70 | numeric | httpClient `?? {connectTimeout: 10_000}` 同上 |
| 51 | configValidator.ts:71 | numeric | readTimeout 30_000 同上 |
| 52 | configValidator.ts:72 | numeric | maxRetryCount 3 同上 |

### 死代码信号（回溯 main 侧建议，依 D6 条款）

- configValidator 默认值双写（parse 层 + validator `??` 层）建议归一单层，消除 #49-52 类伪幸存。
- loader.ts:140/144 的 env 名三元在 explicit 语义下恒 false，建议并入显式错误消息或删除。
- client.ts:131 randomUUID 快路径使 136/137 回退分支在 Node 下不可达——浏览器目标仍需该分支，建议加注释明示。

### 击杀资产说明（本轮）

- 击杀资产 = vitest 全量套件（13 文件，含 mutation-killers.spec.ts 本轮增量用例）。
- 本轮补杀：cjp:110/117/238（负值触发 fieldName 包装消息）、url:58、configValidator:41、suite:34（RSA2048 十字段全等）、suite:102（家族表守卫消息全等）；单点注入验证均已闭环。
