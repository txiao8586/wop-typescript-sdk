# 变异测试幸存体归档：15 个等价变异证明（2026-08-31 定局轮）

> 击杀率 94.27%（247/262，门禁 ≥90% 通过）。以下 15 个幸存体均为**黑盒行为等价**——
> 即不存在任何不改 src 语义的测试能区分它们（证明附后）。它们不是测试缺口，
> 而是（a）防御性冗余代码、（b）I7 模糊化纪律的固有代价、（c）环境等价、（d）语义保真分支。
>
> 历史轮次：08-29 第四轮 263/250/95.06%；08-31 定局轮在 main 侧 code-scanning 修复
> （commit cb51dbd，fromBase64 正则剥填充 → trimBase64Padding 线性扫描）与测试增补后重测。

| # | 位置 | 算子 | 锚 | 等价原因 |
|---|------|------|----|---------|
| 1 | client.ts:577 | cond-lt `dekIdx < 0` → `<= 0` | `if (dekIdx < 0)` | `dekIdx === 0` 不可达：进入该分支要求头以 `l2` 开头（`startsWith`），而 `indexOf('dek=') === 0` 要求头以 `dek=` 开头，二者互斥 | |
| 2 | `client.ts:546` | bool `sigOk = true` → `false` | `authString: `${protocolV` | 初值唯一读取点在 `rsaVerify` 返回后立即覆盖；rsaVerify 抛错路径经 catch 显式赋 `false`，两初值在所有路径终值一致 | |
| 3 | client.ts:479 | string `'parse'` category 追加 | `throw new WopError('响应缺少 x-wop-sign 头'` | `verifyResponse` 捕获 WopError 后仅外显 `e.message`；内部 category 无任何可观测通道（对外契约是 VerifyResult{ok,reason}） | |
| 4 | `client.ts:592` | string `'consistency'` category 追加 | `// 一律归入解密类模糊（I7 保守默认，int` | 同上 | |
| 5 | crypto.ts:146 | cond-lt `len < 16` → `<= 16` | `if (cipherTag.length < 1` | 16B 输入：短路路径抛 `DECRYPT_FAILED`；非短路走 WebCrypto GCM（空明文+16B tag）tag 校验失败同抛 `DECRYPT_FAILED`（I7 模糊化使两路径文案恒同）——**2026-10-19 已击杀**：空明文 GCM 往返（mutation-killers）证明 16B 合法 tag 原版解密成功、变异被拒 | |
| 6 | crypto.ts:146 | numeric `16` → `17` | `if (cipherTag.length < 1` | 15/16B 输入两路径同文案（同上）；17B+ 输入不受阈值影响——**2026-10-19 已击杀**（同上空明文往返） | |
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
## 2026-10-18 增量轮：26 个等价变异证明（src 演进 262→425 变异点，击杀率 93.88%）

> 背景：08-31 定局轮后 src 演进（RSA2048 套件表、L2 回程、crypto-provider、
> config 三件套），变异点 262→425，旧 report 陈旧致门禁假红（82.59%）。
> 本轮经 tests/mutation-killers.spec.ts 两轮增量击杀（cjp 负值包装消息、
> 套件表字段全等、url/serverRoot 校验消息、默认值、协议边界、家族表守卫）
> 74→37 幸存后，剩余 37 个逐个论证黑盒等价。行号以本轮 src 为准；
> 与 08-31 轮同名论证标注「移位」。编号保留原值不重排以维持历史可追溯。
>
> **2026-10-19 评审增补（Sourcery PR #49 + 异构对抗复审）**：击杀 11 条原判
> 等价实为可区分的变异——#5/#6/#29/#30（crypto 16B tag 阈值：空明文 GCM 往返；
> 旧表内联标注）、#39/#40（`\u` 4 位 hex 后 EOF 的可区分错误）、#41/#42
> （「未找到」消息全等断言——原「env 三元恒 false」论证错位：string 算子捕的
> 是恒被求值的消息字面量）、#47（loader 非显式竞态 category 全等）、#49-52
> （buildConfig 程序化路径的 `??` 默认值回退，原论证仅覆盖 JSON 加载路径）。
> 归档保留 26 条。report 口径：全量实测 396/425 后，loader.ts:102/140/144
> 三条经单点变异注入验证击杀后同步（399/425，93.88%）——夜间 mutation 巡检
> 将全量复核。

### A. 越界读 charCodeAt/索引 → NaN/undefined 行为一致（configJsonParser 手写解析）

判定基础：`pos < len` → `<=` 后多出的一轮迭代读到 `s[pos] === undefined`。
字符串比较（`=== '"'`、`=== closing` 等）对 undefined 恒 false；正则
`/\d/` 对 undefined 字符串化后的 'undefined' 不匹配。多消费的 pos 使
后续所有 `pos < length` 检查同样立即退出，循环退出后的 EOF 路径与原版
逐位一致，无任何消息差异。

| # | 位置 | 算子 | 锚 | 等价原因 |
|---|------|------|----|---------|
| 16 | configJsonParser.ts:158 | cond-lt | `while (this.pos < this.json.length)` | readString 主循环：undefined 不匹配 `"` 与 `\`，退出后照抛「字符串未闭合」 |
| 17 | configJsonParser.ts:229 | cond-lt | `while (this.pos < this.json.length && /\d/` | 数字扫描：`/\d/.test(undefined)` false，立即退出 |
| 18 | configJsonParser.ts:295 | cond-lt | `while (this.pos < this.json.length && /[a-zA-Z]/` | skipLiteral：`/[a-zA-Z]/` 虽匹配 'undefined'，但 pos 越界后下游边界检查全退出 |
| 19 | configJsonParser.ts:310 | cond-lt | `if (this.pos < this.json.length` | tryConsume：`undefined === ch` false，不误消费 |
| 20 | configJsonParser.ts:326 | cond-lt | `if (this.pos < this.json.length` | 尾随逗号检查：`undefined === closing` false，不误抛 |
| 21 | configJsonParser.ts:331 | cond-lt | `if (this.pos < this.json.length` | 闭括号消费：同上不误消费 |

### B. 08-31 轮已论证等价的移位与环境等价

| # | 位置 | 算子 | 锚 | 等价原因 |
|---|------|------|----|---------|
| 22 | client.ts:542 | string | `'parse',` | #3 移位：'parse' category 追加——verifyResponse 捕获后仅外显 message，category 无可观测通道（对外契约 VerifyResult{ok,reason}） |
| 23 | client.ts:578 | string | `throw new WopError('x-wop-encrypt 格式错误：L2 须携带 dek='` | #4 移位：本行被变异字面量是 'parse' category（消息字面量已被 :358 全等钉死）——catch 后仅外显 message，category 无可观测通道 |
| 24 | client.ts:552 | bool | `let sigOk = true;` | #2 移位：sigOk 初值唯一读取点立即覆盖 |
| 25 | client.ts:577 | cond-lt | `if (dekIdx < 0)` | #1 移位：dekIdx===0 不可达（l2 前缀与 dek=0 互斥） |
| 26 | client.ts:147 | numeric | `b[6] = (b[6]! & 0x0f)` | #8 同构：Node ≥19 `randomUUID` 快路径使该分支仅 stub 后可达；0x40→65 只翻转 bit0，version 高 nibble 恒 4 不变，确定区分需对 id[13] 做奇偶统计断言（概率性，不引入） |
| 27 | client.ts:148 | numeric | `b[8] = (b[8]! & 0x3f)` | 同上（0x80→129 只翻转 bit0，variant 高位不变） |
| 28 | crypto.ts:28 | stmt-del | `if (g?.subtle) return g;` | #8 移位：Node≥19 globalThis.crypto 与 webcrypto 同对象 |
| 31 | crypto.ts:146 | stmt-del | `if (cipherTag.length < 16)` | #7 移位：15B 输入走 WebCrypto 失败同文案；16B 空 tag 往返两版均走 WebCrypto 同结果（2026-10-19 复核成立） |
| 32 | encode.ts:70 | cond-gt | `if (end > 0 && s[end` | #9 移位：空串 s[-1]=undefined ≠ '\n'，换行探测无操作差异 |
| 33 | encode.ts:70 | stmt-del | `if (end > 0 && s[end` | #10 移位：换行探测语义保真（剥序不影响下游正则拒绝） |
| 34 | encode.ts:74 | cond-gt | `while (end > 0 && s[end` | #11 移位：end===0 时 s[-1]=undefined ≠ '='，循环立即退出 |
| 35 | encode.ts:93 | cond-lt | `for (let i = 0; i < out.length` | #12 移位：越界写 Uint8Array 静默丢弃 |
| 36 | encode.ts:138 | cond-lt | `for (let i = 0; i < len` | #13 移位：同上 |
| 37 | encode.ts:14 | string | `const STD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ` | #14 移位：字母表尾部追加，编码只用 0-63/解码正则预检拒绝 |
| 38 | encode.ts:16 | string | `const B64U_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ` | #15 移位：同上 |

### C. 结构性不可达（JSON 语法/显式语义保证）

原 #39/#40（configJsonParser.ts:203 `\u` 边界）与 #41/#42（loader.ts:140/144
「未找到」消息字面量）已移出归档：前者在「4 位 hex 后即 EOF」输入下产生可区分
错误消息，后者恒被求值且可全等断言——均于 2026-10-19 由评审增补测试击杀。

### D. 环境等价与防御性冗余

| # | 位置 | 算子 | 锚 | 等价原因 |
|---|------|------|----|---------|
| 43 | client.ts:131 | cond-lt | `while (start < end && isWs(s.charCodeAt(start)))` | trim 双指针：end===start 时 s[-1]=undefined，charCodeAt→NaN，isWs(NaN) false 立即退环（08-31 #9 同构） |
| 44 | client.ts:132 | cond-gt | `while (end > start && isWs(s.charCodeAt(end - 1)))` | 同上对称端 |
| 45 | loader.ts:113 | neq | `if (typeof __dirname !== 'undefined')` | 反转仅在纯 ESM 运行时可观测；vitest 运行时 __dirname 由 vite CJS 兼容层注入且与 import.meta 指向同目录，两分支返回值相同 |
| 46 | loader.ts:113 | string | `if (typeof __dirname !== 'undefined')` | 'undefined'@mut 使条件恒真 → 恒走 __dirname 分支 → vitest 下与原版同返回值 |
| 48 | configValidator.ts:36 | stmt-del | `void suite;` | `void suite;` 为纯标记语句（表明已校验），无任何可观测副作用 |

### 死代码信号（回溯 main 侧建议，依 D6 条款）

- configValidator 默认值双写（parse 层 + validator `??` 层）建议归一单层（#49-52 已于 2026-10-19 由 buildConfig 程序化路径测试击杀钉住，双写不再是逃逸口）。
- loader.ts:140/144 的 env 名三元在 explicit 语义下恒 false，建议并入显式错误消息或删除。
- client.ts:131 randomUUID 快路径使 136/137 回退分支在 Node 下不可达——浏览器目标仍需该分支，建议加注释明示。

### 击杀资产说明（本轮）

- 击杀资产 = vitest 全量套件（13 文件，含 mutation-killers.spec.ts 本轮增量用例）。
- 本轮补杀：cjp:110/117/238（负值触发 fieldName 包装消息）、url:58、configValidator:41、suite:34（RSA2048 十字段全等）、suite:102（家族表守卫消息全等）；单点注入验证均已闭环。
