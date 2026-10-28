# 商户使用场景 × 测试用例矩阵（wop-typescript-sdk）

> 依据：`wop-specs/sdk/wop-sdk-spec.md`（v1.0-ratified + 附录 D1–D5）F1–F9、概念 API（§2）与网关定位（§1）。
> 视角：**商户接入方**——从"我拿到 appKey 和两把密钥之后要做什么 / 什么会做错 / 会被怎样攻击"出发。
> 落点：`已有` = 既有 spec 文件；`新增` = 本次质量闭环新增（hardening.spec.ts / features/*.feature）。

## 一、场景 → 用例矩阵

| # | 商户使用场景 | spec 依据 | 期望行为 | 落点 |
|---|---|---|---|---|
| S1 | 首次接入：appKey + RSA3072 套件 + PKCS8 私钥 + SPKI 公钥初始化客户端 | F1 / §2 / D12 | 构造成功，套件四维推导正确 | 已有 suite.spec / client.spec；Gherkin #1 |
| S2 | 误配国密套件 WOP-SM2-SM3（看文档以为支持） | F1 / Q7 / §1.2 | 明确 unsupported「暂未支持」+ 指向 README 路线图 | 已有 suite.spec；Gherkin #2 |
| S3 | 误配跨族/非法套件（WOP-RSA3072-SM3、WOP-RSA2048-SHA256、非三段式） | F1 / I5 | parse/unsupported 明确拒绝（构造即抛） | 已有 suite.spec；Gherkin #3 |
| S4 | 发起 L0 明文写请求（下单/转账），自带 HTTP 栈直接消费 RequestDraft | F2/F3/F4/F9 / Q1 | 5 段 canonical、digest 必入签、网关公钥可验签 | 已有 client.spec L0 + 互操作闭环；Gherkin #4 |
| S5 | 发起 GET 查询（无 body） | F4 / D2 / I1 | digest 头缺席、signedHeaders 不含 digest | 已有 client.spec；Gherkin #5 |
| S6 | 发起 L2 敏感数据请求（身份证/手机号全文加密） | F5 / §6 | wireBody={"encrypted":…}、encrypt 头入签、网关可解包回环 | 已有 client.spec L2；Gherkin #6 |
| S7 | 校验网关同步 L0 响应 | F6 / I2 | 验签→digest 复核全过，plaintext==body | 已有 client.spec；Gherkin #7 |
| S8 | 校验网关同步 L2 响应 | F6 / I3 / D8 | DEK 解包→alg 族比对→bulk 解密，得明文 | 已有 client.spec；Gherkin #8 |
| S9 | 响应被中间人篡改：签名段 / body（digest） / DEK 载荷 / GCM tag | F6 / I2/I3/I7 | 顺序固定（先验签）；密钥参与失败一律模糊文案 | 已有 client.spec tamper 系列；Gherkin #9–#11 |
| S10 | 收到平台异步回调通知（完整 URL / 纯 path 两种传法） | F6 / §2 | URL 取 pathname 入 canonical；path 不符即验签失败 | 已有 client.spec callback；Gherkin #12–#13 |
| S11 | 网络抖动重试：同参数重复构造请求 | §2 确定性 | 同输入同输出（注入 timestamp/nonce/dek/iv 后全等）；默认 CSPRNG 两次不同 | 已有 client.spec 幂等；Gherkin #14 |
| S12 | 恶意/失控网关返回超大响应体 | D4 | 流式计数 11MiB 上限，越限即断流抛协议类错误 | 已有 transport.spec；Gherkin #15 |
| S13 | send() 便利编排：带/不带签名响应、非 2xx | §2 / Q1 | 有 x-wop-sign 自动 F6 校验；无签名按状态码定 ok | 已有 transport.spec send 系列 |
| S14 | 密钥材料各种形态：PEM 多行 / 单行 base64 / base64url / 损坏 | D12 | 剥离 PEM+空白后 DER 解析；非法/过短 fail-fast | 已有 keys.spec / edge.spec |
| S15 | 黄金向量自测（签名/OAEP/AES-GCM/digest/DEK/formatRules） | F8 / A1 / A2 / D1 | 字节级一致；tamper/跨族/错长度/尾随位全部拒 | 已有 vectors/encode/digest/interop.spec |
| S16 | 平台公钥材料损坏但恰好通过长度校验（运行时才暴露） | F6 / I7 | rsaVerify 异常被吞为模糊「签名验证失败」，不泄露内部细节 | **新增 hardening.spec（行覆盖缺口 326-327）** |
| S17 | L2 响应信封畸形：缺 dek=、encrypted 带 `=`、body 非 JSON、缺 encrypted 字段、载荷无 `$` | F5/F6/F7 / n06/n13 | 结构类明确 parse 拒绝；密钥参与类模糊 | 已有 edge.spec / client.spec |
| S18 | SM 段向量在场但不消费 | §1.2 / Q7 | SM 套件必须拒（负测试锚：SM4 16B key 走 AES 入口必炸） | 已有 vectors.spec |
| S19 | ISV 代子商户调用业务 API（D-13） | ISV D-13 / AC-20 | `subMchId` 写入 `x-wop-sub-mch-id` 且自动入 signedHeaders；不传 = 头缺席、签名逐字节不变 | 已有 client.spec 子商户头 describe；mutation-killers 文案/边界 |

## 二、攻击者视角补充（负路径）

| # | 攻击/误用 | 期望 | 落点 |
|---|---|---|---|
| A1 | 重放旧签名（expiredSeconds 窗口外） | 网关侧拒绝（SDK 组装 authString 供网关校验，F9） | client.spec 头结构断言 |
| A2 | 篡改 wire body 但保留旧 digest | 明确「摘要不匹配」（完整性类，非模糊） | client.spec / Gherkin #10 |
| A3 | 伪造签名头（换密钥/改字节） | 模糊「签名验证失败」，不区分原因（I7 防 oracle） | client.spec / Gherkin #9 |
| A4 | base64url 尾随位非规范 / 带 `=` | 严格拒绝（D1，对齐 Go RawURLEncoding.Strict()） | encode.spec formatRules 全量 |
| A5 | 响应头大小写混淆 | 小写化归一后校验 | client.spec 大小写不敏感 |
| A6 | 声明了不存在的 signedHeader | 明确 parse 拒绝 | client.spec |
| A7 | 子商户头注入/歧义：CR/LF/控制字符、非 ASCII、内部空格、超长 | configuration 明确拒绝（原值扫描先于 trim） | client.spec 子商户头 describe；mutation-killers 文案/边界 |

## 三、Gherkin 场景（cucumber-js，tests/features/merchant-journey.feature）

| Gherkin | 对应矩阵 | 场景名 |
|---|---|---|
| #1 | S1 | 商户以合法配置初始化客户端 |
| #2 | S2 | 商户误配国密套件得到明确的暂未支持 |
| #3 | S3 | 商户误配跨族套件被明确拒绝 |
| #4 | S4 | 商户发起 L0 订单创建请求且网关可验签 |
| #5 | S5 | 商户发起无 body 查询请求时摘要头缺席 |
| #6 | S6 | 商户发起 L2 敏感数据请求且网关可解密回文 |
| #7 | S7 | 商户校验 L0 同步响应 |
| #8 | S8 | 商户校验 L2 同步响应得到明文 |
| #9 | A3/S9 | 响应签名被篡改时得到模糊失败 |
| #10 | A2/S9 | 响应 body 被篡改时得到明确的摘要不匹配 |
| #11 | S9 | L2 响应 DEK 被篡改时得到模糊解密失败 |
| #12 | S10 | 商户以完整 URL 校验异步回调 |
| #13 | S10 | 回调 path 与签名不符时校验失败 |
| #14 | S11 | 同参数重放构造请求得到全等结果 |
| #15 | S12 | 响应体超过 11MiB 上限时断流拒绝 |

## 四、覆盖与变异闭环（2026-08-31 定局轮）

- 行/分支/函数/语句覆盖率：**100% / 100% / 100% / 100%**（vitest coverage-v8）。
  08-29 修复缺口：`src/client.ts:326-327`（rsaVerify 异常 catch → 模糊验签失败，I7）→ tests/hardening.spec.ts。
- 变异测试：`npm run test:mutation`（tests/mutation/run-mutations.mjs），**12 类算子**，262 个变异体，
  击杀 247，**击杀率 94.27%**（门禁 ≥90%）；15 个幸存体均为黑盒等价，证明见
  `tests/mutation/EQUIVALENT-MUTANTS.md`（含 08-31 main 侧 code-scanning 修复 cb51dbd 后的
  `trimBase64Padding` 新等价体）。
- Gherkin：`npm run test:bdd`（cucumber-js），15 场景 49 步全过。
- 测试资产：177 vitest 测试（13 文件；08-31 含用户增补 3 个）+ 15 Gherkin 场景。
- 断言纪律：全仓遵循 wop-sdk-spec 附录 **D6**（协议类消息全等 / 密钥参与类固定模糊文案 /
  category 显式断言 / 幸存体逐个举证）。
