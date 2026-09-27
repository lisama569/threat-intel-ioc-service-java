# 本地威胁情报 IOC 服务

基于 Spring Boot 的本地 IOC（Indicator of Compromise）接入、聚合与命中判定服务。
用内存假数据源模拟多个外部情报源，重复上报、来源冲突、情报过期时的判定结果完全可预期、可复现。

## 情报字段

接入接口 `POST /api/iocs`，请求体为 `RawIocReport`：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `source` | string | 是 | 来源标识，决定权重（见下） |
| `type` | string | 是 | `domain` / `ip` / `cidr` / `url` / `hash`（含别名 `ipv4`、`network`、`md5`、`sha1`、`sha256`），大小写不敏感 |
| `value` | string | 是 | IOC 原始值，容忍大小写、协议前缀、路径等形态差异 |
| `verdict` | string | 是 | `MALICIOUS` / `SUSPICIOUS` / `BENIGN` / `WHITELISTED`，大小写不敏感 |
| `confidence` | double | 是 | 来源自报置信度，范围 [0,1] |
| `ttlSeconds` | long | 是 | 存活时间（秒），必须为正；到期后不再参与命中 |
| `reportedAt` | instant | 否 | 上报时间，缺省取服务端当前时间 |

## 归一化规则

同一个 IOC 的不同形态会归并到同一条情报（`IocNormalizer`）：

- **域名**：统一小写、去末尾点；容忍 `http://`、端口、路径（`HTTP://Example.COM:8080/a` → `DOMAIN:example.com`）；校验标签合法性（字母数字+连字符、TLD 为纯字母）。
- **URL**：提取 host，host 是 IP 则折叠为 IP，否则折叠为域名。
- **IP**：仅支持 IPv4 点分十进制，逐段校验 0-255，拒绝前导零。
- **CIDR**：归并到网络地址（`10.0.3.7/24` → `CIDR:10.0.3.0/24`）；`/32` 单地址折叠为 IP。
- **哈希**：统一小写，仅接受 32/40/64 位十六进制（MD5/SHA1/SHA256）。

字段缺失或格式错误**不会静默跳过**，返回可区分的拒绝原因（`RejectReason`）：
`MISSING_SOURCE` / `MISSING_TYPE` / `MISSING_VALUE` / `MISSING_VERDICT` /
`UNKNOWN_TYPE` / `UNKNOWN_VERDICT` / `INVALID_VALUE_FORMAT` / `INVALID_CONFIDENCE` / `INVALID_TTL`。
被拒收的情报会留档，后续命中查询返回 `REJECTED` 及原始拒绝原因，与“未命中”明确区分。

## 置信度聚合与生命周期

- 单次上报有效置信度 = `confidence × 来源权重 × 0.5^(age / halfLife)`（`ioc.half-life-seconds`，默认 86400）。
- 同一 IOC 多次上报按独立证据合并：`1 - Π(1 - effective_i)`。
- 过期上报（`now >= reportedAt + ttlSeconds`）不参与聚合与仲裁；全部过期后记录状态为 `EXPIRED`。
- 内置假数据源权重：`commercial-feed=0.9`、`community-feed=0.6`、`honeypot=0.5`、`internal-whitelist=1.0`，未注册来源默认 0.3；`SourceRegistry.setWeight` 可在线调整。

## 冲突仲裁策略（确定性，按序适用）

1. 过期上报不参与仲裁。
2. 存在来源权重 ≥ `ioc.whitelist-weight-threshold`（默认 0.8）的 `WHITELISTED` 上报 → 结论 `WHITELISTED`（可信白名单优先，防误杀）。
3. 否则按结论分组累计有效置信度，得分最高者胜。
4. 并列时按严重度：`MALICIOUS > SUSPICIOUS > BENIGN > WHITELISTED`。

权重或规则参数调整后，对相同历史输入重算必然复现相同结论（测试注入固定 `Clock` 验证）。

## 命中判定

`GET /api/iocs/hit?type=...&value=...`，结果 `HitStatus` 彼此可区分：

| 状态 | 含义 |
|---|---|
| `HIT` | 活跃记录，结论为 MALICIOUS/SUSPICIOUS 且聚合置信度 ≥ `ioc.hit-confidence-threshold`（默认 0.5） |
| `MISS` | 从未见过，或已知但非威胁/置信度不足（后者附带记录详情） |
| `EXPIRED` | 存在记录但全部上报已过期 |
| `DELETED` | 已逻辑删除（墓碑，`DELETE /api/iocs?type=...&value=...`） |
| `REJECTED` | 该值历史上被规范化拒收，附带拒绝原因 |

## 并发模型

每个 IOC 一个存储条目，增删改在条目监视器锁内完成，对外只暴露不可变快照
（`StoreEntryView` / `IocRecord`），并发上报、删除、查询不会读到更新一半的中间态，计数不丢失。

## 本地验证

```bash
# 全部测试（归一化、冲突仲裁、重复上报、过期、并发）
mvn test

# 启动服务（application.properties 中 server.port=0 表示随机端口，可改为固定端口）
mvn spring-boot:run

# 示例：接入与命中
curl -X POST localhost:8080/api/iocs -H 'Content-Type: application/json' -d '{
  "source":"commercial-feed","type":"url","value":"HTTP://Evil.COM:8080/payload",
  "verdict":"MALICIOUS","confidence":0.9,"ttlSeconds":86400}'
curl 'localhost:8080/api/iocs/hit?type=domain&value=evil.com'
```

单测日志会打印原始输入与归一化后的判定依据（归一化键、拒绝原因、仲裁结论、聚合置信度）。
