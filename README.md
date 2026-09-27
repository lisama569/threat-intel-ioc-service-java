# 本地威胁情报 IOC 服务

基于内存假数据源模拟多个外部情报源，提供 IOC 的接入、归一化、聚合与命中判定。
重复上报、来源冲突、情报过期时的判定结果均可预期、可复现。

## 情报字段

上报接口 `POST /api/ioc/ingest`，请求体 `IocReport`：

| 字段 | 类型 | 说明 |
|---|---|---|
| `sourceId` | string | 来源 ID，必须已注册（预置 `feed-alpha` 0.9 / `feed-beta` 0.6 / `feed-gamma` 0.3） |
| `type` | string | `DOMAIN` / `IP` / `URL` / `HASH`（大小写不敏感） |
| `rawValue` | string | 原始 IOC 值，允许各来源的不同形态 |
| `verdict` | enum | `MALICIOUS` / `SUSPICIOUS` / `BENIGN` |
| `confidence` | double | 来源自报置信度，取值 [0,1] |
| `reportedAtEpochMs` | long | 上报时间（epoch 毫秒） |
| `ttlSeconds` | long | 生存期（秒），必须为正数；到期即过期 |

字段缺失、类型未知、格式非法、置信度越界、TTL 非正、来源未注册都会被**拒收**，
并返回可区分的 `RejectReason`：`MISSING_FIELD`、`UNKNOWN_TYPE`、`UNKNOWN_SOURCE`、
`INVALID_DOMAIN`、`INVALID_IP`、`INVALID_URL`、`INVALID_HASH`、`INVALID_CONFIDENCE`、`INVALID_TTL`。

## 归一化规则

同一 IOC 的不同上报形态归并为同一条情报（键为 `TYPE:normalizedValue`）：

- **DOMAIN**：去协议前缀（`https://`）、去路径与端口、小写化、去结尾点；
  校验标签长度与字符集，最后一段不能全数字（避免把 IP 当域名）。
  例：`Evil.Example.COM.`、`https://Evil.Example.com/x`、`evil.example.com:8080/`
  → `DOMAIN:evil.example.com`
- **IP**：仅 IPv4；八位组 0-255，去前导零；`/32` CIDR 归并为单 IP（其它前缀拒绝）。
  例：`10.0.0.1/32`、`010.0.0.1` → `IP:10.0.0.1`
- **URL**：scheme/host 小写、去默认端口（80/443）、去 fragment、空路径归一为 `/`。
  例：`HTTP://Evil.Example.COM:80/a#f` → `URL:http://evil.example.com/a`
- **HASH**：小写 hex，长度须为 32(MD5)/40(SHA1)/64(SHA256)。

查询侧（`GET /api/ioc/lookup`）与上报侧使用**同一套**归一化规则。

## 置信度衰减与冲突仲裁

- 同一来源对同一 IOC 重复上报时只保留**最新一条**（按来源 upsert）。
- 每条上报受理时**固化当时的来源权重**，之后调整权重不影响历史判定（可复现）。
- 有效置信度随时间线性衰减：
  `effective = confidence × sourceWeight × (1 - age/ttl)`，过期（`now ≥ reportedAt + ttl`）后为 0，
  过期情报不参与命中判定。
- 冲突仲裁（`ConflictResolver`）：只统计未过期上报，按结论分组对有效置信度求和，
  总分最高者胜出；平分按固定优先级 `MALICIOUS > SUSPICIOUS > BENIGN` 打破；
  聚合置信度为胜方总分，封顶 1.0。规则完全确定，同样输入必得同样结论。

## 命中判定状态

`GET /api/ioc/lookup?type=...&value=...` 返回 `HitResult`，`status` 可明确区分：

| 状态 | 含义 |
|---|---|
| `HIT` | 命中，附 `verdict`、聚合 `confidence` 与逐条判定依据 `basis` |
| `MISS` | 从未见过该 IOC |
| `REJECTED` | 查询值本身非法，或该 IOC 的上报曾被拒收（附拒收原因） |
| `DELETED` | 曾存在但已被删除（删除留下墓碑） |
| `EXPIRED` | 曾存在但全部上报已过期 |

## 并发语义

- 存储层写操作（上报/删除）串行化，聚合体内部读写分离锁；
  并发上报不会出现计数丢失，并发删除只有一个胜者。
- 查询读取一致性快照，不会看到只更新一半的状态。

## 本地验证

```bash
# 全部测试（归一化 / 冲突 / 重复上报 / 过期 / 并发，日志打印原始输入与判定依据）
mvn test

# 只看某类场景
mvn test -Dtest=IocNormalizerTests
mvn test -Dtest=IocServiceTests
mvn test -Dtest=IocConcurrencyTests

# 启动服务并手工验证
mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8080

curl -X POST localhost:8080/api/ioc/ingest -H 'Content-Type: application/json' -d '{
  "sourceId":"feed-alpha","type":"domain","rawValue":"Evil.Example.COM.",
  "verdict":"MALICIOUS","confidence":0.9,"reportedAtEpochMs":'"$(date +%s)000"',"ttlSeconds":3600}'

curl "localhost:8080/api/ioc/lookup?type=domain&value=https://EVIL.example.COM/x"
curl -X DELETE "localhost:8080/api/ioc?type=domain&value=evil.example.com"
```
