# 交通数据可信验证后端交接说明

本文档用于项目交接，说明当前后端已经完成的接口能力、兼容接口、运行方式，以及后续成员需要继续完善的功能边界。

## 1. 项目概览

本项目是交通数据跨链可信验证后端，当前服务基于 Spring Boot 2.7.x，默认启动端口为 `8088`，主启动类为：

```text
com.traffic.wecross.crossverification.CrossVerificationApplication
```

当前代码同时保留了两套接口路径：

| 接口路径 | 用途 | 状态 |
| --- | --- | --- |
| `/api/cross-verification/*` | 新版可信验证接口，供新版前端模块使用 | 已实现基础可用能力 |
| `/api/verification/*` | 旧版前端兼容接口 | 已恢复兼容适配，不建议删除 |

新版接口下已经拆分为三类独立验证能力：

- 数据完整性验证：Merkle-SHA256
- 隐私证明验证：Groth16 接口适配
- 多方签名验证：Threshold-Signature 接口适配

三类验证都会生成统一的验证记录，并可按需尝试同步可信账本。

## 2. 本地运行

### 2.1 环境要求

- JDK 8+
- Maven 3.x
- 默认服务端口：`8088`
- WeCross Router 默认地址：`http://127.0.0.1:8250`

### 2.2 编译

```powershell
mvn -q -DskipTests compile
```

### 2.3 启动

```powershell
mvn -q spring-boot:run
```

启动后可先访问健康检查：

```http
GET http://127.0.0.1:8088/api/cross-verification/health
```

预期返回：

```json
{
  "status": "UP",
  "service": "transportation-cross-verification-service",
  "apiPrefix": "/api/cross-verification"
}
```

## 3. 已完成的新版接口

### 3.1 健康检查

```http
GET /api/cross-verification/health
```

用途：确认服务是否启动，以及新版 API 前缀是否可访问。

### 3.2 Merkle 数据完整性验证

```http
POST /api/cross-verification/merkle/verify
Content-Type: application/json
```

请求示例：

```json
{
  "businessId": "traffic-batch-001",
  "dataSourceName": "vehicle-speed-records",
  "leafItems": ["record-1", "record-2", "record-3"],
  "expectedRoot": "",
  "sampleIndex": 1,
  "writeLedger": false,
  "ledgerTargets": []
}
```

已完成能力：

- 对 `leafItems` 每一项计算 SHA-256 叶子哈希。
- 构建 Merkle 树，奇数节点时复制最后一个节点参与下一层计算。
- 返回根哈希 `resultHash` / `detail.rootHash`。
- 如果传入 `expectedRoot`，会与计算得到的根哈希比较，返回 `PASS` 或 `FAIL`。
- 如果传入 `sampleIndex`，返回对应叶子哈希和 `proofPath`。
- 生成统一验证记录，可通过记录接口查询。
- 支持 `writeLedger=true` 时进入可信账本同步流程。

主要校验规则：

- `businessId` 必填。
- `leafItems` 必填且不能为空。
- `sampleIndex` 必须在叶子数组范围内。
- `expectedRoot` 如果传入，必须是 64 位十六进制 SHA-256 字符串。

### 3.3 Groth16 隐私证明验证

```http
POST /api/cross-verification/zkp/verify
Content-Type: application/json
```

请求示例：

```json
{
  "businessId": "traffic-proof-001",
  "circuitId": "traffic-speed-range-v1",
  "proof": {
    "piA": "0xabc",
    "piB": "0xdef",
    "piC": "0x123"
  },
  "publicSignals": {
    "batchCommitment": "0x9f01"
  },
  "publicInputHash": "",
  "writeLedger": false,
  "ledgerTargets": []
}
```

已完成能力：

- 接收 Groth16 证明结构、公开信号、公开输入哈希。
- 如果未传 `publicInputHash`，会根据 `publicSignals` 计算输入哈希。
- 对 `proof` 计算 `proofHash`，返回摘要信息而不是直接回显完整证明。
- 检查 `proof` 中是否包含 `piA`、`piB`、`piC`。
- 支持通过 `proof.valid=false` 模拟验证失败。
- 生成统一验证记录，可通过记录接口查询。
- 支持 `writeLedger=true` 时进入可信账本同步流程。

当前边界：

- 目前 `Groth16ProofVerifier` 是可替换的适配器，主要做结构和字段检查。
- 尚未接入真正的 Groth16 配对密码学验证逻辑。

主要校验规则：

- `businessId` 必填。
- `circuitId` 必填。
- `proof` 或 `publicSignals` 至少有一个包含可验证内容。
- `publicInputHash` 如果传入，必须是 64 位十六进制 SHA-256 字符串。

### 3.4 多方门限签名验证

```http
POST /api/cross-verification/threshold-signature/verify
Content-Type: application/json
```

请求示例：

```json
{
  "businessId": "multi-party-confirm-001",
  "message": "traffic-batch-001 approved",
  "threshold": 3,
  "totalNodes": 5,
  "participantIds": [1, 2, 4],
  "signatureBundle": {
    "aggregateSignature": "0xabc123",
    "valid": true
  },
  "writeLedger": false,
  "ledgerTargets": []
}
```

已完成能力：

- 校验门限参数、节点总数和参与方列表。
- 计算 `messageHash`、`participantSetHash`、`signatureHash`。
- 支持三种签名证据形态：
  - `participantSignatures`
  - `signatures`
  - `aggregateSignature` 或 `signature`
- 支持通过 `signatureBundle.valid=false` 模拟验证失败。
- 生成统一验证记录，可通过记录接口查询。
- 支持 `writeLedger=true` 时进入可信账本同步流程。

当前边界：

- 目前 `ThresholdSignatureVerifier` 是可替换的适配器，主要检查签名证据是否满足门限数量和字段形态。
- 尚未接入真实的门限签名密码学验签库。

主要校验规则：

- `businessId` 必填。
- `message` 必填。
- `threshold > 0`。
- `totalNodes > 0`。
- `threshold <= totalNodes`。
- `participantIds` 必填，数量必须大于等于 `threshold`。
- `participantIds` 不允许重复，每个 ID 必须在 `1..totalNodes` 范围内。
- `signatureBundle` 必填且不能为空。

### 3.5 验证记录查询

```http
GET /api/cross-verification/records
```

支持查询参数：

| 参数 | 说明 |
| --- | --- |
| `verifyType` | 可选，`MERKLE` / `ZKP` / `THRESHOLD_SIGNATURE` |
| `businessId` | 可选，业务编号 |
| `status` | 可选，`PASS` / `FAIL` / `ERROR` |
| `page` | 可选，默认 `1` |
| `size` | 可选，默认 `10`，最大按代码限制为 `100` |

详情查询：

```http
GET /api/cross-verification/records/{recordId}
```

已完成能力：

- 三类验证都会写入统一记录服务。
- 支持按类型、业务编号、状态分页筛选。
- 详情接口返回列表字段、输入哈希、证明哈希、验证详情、账本同步状态和原始结果。
- 记录不存在时返回 HTTP `404`。

当前边界：

- 当前记录存储是内存 `ConcurrentHashMap`，服务重启后记录会丢失。
- 尚未接入数据库、文件存储或可信账本反查。

## 4. 统一返回结构

新版验证接口统一返回 `VerificationResult`：

| 字段 | 说明 |
| --- | --- |
| `recordId` | 验证记录编号 |
| `verifyType` | 验证类型 |
| `verifyName` | 验证名称 |
| `businessId` | 业务编号 |
| `algorithm` | 算法名称 |
| `status` | `PASS` / `FAIL` / `ERROR` |
| `message` | 结果说明 |
| `inputHash` | 输入摘要 |
| `proofHash` | 证明或签名摘要 |
| `resultHash` | 结果摘要，Merkle 场景下为根哈希 |
| `ledger` | 可信账本同步结果 |
| `detail` | 验证详情 |
| `timestamp` | 记录时间戳 |

账本状态字段 `ledger.status` 当前可能值：

| 状态 | 说明 |
| --- | --- |
| `DISABLED` | 未请求账本同步 |
| `PENDING` | 已请求同步，但适配器或链上状态未确认 |
| `SUCCESS` | 同步成功 |
| `FAILED` | 验证完成，但账本同步失败 |

异常处理边界：

- 业务校验异常通常会被服务层包装成 `status=ERROR` 的验证记录。
- JSON 请求体无法解析等控制器层异常会返回 HTTP `400`。
- 记录详情不存在会返回 HTTP `404`。

## 5. 已完成的旧版兼容接口

旧版路径用于兼容已有前端或历史联调脚本：

```http
GET  /api/verification/health
POST /api/verification/merkle
POST /api/verification/groth16
POST /api/verification/threshold-signature
POST /api/verification/full
```

旧版接口的实现方式：

- `VerificationController` 将旧请求 DTO 映射到新版服务。
- 旧接口仍返回 `com.traffic.wecross.api.VerificationRecord` 结构。
- 保留历史字段名，例如：
  - `verifyType=MERKLE_ROOT`
  - `detail.merkleRoot`
  - `detail.proofHash`
  - `detail.piA`
  - `detail.piB`
  - `detail.piC`
  - `detail.participants`
  - `detail.signature`
- 门限签名旧接口保留默认参数：
  - `totalNodes` 缺省为 `10`
  - `threshold` 缺省为 `5`
  - `participantIds` 缺省为 `[1..threshold]`

交接注意：

- 旧接口是为了避免历史前端出现 `404` 或字段读取失败。
- 在新版前端完全迁移并验证前，不建议删除 `/api/verification/*`。

## 6. 可信账本同步现状

三类新版验证请求均支持以下字段：

```json
{
  "writeLedger": true,
  "ledgerTargets": [
    "traffic.bcos30.VerificationStore",
    "traffic.fabric20.VerificationStore"
  ]
}
```

当前实现流程：

1. 验证逻辑先生成 `VerificationResult`。
2. `VerificationLedgerService` 根据结果构造 `LedgerRecordPayload`。
3. `TrustedLedgerService` 尝试查找历史 `com.traffic.wecross.api.WeCrossGateway` Bean。
4. 如果找到历史网关，则通过反射调用 `writeRecord(...)`。
5. 如果当前运行环境没有历史网关，则返回 `PENDING`，不会改变验证本身的 `PASS` / `FAIL` 状态。

当前边界：

- 当前源码中没有完整历史 `WeCrossGateway` 实现。
- 如果未接入真实网关，`writeLedger=true` 大概率只会得到 `PENDING`。
- 账本同步失败不会覆盖验证结果，只体现在 `ledger.status` 和 `ledger.message`。

## 7. 后续建议完善的接口和功能

### 7.1 记录持久化

当前验证记录只保存在内存中，建议后续补充：

- 数据库表结构或统一持久化仓储。
- 按 `recordId`、`businessId`、`verifyType`、`status`、时间范围检索。
- 服务重启后的记录恢复。
- 与可信账本记录的双向校验或反查。

### 7.2 真实 Groth16 验证

当前 ZKP 接口只完成了接口契约、字段摘要和结构校验，建议后续补充：

- 真实 Groth16 验证器。
- 验证密钥 `verifyingKeyId` 的加载和管理。
- `proof` / `publicSignals` 的标准格式约束。
- 失败原因的可解释化输出。
- 对本地 JPBC 依赖或其他密码学库的打包验证。

### 7.3 真实门限签名验签

当前门限签名接口只检查证据形态和参与数量，建议后续补充：

- 真实门限签名聚合验签。
- 节点公钥、参与方身份、阈值策略的可信来源。
- 签名消息规范，避免不同模块对 `message` 的序列化方式不一致。
- 签名证据格式标准化。

### 7.4 可信账本写入适配

当前账本写入是通过历史网关反射适配，建议后续补充：

- 明确当前项目使用的 WeCross 网关 Bean。
- 固化写链接口，不再依赖反射猜测。
- 补充链上合约方法和资源路径配置。
- 写链成功后记录 `chainPath`、`resourcePath`、`txHash`。
- 增加链上写入失败、鉴权失败、路由不可达等场景的可观测日志。

### 7.5 接口文档和联调样例

建议补充：

- OpenAPI / Swagger 文档。
- 每个接口的成功、失败、参数错误样例。
- 前端联调用的最小 curl 或 PowerShell 请求脚本。
- 与新版前端 `/cross-verification` 模块对应的字段说明。

### 7.6 中文编码与展示文本

当前部分 Java 源码和 docs 中的中文提示文本在本地查看时存在乱码现象。建议后续统一检查：

- 源码文件是否全部为 UTF-8。
- PowerShell / IDE / Maven 编译使用的编码是否一致。
- `verifyName`、`message`、`ledger.message` 等前端展示字段是否为正确中文。

### 7.7 测试覆盖

建议补充：

- Merkle 正常通过、根哈希不匹配、空叶子、非法 `sampleIndex` 测试。
- ZKP 缺少 `piA` / `piB` / `piC`、`valid=false`、非法 `publicInputHash` 测试。
- 门限签名参与方不足、重复参与方、非法节点编号、签名证据为空测试。
- 记录分页、筛选、详情不存在测试。
- 可信账本 `DISABLED`、`PENDING`、`SUCCESS`、`FAILED` 状态测试。
- 旧版 `/api/verification/*` 字段兼容性测试。

## 8. 重要代码位置

| 模块 | 路径 |
| --- | --- |
| 启动类 | `src/main/java/com/traffic/wecross/crossverification/CrossVerificationApplication.java` |
| 新版控制器 | `src/main/java/com/traffic/wecross/crossverification/controller` |
| 新版 DTO | `src/main/java/com/traffic/wecross/crossverification/dto` |
| 新版服务 | `src/main/java/com/traffic/wecross/crossverification/service` |
| 记录模型 | `src/main/java/com/traffic/wecross/crossverification/record` |
| 可信账本适配 | `src/main/java/com/traffic/wecross/crossverification/ledger` |
| 工具类 | `src/main/java/com/traffic/wecross/crossverification/util` |
| 旧版兼容接口 | `src/main/java/com/traffic/wecross/api` |
| 配置文件 | `src/main/resources/application.properties`、`src/main/resources/application.toml` |

## 9. 交接建议

新成员接手时建议按以下顺序确认：

1. 先运行 `GET /api/cross-verification/health`，确认服务启动。
2. 分别调用 Merkle、ZKP、门限签名三个新版接口，确认能生成记录。
3. 调用 `/api/cross-verification/records` 和 `/records/{recordId}`，确认记录查询正常。
4. 调用旧版 `/api/verification/*`，确认历史前端仍可兼容。
5. 如果需要真实上链，优先补齐 WeCross 网关和合约资源路径。
6. 如果要上线使用，优先补齐记录持久化、真实密码学验证和自动化测试。

