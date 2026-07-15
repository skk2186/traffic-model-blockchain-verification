# 多模态交通可信验证后端技术文档

本项目是交通数据跨机构协作场景下的可信验证后端，基于 Spring Boot 提供三类验证能力：数据完整性验证、隐私证明验证、多方签名验证。后端同时负责保存验证记录，并可在验证完成后把摘要结果同步到可信账本。

首次接手项目时，建议先按“快速启动”跑通健康检查和 Merkle 验证，再补齐 ZoKrates、MySQL、WeCross 等真实环境。

## 1. 功能概览

### 1.1 核心验证能力

| 能力 | 接口 | 算法/引擎 | 说明 |
| --- | --- | --- | --- |
| 数据完整性验证 | `POST /api/cross-verification/merkle/verify` | Merkle-SHA256 | 对交通数据批次生成 Merkle 根，或和前端/链上给出的根哈希进行比对 |
| 隐私证明验证 | `POST /api/cross-verification/zkp/verify` | Groth16 + ZoKrates CLI | 校验 ZoKrates 生成的 Groth16 证明，默认使用真实验证模式 |
| 多方签名验证 | `POST /api/cross-verification/threshold-signature/verify` | ECDSA-P256-SHA256 | 按策略文件校验参与方签名数量是否达到阈值 |
| 验证记录查询 | `GET /api/cross-verification/records` | 内存或 MySQL | 支持按验证类型、业务 ID、状态分页查询 |
| 账本状态回写 | `PUT /api/cross-verification/records/{recordId}/ledger` | 记录更新 | 前端或编排层完成链上同步后，可回写账本状态 |

### 1.2 兼容接口

项目仍保留旧版 `/api/verification/*` 兼容接口，用于适配历史前端或旧联调脚本。新开发优先使用 `/api/cross-verification/*`。

旧接口包括：

- `GET /api/verification/health`
- `POST /api/verification/merkle`
- `POST /api/verification/groth16`
- `POST /api/verification/threshold-signature`
- `POST /api/verification/full`

### 1.3 记录存储

验证记录有两种存储模式：

- `memory`：进程内存存储，适合快速调试，服务重启后记录丢失。
- `mysql`：写入 MySQL 表 `verification_records`，适合联调、演示和长期保存。

`src/main/resources/application.properties` 默认是 `memory`；`scripts/start-backend.ps1` 默认使用 `mysql`。如果只是首次跑通，可以显式传入 `-RecordStorage memory`。

### 1.4 可信账本同步

请求体中的 `writeLedger=true` 会触发账本同步逻辑。当前实现通过反射寻找旧模块中的 `com.traffic.wecross.api.WeCrossGateway`，并调用其写链能力：

- 找到并调用成功：返回 `SUCCESS` 或 `FAILED`。
- 未接入网关或状态暂不能确认：返回 `PENDING`。
- 未请求写链：返回 `DISABLED`。

因此，业务验证结果和账本同步结果是两个层次：验证可以 `PASS`，账本状态仍可能是 `PENDING`。

## 2. 技术栈与目录

### 2.1 技术栈

- JDK 8
- Maven
- Spring Boot 2.7.18
- MySQL 8.x，可选但推荐
- ZoKrates 0.8.7，用于真实 Groth16 验证
- WeCross Java SDK 1.4.0，用于兼容可信账本集成

### 2.2 关键目录

```text
src/main/java/com/traffic/wecross/crossverification
  controller/       新版验证接口
  service/          Merkle、ZKP、多方签名、记录服务
  zkp/              ZoKrates 证明规范化和进程调用
  threshold/        多方签名策略加载和公钥解析
  record/           验证记录模型和 MySQL 仓储
  ledger/           可信账本同步适配

src/main/java/com/traffic/wecross/api
  旧版 /api/verification 兼容层

config/zkp
  ZKP 验证公钥目录

config/threshold
  多方签名策略文件目录

crypto/zokrates/traffic-speed-range-v1
  ZoKrates 电路、构建脚本、证明样例

scripts
  Windows PowerShell 启动脚本

scripts/mysql
  MySQL 建库建表脚本

docs
  补充 API 和数据库说明
```

## 3. 环境要求

### 3.1 基础环境

确认 Java 和 Maven 可用：

```powershell
java -version
mvn -version
```

要求：

- Java 编译目标为 1.8。
- Maven 能访问项目依赖。脚本默认使用项目内 `.m2/repository` 作为本地仓库。
- Windows 推荐使用 PowerShell 5.1 或更新版本。

### 3.2 ZoKrates 环境

真实 ZKP 验证依赖 ZoKrates CLI。默认约定路径为：

```text
<项目族根目录>\ZoKrates\target\release\zokrates.exe
```

也可以通过启动参数或环境变量指定：

```powershell
$env:ZOKRATES_EXECUTABLE="E:\path\to\zokrates.exe"
```

本项目内置 `traffic-speed-range-v1` 示例电路，证明含义是：私有速度值 `speed` 位于公开区间 `[minSpeed, maxSpeed]` 内。示例使用：

- 私有输入：`speed=60`
- 公开输入：`minSpeed=30`、`maxSpeed=80`
- 曲线：`bn128`
- 证明系统：`g16`
- ZoKrates backend：`ark`

构建电路和生成样例：

```powershell
.\crypto\zokrates\traffic-speed-range-v1\scripts\build.ps1 -ZokratesPath $env:ZOKRATES_EXECUTABLE
.\crypto\zokrates\traffic-speed-range-v1\scripts\generate-valid-proof.ps1 -ZokratesPath $env:ZOKRATES_EXECUTABLE
.\crypto\zokrates\traffic-speed-range-v1\scripts\verify-proof.ps1 -ZokratesPath $env:ZOKRATES_EXECUTABLE
```

说明：

- `build.ps1` 会生成运行时产物到 `runtime/zkp/traffic-speed-range-v1/`。
- 公开验证密钥会复制到 `crypto/zokrates/traffic-speed-range-v1/keys/verification.key`。
- 服务默认从 `config/zkp/{verifyingKeyId}/verification.key` 查找验证密钥。仓库已提供 `config/zkp/traffic-speed-range-v1/verification.key`。
- 证明文件样例在 `crypto/zokrates/traffic-speed-range-v1/fixtures/valid/`。

### 3.3 MySQL 环境

生产或联调建议开启 MySQL 记录存储。先创建数据库：

```powershell
mysql -uroot -p < .\scripts\mysql\verification-records.sql
```

如果使用 Navicat，也可以打开 `scripts/mysql/verification-records.sql` 直接执行。

默认连接串：

```text
jdbc:mysql://127.0.0.1:3306/traffic_verification?useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai&useSSL=false&allowPublicKeyRetrieval=true
```

当 `VERIFICATION_RECORDS_MYSQL_INITIALIZE_SCHEMA=true` 时，只要数据库存在，后端会自动创建或补齐 `verification_records` 表。

### 3.4 WeCross/可信账本环境

可信账本同步是可选能力。默认配置：

```properties
wecross.mode=trusted-ledger
wecross.contract-method=saveRecord
wecross.default-targets=traffic.bcos30.VerificationStore,traffic.fabric20.VerificationStore
wecross.router-url=http://127.0.0.1:8250
```

如果只是验证后端功能，可以把请求中的 `writeLedger` 设为 `false`。如果设为 `true`，但没有接入可用的 WeCross 网关，接口通常仍会返回验证结果，同时账本状态为 `PENDING` 或 `FAILED`。

## 4. 快速启动

### 4.1 最快跑通：内存记录模式

适合第一次拉取代码，只验证服务能启动、接口能调用：

```powershell
cd E:\path\to\traffic-model-blockchain-verification
$env:VERIFICATION_RECORDS_STORAGE="memory"
mvn -q spring-boot:run
```

服务地址：

```text
http://127.0.0.1:8088
```

健康检查：

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8088/api/cross-verification/health"
```

预期返回：

```json
{
  "status": "UP",
  "service": "transportation-cross-verification-service",
  "apiPrefix": "/api/cross-verification"
}
```

### 4.2 推荐启动：PowerShell 脚本

脚本会设置 ZoKrates、验证模式、记录存储和 Maven 本地仓库：

```powershell
.\scripts\start-backend.ps1 `
  -ZokratesPath "E:\path\to\zokrates.exe" `
  -RecordStorage memory
```

使用 MySQL 存储：

```powershell
.\scripts\start-backend.ps1 `
  -ZokratesPath "E:\path\to\zokrates.exe" `
  -RecordStorage mysql `
  -MysqlUrl "jdbc:mysql://127.0.0.1:3306/traffic_verification?useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai&useSSL=false&allowPublicKeyRetrieval=true" `
  -MysqlUsername "root" `
  -MysqlPassword "your_password"
```

### 4.3 后台启动示例

如果希望后端在后台运行：

```powershell
$env:VERIFICATION_RECORDS_STORAGE="memory"
Start-Process powershell -WindowStyle Hidden -ArgumentList @(
  "-NoProfile",
  "-ExecutionPolicy", "Bypass",
  "-Command",
  "cd '$PWD'; mvn -q spring-boot:run *> backend-run.log"
)
```

查看端口：

```powershell
netstat -ano | Select-String ":8088"
```

停止时根据 `netstat` 输出的 PID 执行：

```powershell
Stop-Process -Id <PID> -Force
```

## 5. 配置项

常用配置可通过环境变量覆盖。

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ZKP_MODE` | `real` | ZKP 验证模式，真实模式调用 ZoKrates |
| `ZKP_ALLOW_LEGACY_MOCK` | `false` | 是否允许旧 mock ZKP 校验；真实环境保持 `false` |
| `ZOKRATES_EXECUTABLE` | 本机 ZoKrates 路径 | ZoKrates CLI 路径 |
| `ZKP_KEY_ROOT` | `config/zkp` | 验证密钥根目录 |
| `ZKP_TEMP_ROOT` | `runtime/zkp-temp` | ZKP 临时工作目录 |
| `ZKP_TIMEOUT_MILLIS` | `30000` | 单次 ZoKrates 验证超时时间 |
| `THRESHOLD_SIGNATURE_MODE` | `real` | 多方签名验证模式 |
| `THRESHOLD_SIGNATURE_ALLOW_LEGACY_MOCK` | `false` | 是否允许旧 mock 多方签名校验 |
| `VERIFICATION_RECORDS_STORAGE` | `memory` | 记录存储模式：`memory` 或 `mysql` |
| `VERIFICATION_RECORDS_MYSQL_URL` | 空 | MySQL JDBC URL |
| `VERIFICATION_RECORDS_MYSQL_USERNAME` | `root` | MySQL 用户名 |
| `VERIFICATION_RECORDS_MYSQL_PASSWORD` | 空 | MySQL 密码 |
| `VERIFICATION_RECORDS_MYSQL_INITIALIZE_SCHEMA` | `true` | 是否自动初始化记录表 |
| `WECROSS_ROUTER_URL` | `http://127.0.0.1:8250` | WeCross Router 地址 |
| `WECROSS_DEFAULT_TARGETS` | `traffic.bcos30.VerificationStore,traffic.fabric20.VerificationStore` | 默认写链目标 |

## 6. 接口使用

### 6.1 健康检查

```http
GET /api/cross-verification/health
```

### 6.2 Merkle 数据完整性验证

请求：

```powershell
$body = @{
  businessId = "traffic-batch-001"
  dataSourceName = "vehicle-speed-records"
  leafItems = @("record-1", "record-2", "record-3")
  expectedRoot = ""
  sampleIndex = 1
  writeLedger = $false
  ledgerTargets = @()
} | ConvertTo-Json -Depth 10

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8088/api/cross-verification/merkle/verify" `
  -ContentType "application/json" `
  -Body $body
```

说明：

- `expectedRoot` 为空时，后端只生成本批数据的 Merkle 根并返回 `PASS`。
- `expectedRoot` 非空时，必须是 64 位 SHA-256 十六进制字符串；后端会和计算出的根哈希比对。
- `sampleIndex` 用于生成指定叶子的 Merkle 证明路径。

### 6.3 ZKP 隐私证明验证

使用内置有效样例：

```powershell
$proof = Get-Content ".\crypto\zokrates\traffic-speed-range-v1\fixtures\valid\proof.json" -Raw -Encoding UTF8 | ConvertFrom-Json
$signals = Get-Content ".\crypto\zokrates\traffic-speed-range-v1\fixtures\valid\public-signals.json" -Raw -Encoding UTF8 | ConvertFrom-Json

$body = @{
  businessId = "traffic-zkp-valid"
  circuitId = "traffic-speed-range-v1"
  verifyingKeyId = "traffic-speed-range-v1"
  proof = $proof
  publicSignals = $signals
  writeLedger = $false
  ledgerTargets = @()
} | ConvertTo-Json -Depth 30

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8088/api/cross-verification/zkp/verify" `
  -ContentType "application/json" `
  -Body $body
```

说明：

- `circuitId` 标识业务电路。
- `verifyingKeyId` 为空时默认使用 `circuitId`。
- 真实模式会从 `config/zkp/{verifyingKeyId}/verification.key` 查找验证密钥。
- `proof` 支持原生 ZoKrates proof JSON；`publicSignals` 可使用 proof 中的 `inputs` 数组。

### 6.4 多方签名验证

仓库根目录提供了三个样例：

- `threshold-valid-request.json`
- `threshold-two-valid-request.json`
- `threshold-forged-request.json`

调用有效样例：

```powershell
$body = Get-Content ".\threshold-valid-request.json" -Raw -Encoding UTF8

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8088/api/cross-verification/threshold-signature/verify" `
  -ContentType "application/json" `
  -Body $body
```

真实模式请求格式：

```json
{
  "businessId": "traffic-threshold-valid",
  "message": "traffic speed range approved",
  "threshold": 3,
  "totalNodes": 5,
  "participantIds": [1, 2, 4],
  "signatureBundle": {
    "scheme": "ECDSA-P256-SHA256",
    "policyId": "traffic-consortium-dev-local",
    "participantSignatures": {
      "1": "<base64-ecdsa-signature>",
      "2": "<base64-ecdsa-signature>",
      "4": "<base64-ecdsa-signature>"
    }
  },
  "writeLedger": false,
  "ledgerTargets": []
}
```

说明：

- 策略文件位于 `config/threshold/{policyId}.json`。
- 当前支持的签名方案为 `ECDSA-P256-SHA256`。
- `participantIds` 必须和 `signatureBundle.participantSignatures` 的参与方集合一致。
- `threshold`、`totalNodes` 必须和策略文件一致。

### 6.5 查询验证记录

列表查询：

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8088/api/cross-verification/records?page=1&size=10"
```

支持参数：

- `verifyType`：`MERKLE`、`ZKP`、`THRESHOLD_SIGNATURE`
- `businessId`：业务 ID
- `status`：`PASS`、`FAIL`、`ERROR`
- `page`：页码，从 1 开始
- `size`：每页数量，最大 100

详情查询：

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8088/api/cross-verification/records/{recordId}"
```

账本状态回写：

```powershell
$body = @{
  ledger = @{
    enabled = $true
    status = "SUCCESS"
    chainPath = "traffic.bcos30"
    resourcePath = "traffic.bcos30.VerificationStore"
    txHash = "0xabc"
    message = "已同步至可信账本"
  }
  chainVerification = @{
    status = "SUCCESS"
    chainPath = "traffic.fabric20"
    resourcePath = "traffic.fabric20.VerificationStore"
    txHash = "0xdef"
    recordKey = "traffic-batch-001:MERKLE"
  }
} | ConvertTo-Json -Depth 10

Invoke-RestMethod `
  -Method Put `
  -Uri "http://127.0.0.1:8088/api/cross-verification/records/{recordId}/ledger" `
  -ContentType "application/json" `
  -Body $body
```

## 7. 返回结构

三类验证接口统一返回 `VerificationResult`：

```json
{
  "recordId": "MERKLE-1782730000000-123456",
  "verifyType": "MERKLE",
  "verifyName": "数据完整性验证",
  "businessId": "traffic-batch-001",
  "algorithm": "Merkle-SHA256",
  "status": "PASS",
  "message": "数据完整性验证通过",
  "inputHash": "...",
  "proofHash": "...",
  "resultHash": "...",
  "ledger": {
    "enabled": false,
    "status": "DISABLED",
    "chainPath": null,
    "resourcePath": null,
    "txHash": null,
    "message": "未请求可信账本同步"
  },
  "detail": {},
  "timestamp": 1782730000000
}
```

状态值：

- `PASS`：验证通过。
- `FAIL`：验证未通过，例如根哈希不一致、证明被拒绝、有效签名数不足。
- `ERROR`：请求参数不合法或内部执行异常。

账本状态：

- `DISABLED`：未请求写链。
- `PENDING`：已请求写链，但状态暂未确认或适配未完全接入。
- `SUCCESS`：写链成功。
- `FAILED`：写链失败。

## 8. 构建与测试

编译：

```powershell
mvn -q -DskipTests compile
```

运行测试：

```powershell
mvn -q test
```

打包：

```powershell
mvn -q -DskipTests package
```

构建产物：

```text
target/transportation_model-1.0-SNAPSHOT.jar
```

## 9. 常见问题

### 9.1 `ZoKrates executable does not exist`

启动脚本没有找到 `zokrates.exe`。处理方式：

```powershell
.\scripts\start-backend.ps1 -ZokratesPath "E:\path\to\zokrates.exe" -RecordStorage memory
```

或设置环境变量：

```powershell
$env:ZOKRATES_EXECUTABLE="E:\path\to\zokrates.exe"
```

### 9.2 ZKP 返回 `VERIFICATION_KEY_NOT_FOUND`

检查验证密钥是否存在：

```text
config/zkp/{verifyingKeyId}/verification.key
```

例如 `verifyingKeyId=traffic-speed-range-v1` 时，应存在：

```text
config/zkp/traffic-speed-range-v1/verification.key
```

### 9.3 MySQL 模式启动失败

常见原因：

- 数据库 `traffic_verification` 不存在。
- 连接串、用户名或密码错误。
- MySQL 服务未启动。

可以先切回内存模式确认后端主体可运行：

```powershell
.\scripts\start-backend.ps1 -ZokratesPath "E:\path\to\zokrates.exe" -RecordStorage memory
```

### 9.4 验证通过但账本状态是 `PENDING`

这通常表示后端没有找到可用的旧版 `WeCrossGateway`，或写链状态暂未确认。先确认请求中的 `writeLedger` 是否必须开启；如果只是验证算法功能，可使用：

```json
{
  "writeLedger": false,
  "ledgerTargets": []
}
```

### 9.5 接口返回 200，但业务状态是 `ERROR`

三类验证服务会把业务校验失败封装为统一结果返回。排查时不要只看 HTTP 状态码，还要看响应体中的：

- `status`
- `message`
- `detail.reason`
- `detail.errorCode`

## 10. 新人上手建议

建议按以下顺序熟悉项目：

1. 启动内存模式，调用 `/api/cross-verification/health`。
2. 调用 Merkle 验证，确认记录列表能看到新记录。
3. 配置 MySQL，确认记录能落入 `verification_records`。
4. 配置 ZoKrates，调用内置 `traffic-speed-range-v1` 证明样例。
5. 调用 `threshold-valid-request.json`，理解策略文件和参与方签名关系。
6. 需要链上联调时，再开启 `writeLedger=true` 并接入 WeCross 网关。

补充文档：

- `docs/cross-verification-api.md`
- `docs/mysql-verification-records.md`
- `docs/cross-verification-backend-skeleton.md`
- `crypto/zokrates/traffic-speed-range-v1/README.md`
