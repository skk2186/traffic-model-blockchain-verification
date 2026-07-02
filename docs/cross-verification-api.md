# Cross Verification API

## 1. Module

The cross verification backend provides three independent trusted verification methods for transportation data collaboration:

- Data integrity verification with Merkle-SHA256.
- Privacy proof verification with Groth16.
- Multi-party signature verification with Threshold-Signature.

Each method has its own endpoint and can run independently. Verification records and trusted ledger sync are shared backend capabilities.

## 2. Verification Types

| verifyType | verifyName | algorithm |
| --- | --- | --- |
| `MERKLE` | 数据完整性验证 | `Merkle-SHA256` |
| `ZKP` | 隐私证明验证 | `Groth16` |
| `THRESHOLD_SIGNATURE` | 多方签名验证 | `Threshold-Signature` |

## 3. Health Check

```http
GET /api/cross-verification/health
```

Response:

```json
{
  "status": "UP",
  "service": "transportation-cross-verification-service",
  "apiPrefix": "/api/cross-verification"
}
```

## 4. Merkle Verification

```http
POST /api/cross-verification/merkle/verify
Content-Type: application/json
```

Request:

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

## 5. ZKP Verification

```http
POST /api/cross-verification/zkp/verify
Content-Type: application/json
```

Request:

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

## 6. Threshold Signature Verification

```http
POST /api/cross-verification/threshold-signature/verify
Content-Type: application/json
```

Request:

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

## 7. Verification Records

List records:

```http
GET /api/cross-verification/records?verifyType=MERKLE&status=PASS&page=1&size=10
```

Get record detail:

```http
GET /api/cross-verification/records/{recordId}
```

List response:

```json
{
  "records": [
    {
      "recordId": "MERKLE-1782730000000-123456",
      "verifyType": "MERKLE",
      "verifyName": "数据完整性验证",
      "businessId": "traffic-batch-001",
      "algorithm": "Merkle-SHA256",
      "status": "PASS",
      "resultHash": "rootHash",
      "ledgerStatus": "DISABLED",
      "chainPath": null,
      "resourcePath": null,
      "txHash": null,
      "createdAt": 1782730000000
    }
  ],
  "page": 1,
  "size": 10,
  "total": 1,
  "totalPages": 1
}
```

## 8. Trusted Ledger Sync

Request fields:

- `writeLedger`: set `true` to request trusted ledger sync.
- `ledgerTargets`: optional target resource paths.

Response field:

```json
{
  "ledger": {
    "enabled": true,
    "status": "PENDING",
    "chainPath": "traffic.bcos30",
    "resourcePath": "traffic.bcos30.VerificationStore",
    "txHash": null,
    "message": "可信账本同步适配待接入"
  }
}
```

Ledger status values:

- `DISABLED`: trusted ledger sync was not requested.
- `SUCCESS`: trusted ledger sync succeeded.
- `FAILED`: verification completed, but trusted ledger sync failed.
- `PENDING`: sync status is not confirmed yet.

## 9. Status Values

Verification status values:

- `PASS`: verification passed.
- `FAIL`: verification did not pass.
- `ERROR`: request parameters or internal execution failed.

Structured error response:

```json
{
  "status": "ERROR",
  "message": "businessId must not be empty",
  "detail": {
    "errorCode": "PARAMETER_ERROR",
    "errorMessage": "businessId must not be empty"
  },
  "timestamp": 1782730000000
}
```

## 10. Frontend Proxy

During local frontend development, proxy API requests to the backend service:

```js
proxy: {
  '/api/cross-verification': {
    target: 'http://127.0.0.1:8088',
    changeOrigin: true
  }
}
```

The frontend can call the three verification endpoints independently and then refresh `/api/cross-verification/records` to show the latest verification records.
