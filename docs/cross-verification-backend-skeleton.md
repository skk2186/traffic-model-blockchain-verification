# Cross Verification Backend Skeleton

## Current Scope

This repository currently contains build artifacts and a newly added source skeleton for the cross-verification API. The source tree does not yet restore the legacy `com.traffic.wecross.api` implementation from the existing jar, so the new files are a design and integration scaffold rather than a complete replacement of the running artifact.

## New API Prefix

`/api/cross-verification`

Planned endpoints:

- `GET /api/cross-verification/health`
- `POST /api/cross-verification/merkle/verify`
- `POST /api/cross-verification/zkp/verify`
- `POST /api/cross-verification/threshold-signature/verify`
- `GET /api/cross-verification/records`
- `GET /api/cross-verification/records/{recordId}`

## Merkle Verification

`POST /api/cross-verification/merkle/verify` is implemented by `MerkleVerificationController` and `MerkleVerificationService`.

Behavior:

- Calculates SHA-256 for each `leafItems` entry.
- Builds a Merkle tree by hashing left/right child hash bytes together.
- Duplicates the last node when a layer has an odd number of nodes.
- Returns the Merkle root as `resultHash`.
- Compares the calculated root with `expectedRoot` when provided.
- Returns `leafHash` and `proofPath` when `sampleIndex` is provided.
- Returns `LedgerSyncResult.DISABLED` by default and `PENDING` when `writeLedger=true`.

The default Maven compile path does not require JPBC. JPBC remains available through the `jpbc` Maven profile for the later ZKP implementation stage, once the local `lib/jpbc-*.jar` files are restored.

## ZKP Verification

`POST /api/cross-verification/zkp/verify` is implemented by `ZkpVerificationController` and `ZkpVerificationService`.

Behavior:

- Requires `businessId` and `circuitId`.
- Accepts `proof`, `publicSignals`, and `publicInputHash`.
- Reuses `publicInputHash` when provided.
- Calculates `publicInputHash` from `publicSignals` when the request does not provide one.
- Calculates `proofHash` from the proof object.
- Returns a compact `proofSummary` instead of returning raw proof content.
- Uses `Groth16ProofVerifier` as the replaceable verifier adapter.
- Returns `LedgerSyncResult.DISABLED` by default and `PENDING` when `writeLedger=true`.

The current verifier adapter checks the proof field shape and public input availability. A cryptographic pairing verifier can replace `Groth16ProofVerifier.verify(...)` without changing the controller or DTO contract.

## Threshold Signature Verification

`POST /api/cross-verification/threshold-signature/verify` is implemented by `ThresholdSignatureVerificationController` and `ThresholdSignatureVerificationService`.

Behavior:

- Requires `businessId`, `message`, `totalNodes`, `threshold`, `participantIds`, and `signatureBundle`.
- Verifies `threshold <= totalNodes`.
- Verifies participant IDs are unique and within `1..totalNodes`.
- Calculates `messageHash`, `participantSetHash`, and `signatureHash`.
- Returns threshold metadata and hash summaries without exposing extra message content in detail.
- Uses `ThresholdSignatureVerifier` as the replaceable verifier adapter.
- Returns `LedgerSyncResult.DISABLED` by default and `PENDING` when `writeLedger=true`.

The current verifier adapter checks threshold participation and signature evidence shape. A cryptographic threshold signature library can replace `ThresholdSignatureVerifier.verify(...)` without changing the controller or DTO contract.

## Trusted Ledger Sync

`VerificationLedgerService` is the shared ledger sync entry used by Merkle, ZKP, and threshold signature verification. Each verification flow remains independent and calls ledger sync only after its own verification result has been built.

Ledger payload fields:

- `recordId`
- `verifyType`
- `businessId`
- `algorithm`
- `status`
- `inputHash`
- `proofHash`
- `resultHash`
- `metadataHash`
- `timestamp`

`metadataHash` is calculated from the complete `detail` JSON.

`TrustedLedgerService` is the adapter for existing write logic. When the legacy WeCross gateway bean is available, it attempts to call `com.traffic.wecross.api.WeCrossGateway.writeRecord(...)` through reflection and maps the result into `LedgerSyncResult`. When the legacy gateway is not available in the current source runtime, it returns `PENDING` instead of changing the verification status.

Suggested contract/resource method if a new store is required:

```text
TrafficCrossVerifyStore.saveRecord(
  recordId,
  verifyType,
  businessId,
  algorithm,
  status,
  inputHash,
  proofHash,
  resultHash,
  metadataHash
)

TrafficCrossVerifyStore.getRecord(recordId)
TrafficCrossVerifyStore.getRecordStatus(recordId)
```

Ledger sync failure does not change the verification `status`; it is reported only in `ledger.status` and `ledger.message`.

## Verification Records

`VerificationRecordController` provides shared record query APIs for all independent verification methods:

- `GET /api/cross-verification/records`
- `GET /api/cross-verification/records/{recordId}`

List query parameters:

- `verifyType`
- `businessId`
- `status`
- `page`
- `size`

List record fields:

- `recordId`
- `verifyType`
- `verifyName`
- `businessId`
- `algorithm`
- `status`
- `resultHash`
- `ledgerStatus`
- `chainPath`
- `resourcePath`
- `txHash`
- `createdAt`

Detail record fields include the list fields plus:

- `inputHash`
- `proofHash`
- `detail`
- `ledger`
- `rawResult`

`VerificationRecordService` currently uses an in-memory development-stage store. It saves PASS, FAIL, and ERROR records produced by Merkle, ZKP, and threshold signature verification. The service is intentionally isolated so it can later be replaced by a database repository or trusted ledger query adapter without changing the verification controllers.

## Package Layout

```text
src/main/java/com/traffic/wecross/crossverification
  controller
  dto
  ledger
  record
  service
  util
```

## Implementation Boundary

The skeleton intentionally does not call the legacy combination endpoint and does not assume execution order between the three verification methods. This stage defines DTOs, record models, validation helpers, hash helpers, and placeholder ledger status only.

## DTOs

`VerificationResult`:

- `recordId`
- `verifyType`
- `verifyName`
- `businessId`
- `algorithm`
- `status`
- `message`
- `inputHash`
- `proofHash`
- `resultHash`
- `ledger`
- `detail`
- `timestamp`

`LedgerSyncResult`:

- `enabled`
- `status`
- `chainPath`
- `resourcePath`
- `txHash`
- `message`

`VerificationRecord`:

- `recordId`
- `verifyType`
- `verifyName`
- `businessId`
- `algorithm`
- `status`
- `resultHash`
- `ledgerStatus`
- `chainPath`
- `resourcePath`
- `txHash`
- `createdAt`

## Request DTOs

`MerkleVerifyRequest`:

- `businessId`
- `dataSourceName`
- `leafItems`
- `expectedRoot`
- `sampleIndex`
- `writeLedger`
- `ledgerTargets`

`ZkpVerifyRequest`:

- `businessId`
- `circuitId`
- `proof`
- `publicSignals`
- `publicInputHash`
- `writeLedger`
- `ledgerTargets`

`ThresholdSignatureVerifyRequest`:

- `businessId`
- `message`
- `threshold`
- `totalNodes`
- `participantIds`
- `signatureBundle`
- `writeLedger`
- `ledgerTargets`

## Validation Rules

Merkle:

- `businessId` is required.
- `leafItems` is required.
- `sampleIndex` must be within the leaf range when provided.
- `expectedRoot` must be a 64-character hex string when provided.

ZKP:

- `businessId` is required.
- `circuitId` is required.
- At least one of `proof` or `publicSignals` must contain content.
- `publicInputHash` must be a 64-character hex string when provided.

Threshold signature:

- `businessId` is required.
- `message` is required.
- `threshold` must be greater than `0`.
- `totalNodes` must be greater than `0`.
- `threshold` must be less than or equal to `totalNodes`.
- `participantIds` is required.
- `participantIds.size()` must be greater than or equal to `threshold`.
- `participantIds` must not contain duplicate values.
- Each participant ID must be between `1` and `totalNodes`.

Next implementation steps:

1. Restore or migrate the legacy `com.traffic.wecross.api` source package from the current runtime artifact.
2. Move Merkle logic into `MerkleVerificationService`.
3. Move Groth16 logic into `ZkpVerificationService`.
4. Move threshold signature logic into `ThresholdSignatureVerificationService`.
5. Adapt the current WeCross gateway through `TrustedLedgerService`.
6. Add the new health path to the existing security allowlist without changing credential validation behavior.
7. Replace the in-memory record store with the project-approved record persistence path if one exists.

## Naming Rules

New API, DTO, logs, comments, and documents should use:

- `跨链可信验证`
- `可信验证`
- `可信账本同步`
- `验证记录`

New outward-facing code should avoid the legacy public wording that the project is retiring.
