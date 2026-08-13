package com.traffic.wecross.crossverification.service;

import com.traffic.wecross.crossverification.dto.MerkleVerifyRequest;
import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.ledger.LedgerSyncResult;
import com.traffic.wecross.crossverification.ledger.VerificationLedgerService;
import com.traffic.wecross.crossverification.record.VerifyStatus;
import com.traffic.wecross.crossverification.record.VerifyType;
import com.traffic.wecross.crossverification.util.HashUtils;
import com.traffic.wecross.crossverification.util.JsonUtils;
import com.traffic.wecross.crossverification.util.MerkleUtils;
import com.traffic.wecross.crossverification.util.ValidationUtils;
import com.traffic.wecross.crossverification.util.ErrorResultFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class MerkleVerificationService {
    private final VerificationRecordService recordService;
    private final VerificationLedgerService verificationLedgerService;

    public MerkleVerificationService(
            VerificationRecordService recordService,
            VerificationLedgerService verificationLedgerService) {
        this.recordService = recordService;
        this.verificationLedgerService = verificationLedgerService;
    }

    public VerificationResult verify(MerkleVerifyRequest request) {
        try {
            validate(request);
            return verifyInternal(request);
        } catch (Exception e) {
            return buildErrorResult(request, e.getMessage());
        }
    }

    private VerificationResult verifyInternal(MerkleVerifyRequest request) {
        MerkleUtils.MerkleTree tree = MerkleUtils.buildTree(request.leafItems);
        List<Map<String, Object>> proofPath = MerkleUtils.proofPath(tree, request.sampleIndex);
        boolean passed = request.expectedRoot == null
                || request.expectedRoot.trim().isEmpty()
                || tree.rootHash.equalsIgnoreCase(request.expectedRoot.trim());
        String message = request.expectedRoot == null || request.expectedRoot.trim().isEmpty()
                ? "已完成数据完整性摘要生成"
                : passed ? "Merkle验证通过" : "Merkle验证未通过";

        Map<String, Object> detail = JsonUtils.detail();
        detail.put("dataSourceName", request.dataSourceName);
        detail.put("expectedRoot", request.expectedRoot);
        detail.put("totalLeaves", request.leafItems.size());
        detail.put("sampleIndex", request.sampleIndex);
        detail.put("leafHash", request.sampleIndex == null ? null : tree.leafHashes.get(request.sampleIndex));
        detail.put("rootHash", tree.rootHash);
        detail.put("proofPath", proofPath);

        String inputHash = HashUtils.sha256Hex(JsonUtils.toJson(request.leafItems));
        String proofHash = request.sampleIndex == null ? null : HashUtils.sha256Hex(JsonUtils.toJson(proofPath));
        VerificationResult result = recordService.createResult(
                VerifyType.MERKLE,
                request.businessId,
                "Merkle-SHA256",
                passed ? VerifyStatus.PASS : VerifyStatus.FAIL,
                message,
                inputHash,
                proofHash,
                tree.rootHash,
                LedgerSyncResult.disabled(),
                detail);
        syncLedger(result, request.writeLedger, request.ledgerTargets);
        return result;
    }

    private void validate(MerkleVerifyRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be empty");
        }
        ValidationUtils.requireText(request.businessId, "businessId");
        ValidationUtils.requireNotEmpty(request.leafItems, "leafItems");
        ValidationUtils.requireIndexInRange(request.sampleIndex, request.leafItems.size(), "sampleIndex");
        ValidationUtils.requireSha256HexIfPresent(request.expectedRoot, "expectedRoot");
    }

    private VerificationResult buildErrorResult(MerkleVerifyRequest request, String message) {
        String errorMessage = message == null ? "Merkle验证异常" : message;
        Map<String, Object> detail = ErrorResultFactory.detail("MERKLE_VERIFY_ERROR", errorMessage);
        LedgerSyncResult ledger = LedgerSyncResult.disabled();
        return recordService.createResult(
                VerifyType.MERKLE,
                request == null ? null : request.businessId,
                "Merkle-SHA256",
                VerifyStatus.ERROR,
                errorMessage,
                null,
                null,
                null,
                ledger,
                detail);
    }

    private void syncLedger(VerificationResult result, Boolean writeLedger, List<String> ledgerTargets) {
        LedgerSyncResult ledger = verificationLedgerService.syncIfRequested(result, writeLedger, ledgerTargets);
        result.ledger = ledger;
        recordService.updateLedger(result.recordId, ledger);
    }
}
