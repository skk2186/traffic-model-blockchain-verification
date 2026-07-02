package com.traffic.wecross.crossverification.service;

import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.dto.ZkpVerifyRequest;
import com.traffic.wecross.crossverification.ledger.LedgerSyncResult;
import com.traffic.wecross.crossverification.ledger.VerificationLedgerService;
import com.traffic.wecross.crossverification.record.VerifyStatus;
import com.traffic.wecross.crossverification.record.VerifyType;
import com.traffic.wecross.crossverification.util.HashUtils;
import com.traffic.wecross.crossverification.util.JsonUtils;
import com.traffic.wecross.crossverification.util.ValidationUtils;
import com.traffic.wecross.crossverification.util.ErrorResultFactory;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Map;

@Service
public class ZkpVerificationService {
    private final VerificationRecordService recordService;
    private final VerificationLedgerService verificationLedgerService;
    private final Groth16ProofVerifier groth16ProofVerifier;

    public ZkpVerificationService(
            VerificationRecordService recordService,
            VerificationLedgerService verificationLedgerService,
            Groth16ProofVerifier groth16ProofVerifier) {
        this.recordService = recordService;
        this.verificationLedgerService = verificationLedgerService;
        this.groth16ProofVerifier = groth16ProofVerifier;
    }

    public VerificationResult verify(ZkpVerifyRequest request) {
        try {
            validate(request);
            return verifyInternal(request);
        } catch (Exception e) {
            return buildErrorResult(request, e.getMessage());
        }
    }

    private VerificationResult verifyInternal(ZkpVerifyRequest request) {
        String inputHash = request.publicInputHash == null || request.publicInputHash.trim().isEmpty()
                ? HashUtils.sha256Hex(JsonUtils.toJson(request.publicSignals))
                : request.publicInputHash.trim();
        String proofHash = HashUtils.sha256Hex(JsonUtils.toJson(request.proof));

        Groth16ProofVerifier.VerificationDecision decision =
                groth16ProofVerifier.verify(request.proof, request.publicSignals, hasPublicInput(request));

        Map<String, Object> detail = JsonUtils.detail();
        detail.put("circuitId", request.circuitId);
        detail.put("publicInputHash", inputHash);
        detail.put("proofSummary", proofSummary(request));
        if (decision.getReason() != null) {
            detail.put("reason", decision.getReason());
        }

        VerifyStatus status = decision.isPassed() ? VerifyStatus.PASS : VerifyStatus.FAIL;
        String message = decision.isPassed() ? "隐私证明验证通过" : "隐私证明验证未通过";
        VerificationResult result = recordService.createResult(
                VerifyType.ZKP,
                request.businessId,
                "Groth16",
                status,
                message,
                inputHash,
                proofHash,
                LedgerSyncResult.disabled(),
                detail);
        syncLedger(result, request.writeLedger, request.ledgerTargets);
        return result;
    }

    private void validate(ZkpVerifyRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be empty");
        }
        ValidationUtils.requireText(request.businessId, "businessId");
        ValidationUtils.requireText(request.circuitId, "circuitId");
        ValidationUtils.requireSha256HexIfPresent(request.publicInputHash, "publicInputHash");
        if (isEmptyContent(request.proof) && isEmptyContent(request.publicSignals)) {
            throw new IllegalArgumentException("proof or publicSignals must contain verifiable content");
        }
    }

    private Map<String, Object> proofSummary(ZkpVerifyRequest request) {
        Map<String, Object> summary = JsonUtils.detail();
        summary.put("proofHash", HashUtils.sha256Hex(JsonUtils.toJson(request.proof)));
        summary.put("proofFieldCount", contentSize(request.proof));
        summary.put("publicSignalCount", contentSize(request.publicSignals));
        summary.put("hasPiA", hasProofField(request, "piA"));
        summary.put("hasPiB", hasProofField(request, "piB"));
        summary.put("hasPiC", hasProofField(request, "piC"));
        return summary;
    }

    private boolean hasProofField(ZkpVerifyRequest request, String key) {
        if (!(request.proof instanceof Map)) {
            return false;
        }
        Object value = ((Map<?, ?>) request.proof).get(key);
        return value != null && !String.valueOf(value).trim().isEmpty();
    }

    private boolean hasPublicInput(ZkpVerifyRequest request) {
        return !isEmptyContent(request.publicSignals)
                || (request.publicInputHash != null && !request.publicInputHash.trim().isEmpty());
    }

    private boolean isEmptyContent(Object value) {
        if (value == null) {
            return true;
        }
        if (value instanceof Map) {
            return ((Map<?, ?>) value).isEmpty();
        }
        if (value instanceof Collection) {
            return ((Collection<?>) value).isEmpty();
        }
        return String.valueOf(value).trim().isEmpty();
    }

    private int contentSize(Object value) {
        if (value instanceof Map) {
            return ((Map<?, ?>) value).size();
        }
        if (value instanceof Collection) {
            return ((Collection<?>) value).size();
        }
        return value == null ? 0 : 1;
    }

    private VerificationResult buildErrorResult(ZkpVerifyRequest request, String message) {
        String errorMessage = message == null ? "隐私证明验证异常" : message;
        Map<String, Object> detail = ErrorResultFactory.detail("ZKP_VERIFY_ERROR", errorMessage);
        LedgerSyncResult ledger = LedgerSyncResult.disabled();
        return recordService.createResult(
                VerifyType.ZKP,
                request == null ? null : request.businessId,
                "Groth16",
                VerifyStatus.ERROR,
                errorMessage,
                null,
                null,
                ledger,
                detail);
    }

    private void syncLedger(VerificationResult result, Boolean writeLedger, java.util.List<String> ledgerTargets) {
        LedgerSyncResult ledger = verificationLedgerService.syncIfRequested(result, writeLedger, ledgerTargets);
        result.ledger = ledger;
        recordService.updateLedger(result.recordId, ledger);
    }
}
