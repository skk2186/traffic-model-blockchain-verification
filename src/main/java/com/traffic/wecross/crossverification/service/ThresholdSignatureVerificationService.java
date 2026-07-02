package com.traffic.wecross.crossverification.service;

import com.traffic.wecross.crossverification.dto.ThresholdSignatureVerifyRequest;
import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.ledger.LedgerSyncResult;
import com.traffic.wecross.crossverification.ledger.VerificationLedgerService;
import com.traffic.wecross.crossverification.record.VerifyStatus;
import com.traffic.wecross.crossverification.record.VerifyType;
import com.traffic.wecross.crossverification.util.HashUtils;
import com.traffic.wecross.crossverification.util.JsonUtils;
import com.traffic.wecross.crossverification.util.ValidationUtils;
import com.traffic.wecross.crossverification.util.ErrorResultFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
public class ThresholdSignatureVerificationService {
    private final VerificationRecordService recordService;
    private final VerificationLedgerService verificationLedgerService;
    private final ThresholdSignatureVerifier thresholdSignatureVerifier;

    public ThresholdSignatureVerificationService(
            VerificationRecordService recordService,
            VerificationLedgerService verificationLedgerService,
            ThresholdSignatureVerifier thresholdSignatureVerifier) {
        this.recordService = recordService;
        this.verificationLedgerService = verificationLedgerService;
        this.thresholdSignatureVerifier = thresholdSignatureVerifier;
    }

    public VerificationResult verify(ThresholdSignatureVerifyRequest request) {
        try {
            validate(request);
            return verifyInternal(request);
        } catch (Exception e) {
            return buildErrorResult(request, e.getMessage());
        }
    }

    private VerificationResult verifyInternal(ThresholdSignatureVerifyRequest request) {
        String messageHash = HashUtils.sha256Hex(request.message);
        String participantSetHash = participantSetHash(request.participantIds);
        String signatureHash = HashUtils.sha256Hex(JsonUtils.toJson(request.signatureBundle));

        ThresholdSignatureVerifier.VerificationDecision decision =
                thresholdSignatureVerifier.verify(request.threshold, request.participantIds, request.signatureBundle);

        Map<String, Object> detail = JsonUtils.detail();
        detail.put("threshold", request.threshold);
        detail.put("totalNodes", request.totalNodes);
        detail.put("participantCount", request.participantIds.size());
        detail.put("participantIds", request.participantIds);
        detail.put("messageHash", messageHash);
        detail.put("signatureHash", signatureHash);
        detail.put("participantSetHash", participantSetHash);
        if (decision.getReason() != null) {
            detail.put("reason", decision.getReason());
        }

        VerifyStatus status = decision.isPassed() ? VerifyStatus.PASS : VerifyStatus.FAIL;
        String message = decision.isPassed() ? "多方签名验证通过" : "多方签名验证未通过";
        VerificationResult result = recordService.createResult(
                VerifyType.THRESHOLD_SIGNATURE,
                request.businessId,
                "Threshold-Signature",
                status,
                message,
                messageHash,
                signatureHash,
                LedgerSyncResult.disabled(),
                detail);
        syncLedger(result, request.writeLedger, request.ledgerTargets);
        return result;
    }

    private void validate(ThresholdSignatureVerifyRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be empty");
        }
        ValidationUtils.requireText(request.businessId, "businessId");
        ValidationUtils.requireText(request.message, "message");
        ValidationUtils.validateThresholdParticipants(request.threshold, request.totalNodes, request.participantIds);
        if (request.signatureBundle == null || request.signatureBundle.isEmpty()) {
            throw new IllegalArgumentException("signatureBundle must not be empty");
        }
    }

    private String participantSetHash(List<Integer> participantIds) {
        List<Integer> normalized = new ArrayList<>(participantIds);
        Collections.sort(normalized);
        return HashUtils.sha256Hex(JsonUtils.toJson(normalized));
    }

    private VerificationResult buildErrorResult(ThresholdSignatureVerifyRequest request, String message) {
        String errorMessage = message == null ? "多方签名验证异常" : message;
        Map<String, Object> detail = ErrorResultFactory.detail("THRESHOLD_SIGNATURE_VERIFY_ERROR", errorMessage);
        LedgerSyncResult ledger = LedgerSyncResult.disabled();
        return recordService.createResult(
                VerifyType.THRESHOLD_SIGNATURE,
                request == null ? null : request.businessId,
                "Threshold-Signature",
                VerifyStatus.ERROR,
                errorMessage,
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
