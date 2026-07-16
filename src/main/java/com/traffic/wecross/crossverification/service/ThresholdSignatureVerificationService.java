package com.traffic.wecross.crossverification.service;

import com.traffic.wecross.crossverification.dto.ThresholdSignatureVerifyRequest;
import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.ledger.LedgerSyncResult;
import com.traffic.wecross.crossverification.ledger.VerificationLedgerService;
import com.traffic.wecross.crossverification.record.VerifyStatus;
import com.traffic.wecross.crossverification.record.VerifyType;
import com.traffic.wecross.crossverification.threshold.ThresholdSignatureMessage;
import com.traffic.wecross.crossverification.util.ErrorResultFactory;
import com.traffic.wecross.crossverification.util.HashUtils;
import com.traffic.wecross.crossverification.util.JsonUtils;
import com.traffic.wecross.crossverification.util.ValidationUtils;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
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
        String signatureHash =
                HashUtils.sha256Hex(JsonUtils.toJson(canonicalSignatureBundle(request.signatureBundle)));
        String canonicalPayloadHash = canonicalPayloadHash(request);

        ThresholdSignatureVerifier.VerificationDecision decision =
                thresholdSignatureVerifier.verify(
                        request.businessId,
                        request.message,
                        request.threshold,
                        request.totalNodes,
                        request.participantIds,
                        request.signatureBundle);

        Map<String, Object> detail = JsonUtils.detail();
        detail.put("verifierMode", decision.getVerifierMode());
        detail.put("verifierEngine", decision.getVerifierEngine());
        detail.put("scheme", decision.getScheme());
        detail.put("policyId", decision.getPolicyId());
        detail.put("aggregateSignatureVerified", decision.isAggregateSignatureVerified());
        detail.put("validSignatureCount", decision.getValidSignatureCount());
        detail.put("threshold", decision.getThreshold());
        detail.put("totalNodes", decision.getTotalNodes());
        detail.put("participantCount", request.participantIds.size());
        detail.put("participantIds", decision.getParticipantIds());
        detail.put("messageHash", messageHash);
        detail.put("signatureHash", signatureHash);
        detail.put("participantSetHash", participantSetHash);
        detail.put("canonicalPayloadHash", canonicalPayloadHash);
        if (decision.getReason() != null) {
            detail.put("reason", decision.getReason());
        }

        VerifyStatus status = decision.isPassed() ? VerifyStatus.PASS : VerifyStatus.FAIL;
        String message = decision.isPassed()
                ? "FROST threshold signature verified"
                : "FROST threshold signature verification failed";
        VerificationResult result = recordService.createResult(
                VerifyType.THRESHOLD_SIGNATURE,
                request.businessId,
                "FROST-Ed25519-SHA512",
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
        ValidationUtils.validateThresholdParticipants(
                request.threshold, request.totalNodes, request.participantIds);
        if (request.participantIds.size() < request.threshold) {
            throw new IllegalArgumentException(
                    "participantIds count must be greater than or equal to threshold");
        }
        if (request.signatureBundle == null || request.signatureBundle.isEmpty()) {
            throw new IllegalArgumentException("signatureBundle must not be empty");
        }
    }

    private String participantSetHash(List<Integer> participantIds) {
        List<Integer> normalized = new ArrayList<>(participantIds);
        Collections.sort(normalized);
        return HashUtils.sha256Hex(JsonUtils.toJson(normalized));
    }

    private Map<String, Object> canonicalSignatureBundle(Map<String, Object> signatureBundle) {
        Map<String, Object> canonical = new LinkedHashMap<>();
        canonical.put("scheme", signatureBundle.get("scheme"));
        canonical.put("policyId", signatureBundle.get("policyId"));
        canonical.put("aggregateSignature", signatureBundle.get("aggregateSignature"));
        return canonical;
    }

    private String canonicalPayloadHash(ThresholdSignatureVerifyRequest request) {
        Object policyIdValue = request.signatureBundle.get("policyId");
        String policyId = policyIdValue == null ? "" : String.valueOf(policyIdValue).trim();
        byte[] payload = ThresholdSignatureMessage.encode(
                policyId,
                request.businessId,
                request.threshold,
                request.totalNodes,
                request.participantIds,
                request.message);
        return HashUtils.hex(HashUtils.sha256(payload));
    }

    private VerificationResult buildErrorResult(
            ThresholdSignatureVerifyRequest request, String message) {
        String errorMessage = message == null
                ? "FROST threshold signature verification error"
                : message;
        Map<String, Object> detail =
                ErrorResultFactory.detail("THRESHOLD_SIGNATURE_VERIFY_ERROR", errorMessage);
        return recordService.createResult(
                VerifyType.THRESHOLD_SIGNATURE,
                request == null ? null : request.businessId,
                "FROST-Ed25519-SHA512",
                VerifyStatus.ERROR,
                errorMessage,
                null,
                null,
                LedgerSyncResult.disabled(),
                detail);
    }

    private void syncLedger(
            VerificationResult result, Boolean writeLedger, List<String> ledgerTargets) {
        LedgerSyncResult ledger =
                verificationLedgerService.syncIfRequested(result, writeLedger, ledgerTargets);
        result.ledger = ledger;
        recordService.updateLedger(result.recordId, ledger);
    }
}
