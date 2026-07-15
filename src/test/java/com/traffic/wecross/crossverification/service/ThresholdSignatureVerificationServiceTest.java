package com.traffic.wecross.crossverification.service;

import com.traffic.wecross.crossverification.dto.ThresholdSignatureVerifyRequest;
import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.ledger.LedgerSyncResult;
import com.traffic.wecross.crossverification.ledger.VerificationLedgerService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ThresholdSignatureVerificationServiceTest {
    private VerificationRecordService recordService;
    private VerificationLedgerService ledgerService;
    private ThresholdSignatureVerifier verifier;
    private ThresholdSignatureVerificationService service;

    @BeforeEach
    void setUp() {
        recordService = new VerificationRecordService();
        ledgerService = mock(VerificationLedgerService.class);
        verifier = mock(ThresholdSignatureVerifier.class);
        service = new ThresholdSignatureVerificationService(recordService, ledgerService, verifier);
        when(ledgerService.syncIfRequested(any(), any(), any())).thenReturn(LedgerSyncResult.disabled());
    }

    @Test
    void keepsRecordLedgerFlowAndRealEcdsaDetailForPass() {
        Map<String, Boolean> participantResults = participantResults(true, true, true);
        when(verifier.verify(eq("traffic message"), eq(3), eq(5), eq(Arrays.asList(1, 2, 4)), any()))
                .thenReturn(ThresholdSignatureVerifier.VerificationDecision.pass(
                        "ECDSA-P256-SHA256",
                        "traffic-consortium-v1",
                        3,
                        3,
                        5,
                        Arrays.asList(1, 2, 4),
                        participantResults));

        ThresholdSignatureVerifyRequest request = request();
        request.writeLedger = true;
        VerificationResult result = service.verify(request);

        assertEquals("PASS", result.status);
        assertEquals("THRESHOLD_SIGNATURE", result.verifyType);
        assertEquals("Threshold-Signature", result.algorithm);
        assertNotNull(result.recordId);
        assertNotNull(result.inputHash);
        assertNotNull(result.proofHash);
        assertEquals("REAL", result.detail.get("verifierMode"));
        assertEquals("JAVA_SIGNATURE", result.detail.get("verifierEngine"));
        assertEquals("ECDSA-P256-SHA256", result.detail.get("scheme"));
        assertEquals("traffic-consortium-v1", result.detail.get("policyId"));
        assertEquals(3, result.detail.get("validSignatureCount"));
        assertEquals(participantResults, result.detail.get("participantResults"));
        assertNotNull(recordService.getRecordDetail(result.recordId));
        verify(ledgerService).syncIfRequested(any(), eq(Boolean.TRUE), any());
    }

    @Test
    void mapsBelowThresholdDecisionToFailWithoutBreakingHashesOrRecord() {
        Map<String, Boolean> participantResults = participantResults(true, false, true);
        when(verifier.verify(eq("traffic message"), eq(3), eq(5), eq(Arrays.asList(1, 2, 4)), any()))
                .thenReturn(ThresholdSignatureVerifier.VerificationDecision.fail(
                        "ECDSA-P256-SHA256",
                        "traffic-consortium-v1",
                        2,
                        3,
                        5,
                        Arrays.asList(1, 2, 4),
                        participantResults,
                        "valid signature count is less than threshold"));

        VerificationResult result = service.verify(request());

        assertEquals("FAIL", result.status);
        assertEquals("valid signature count is less than threshold", result.detail.get("reason"));
        assertEquals(2, result.detail.get("validSignatureCount"));
        assertEquals(participantResults, result.detail.get("participantResults"));
        assertNotNull(recordService.getRecordDetail(result.recordId));
        verify(ledgerService).syncIfRequested(any(), eq(null), any());
    }

    @Test
    void keepsSignatureAndParticipantSetHashesStableAcrossInputOrder() {
        when(verifier.verify(eq("traffic message"), eq(3), eq(5), any(), any()))
                .thenReturn(ThresholdSignatureVerifier.VerificationDecision.pass(
                        "ECDSA-P256-SHA256",
                        "traffic-consortium-v1",
                        3,
                        3,
                        5,
                        Arrays.asList(1, 2, 4),
                        participantResults(true, true, true)));

        ThresholdSignatureVerifyRequest first = request();
        ThresholdSignatureVerifyRequest second = request();
        second.participantIds = Arrays.asList(4, 1, 2);
        Map<String, Object> reorderedSignatures = new LinkedHashMap<>();
        reorderedSignatures.put("4", "sig-4");
        reorderedSignatures.put("1", "sig-1");
        reorderedSignatures.put("2", "sig-2");
        second.signatureBundle.put("participantSignatures", reorderedSignatures);

        VerificationResult firstResult = service.verify(first);
        VerificationResult secondResult = service.verify(second);

        assertEquals(firstResult.proofHash, secondResult.proofHash);
        assertEquals(firstResult.detail.get("signatureHash"), secondResult.detail.get("signatureHash"));
        assertEquals(firstResult.detail.get("participantSetHash"), secondResult.detail.get("participantSetHash"));
    }

    @Test
    void duplicateParticipantsStillReturnErrorBeforeHashNormalization() {
        ThresholdSignatureVerifyRequest request = request();
        request.participantIds = Arrays.asList(1, 1, 2);

        VerificationResult result = service.verify(request);

        assertEquals("ERROR", result.status);
        assertEquals("THRESHOLD_SIGNATURE_VERIFY_ERROR", result.detail.get("errorCode"));
        verifyNoInteractions(verifier);
    }

    @Test
    void outOfRangeParticipantReturnsErrorBeforeVerifier() {
        ThresholdSignatureVerifyRequest request = request();
        request.participantIds = Arrays.asList(1, 2, 6);

        VerificationResult result = service.verify(request);

        assertEquals("ERROR", result.status);
        assertEquals("THRESHOLD_SIGNATURE_VERIFY_ERROR", result.detail.get("errorCode"));
        verifyNoInteractions(verifier);
    }

    @Test
    void emptySignatureBundleReturnsErrorBeforeVerifier() {
        ThresholdSignatureVerifyRequest request = request();
        request.signatureBundle = new LinkedHashMap<>();

        VerificationResult result = service.verify(request);

        assertEquals("ERROR", result.status);
        assertEquals("THRESHOLD_SIGNATURE_VERIFY_ERROR", result.detail.get("errorCode"));
        verifyNoInteractions(verifier);
    }

    private ThresholdSignatureVerifyRequest request() {
        ThresholdSignatureVerifyRequest request = new ThresholdSignatureVerifyRequest();
        request.businessId = "traffic-threshold-test";
        request.message = "traffic message";
        request.threshold = 3;
        request.totalNodes = 5;
        request.participantIds = Arrays.asList(1, 2, 4);
        request.signatureBundle = new LinkedHashMap<>();
        request.signatureBundle.put("scheme", "ECDSA-P256-SHA256");
        request.signatureBundle.put("policyId", "traffic-consortium-v1");
        Map<String, Object> signatures = new LinkedHashMap<>();
        signatures.put("1", "sig-1");
        signatures.put("2", "sig-2");
        signatures.put("4", "sig-4");
        request.signatureBundle.put("participantSignatures", signatures);
        return request;
    }

    private Map<String, Boolean> participantResults(boolean one, boolean two, boolean four) {
        Map<String, Boolean> results = new LinkedHashMap<>();
        results.put("1", one);
        results.put("2", two);
        results.put("4", four);
        return results;
    }
}
