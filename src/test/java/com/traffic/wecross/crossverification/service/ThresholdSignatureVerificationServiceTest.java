package com.traffic.wecross.crossverification.service;

import com.traffic.wecross.crossverification.dto.ThresholdSignatureVerifyRequest;
import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.ledger.LedgerSyncResult;
import com.traffic.wecross.crossverification.ledger.VerificationLedgerService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
        when(ledgerService.syncIfRequested(any(), any(), any()))
                .thenReturn(LedgerSyncResult.disabled());
    }

    @Test
    void keepsRecordAndLedgerFlowForValidFrostSignature() {
        when(verifier.verify(
                eq("traffic-threshold-test"),
                eq("traffic message"),
                eq(3),
                eq(5),
                eq(Arrays.asList(1, 2, 4)),
                any()))
                .thenReturn(ThresholdSignatureVerifier.VerificationDecision.pass(
                        "FROST-ED25519-SHA512",
                        "traffic-consortium-v1",
                        3,
                        5,
                        Arrays.asList(1, 2, 4)));

        ThresholdSignatureVerifyRequest request = request();
        request.writeLedger = true;
        VerificationResult result = service.verify(request);

        assertEquals("PASS", result.status);
        assertEquals("THRESHOLD_SIGNATURE", result.verifyType);
        assertEquals("FROST-Ed25519-SHA512", result.algorithm);
        assertNotNull(result.recordId);
        assertNotNull(result.inputHash);
        assertNotNull(result.proofHash);
        assertEquals("REAL", result.detail.get("verifierMode"));
        assertEquals(ThresholdSignatureVerifier.ENGINE, result.detail.get("verifierEngine"));
        assertEquals("FROST-ED25519-SHA512", result.detail.get("scheme"));
        assertEquals("traffic-consortium-v1", result.detail.get("policyId"));
        assertEquals(Boolean.TRUE, result.detail.get("aggregateSignatureVerified"));
        assertEquals(3, result.detail.get("validSignatureCount"));
        assertNotNull(result.detail.get("canonicalPayloadHash"));
        assertNotNull(recordService.getRecordDetail(result.recordId));
        verify(ledgerService).syncIfRequested(any(), eq(Boolean.TRUE), any());
    }

    @Test
    void mapsInvalidAggregateSignatureDecisionToFail() {
        when(verifier.verify(any(), any(), any(), any(), any(), any()))
                .thenReturn(ThresholdSignatureVerifier.VerificationDecision.fail(
                        "FROST-ED25519-SHA512",
                        "traffic-consortium-v1",
                        3,
                        5,
                        Arrays.asList(1, 2, 4),
                        "FROST aggregate signature verification failed"));

        VerificationResult result = service.verify(request());

        assertEquals("FAIL", result.status);
        assertEquals(
                "FROST aggregate signature verification failed",
                result.detail.get("reason"));
        assertEquals(Boolean.FALSE, result.detail.get("aggregateSignatureVerified"));
        assertEquals(0, result.detail.get("validSignatureCount"));
        assertNotNull(recordService.getRecordDetail(result.recordId));
        verify(ledgerService).syncIfRequested(any(), eq(null), any());
    }

    @Test
    void hashesAreStableAcrossParticipantInputOrder() {
        when(verifier.verify(any(), any(), any(), any(), any(), any()))
                .thenAnswer(invocation -> ThresholdSignatureVerifier.VerificationDecision.pass(
                        "FROST-ED25519-SHA512",
                        "traffic-consortium-v1",
                        3,
                        5,
                        invocation.getArgument(4)));

        ThresholdSignatureVerifyRequest first = request();
        ThresholdSignatureVerifyRequest second = request();
        second.participantIds = Arrays.asList(4, 1, 2);

        VerificationResult firstResult = service.verify(first);
        VerificationResult secondResult = service.verify(second);

        assertEquals(firstResult.proofHash, secondResult.proofHash);
        assertEquals(
                firstResult.detail.get("participantSetHash"),
                secondResult.detail.get("participantSetHash"));
        assertEquals(
                firstResult.detail.get("canonicalPayloadHash"),
                secondResult.detail.get("canonicalPayloadHash"));
    }

    @Test
    void rejectsTooFewDuplicateAndOutOfRangeParticipantsBeforeVerifier() {
        ThresholdSignatureVerifyRequest tooFew = request();
        tooFew.participantIds = Arrays.asList(1, 2);
        assertEquals("ERROR", service.verify(tooFew).status);

        ThresholdSignatureVerifyRequest duplicate = request();
        duplicate.participantIds = Arrays.asList(1, 1, 2);
        assertEquals("ERROR", service.verify(duplicate).status);

        ThresholdSignatureVerifyRequest outOfRange = request();
        outOfRange.participantIds = Arrays.asList(1, 2, 6);
        assertEquals("ERROR", service.verify(outOfRange).status);

        verifyNoInteractions(verifier);
    }

    @Test
    void emptySignatureBundleReturnsErrorBeforeVerifier() {
        ThresholdSignatureVerifyRequest request = request();
        request.signatureBundle = new LinkedHashMap<>();

        VerificationResult result = service.verify(request);

        assertEquals("ERROR", result.status);
        assertEquals("THRESHOLD_SIGNATURE_VERIFY_ERROR", result.detail.get("errorCode"));
        assertTrue(String.valueOf(result.message).contains("signatureBundle"));
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
        request.signatureBundle.put("scheme", "FROST-ED25519-SHA512");
        request.signatureBundle.put("policyId", "traffic-consortium-v1");
        request.signatureBundle.put("aggregateSignature", "test-signature");
        return request;
    }
}
