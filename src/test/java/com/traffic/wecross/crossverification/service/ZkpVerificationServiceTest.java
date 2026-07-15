package com.traffic.wecross.crossverification.service;

import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.dto.ZkpVerifyRequest;
import com.traffic.wecross.crossverification.ledger.LedgerSyncResult;
import com.traffic.wecross.crossverification.ledger.VerificationLedgerService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ZkpVerificationServiceTest {
    private VerificationRecordService recordService;
    private VerificationLedgerService ledgerService;
    private Groth16ProofVerifier verifier;
    private ZkpVerificationService service;

    @BeforeEach
    void setUp() {
        recordService = new VerificationRecordService();
        ledgerService = mock(VerificationLedgerService.class);
        verifier = mock(Groth16ProofVerifier.class);
        service = new ZkpVerificationService(recordService, ledgerService, verifier);
        when(ledgerService.syncIfRequested(any(), any(), any())).thenReturn(LedgerSyncResult.disabled());
    }

    @Test
    void keepsUnifiedResultRecordAndLedgerFlowForRealPass() {
        when(verifier.verify(eq("traffic-speed-range-v1"), eq("traffic-speed-range-v1"), any(), any()))
                .thenReturn(Groth16ProofVerifier.VerificationDecision.pass(
                        "REAL", "ZOKRATES_CLI", "traffic-speed-range-v1", "traffic-speed-range-v1",
                        "g16", "bn128", "proof accepted", 18L, 0));

        ZkpVerifyRequest request = request();
        request.writeLedger = true;
        VerificationResult result = service.verify(request);

        assertEquals("PASS", result.status);
        assertEquals("ZKP", result.verifyType);
        assertEquals("Groth16", result.algorithm);
        assertNotNull(result.recordId);
        assertNotNull(result.inputHash);
        assertNotNull(result.proofHash);
        assertEquals("REAL", result.detail.get("verifierMode"));
        assertEquals("ZOKRATES_CLI", result.detail.get("verifierEngine"));
        assertEquals("traffic-speed-range-v1", result.detail.get("verifyingKeyId"));
        assertEquals("proof accepted", result.detail.get("reason"));
        assertNotNull(recordService.getRecordDetail(result.recordId));
        verify(ledgerService).syncIfRequested(any(), eq(Boolean.TRUE), any());
    }

    @Test
    void mapsStableVerifierFailureToFailWithoutChangingResultShape() {
        when(verifier.verify(eq("traffic-speed-range-v1"), eq("explicit-key"), any(), any()))
                .thenReturn(Groth16ProofVerifier.VerificationDecision.fail(
                        "REAL", "ZOKRATES_CLI", "explicit-key", "traffic-speed-range-v1",
                        "g16", "bn128", "PROOF_REJECTED", "proof was rejected by ZoKrates", 9L, 0));

        ZkpVerifyRequest request = request();
        request.verifyingKeyId = "explicit-key";
        VerificationResult result = service.verify(request);

        assertEquals("FAIL", result.status);
        assertEquals("PROOF_REJECTED", result.detail.get("reason"));
        assertEquals("proof was rejected by ZoKrates", result.detail.get("reasonMessage"));
        assertEquals(0, result.detail.get("exitCode"));
        assertNotNull(recordService.getRecordDetail(result.recordId));
        verify(ledgerService).syncIfRequested(any(), eq(null), any());
    }

    @Test
    void zkp005FailsWhenOnlyPublicInputHashIsProvidedWithoutPublicSignals() {
        when(verifier.verify(eq("traffic-speed-range-v1"), eq("traffic-speed-range-v1"), any(), eq(null)))
                .thenReturn(Groth16ProofVerifier.VerificationDecision.fail(
                        "REAL", "ZOKRATES_CLI", "traffic-speed-range-v1", "traffic-speed-range-v1",
                        "g16", "bn128", "PUBLIC_SIGNALS_MISSING",
                        "publicSignals must not be empty in real verification mode", 0L, null));

        ZkpVerifyRequest request = request();
        request.publicSignals = null;
        request.publicInputHash = "ace3ce97526e2207675b0f611e31fd1717e4d3aad58d3358d952faaa99fea215";

        VerificationResult result = service.verify(request);

        assertEquals("FAIL", result.status);
        assertEquals("PUBLIC_SIGNALS_MISSING", result.detail.get("reason"));
        assertEquals(request.publicInputHash, result.inputHash);
        assertNotNull(result.recordId);
        assertNotNull(recordService.getRecordDetail(result.recordId));
        verify(ledgerService).syncIfRequested(any(), eq(null), any());
    }

    private ZkpVerifyRequest request() {
        ZkpVerifyRequest request = new ZkpVerifyRequest();
        request.businessId = "traffic-proof-test";
        request.circuitId = "traffic-speed-range-v1";
        request.proof = new LinkedHashMap<String, Object>();
        ((LinkedHashMap<String, Object>) request.proof).put("native", true);
        request.publicSignals = Arrays.asList(30, 80);
        return request;
    }
}
