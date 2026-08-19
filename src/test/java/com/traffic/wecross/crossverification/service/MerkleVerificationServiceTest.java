package com.traffic.wecross.crossverification.service;

import com.traffic.wecross.crossverification.dto.MerkleVerifyRequest;
import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.ledger.TrustedLedgerService;
import com.traffic.wecross.crossverification.ledger.VerificationLedgerService;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MerkleVerificationServiceTest {
    private final MerkleVerificationService service = new MerkleVerificationService(
            new VerificationRecordService(),
            new VerificationLedgerService(new TrustedLedgerService(null)));

    @Test
    void acceptsDifferentSupportedSourceAndVerificationChains() {
        MerkleVerifyRequest request = request("bcos3", "chainmaker");

        VerificationResult result = service.verify(request);

        assertEquals("PASS", result.status);
        assertEquals("bcos3", result.detail.get("sourceChain"));
        assertEquals("chainmaker", result.detail.get("verificationChain"));
    }

    @Test
    void rejectsSameSourceAndVerificationChain() {
        VerificationResult result = service.verify(request("fabric", "fabric"));

        assertEquals("ERROR", result.status);
        assertEquals(
                "sourceChain and verificationChain must be different",
                result.detail.get("errorMessage"));
    }

    @Test
    void rejectsUnsupportedChain() {
        VerificationResult result = service.verify(request("bcos3", "unknown"));

        assertEquals("ERROR", result.status);
        assertEquals(
                "sourceChain and verificationChain must be bcos3, fabric or chainmaker",
                result.detail.get("errorMessage"));
    }

    private MerkleVerifyRequest request(String sourceChain, String verificationChain) {
        MerkleVerifyRequest request = new MerkleVerifyRequest();
        request.businessId = "traffic-chain-selection-test";
        request.leafItems = Arrays.asList("speed=42", "speed=38", "speed=51");
        request.sourceChain = sourceChain;
        request.verificationChain = verificationChain;
        request.writeLedger = false;
        return request;
    }
}
