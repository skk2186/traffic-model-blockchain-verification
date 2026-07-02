package com.traffic.wecross.crossverification.service;

import java.util.Map;

import org.springframework.stereotype.Component;

@Component
public class Groth16ProofVerifier {
    public VerificationDecision verify(Object proof, Object publicSignals, boolean publicInputAvailable) {
        if (!(proof instanceof Map) || ((Map<?, ?>) proof).isEmpty()) {
            return VerificationDecision.fail("proof must contain Groth16 proof elements");
        }
        Map<?, ?> proofMap = (Map<?, ?>) proof;
        if (!hasProofElement(proofMap, "piA") || !hasProofElement(proofMap, "piB") || !hasProofElement(proofMap, "piC")) {
            return VerificationDecision.fail("proof must contain piA, piB and piC");
        }
        if (publicSignals == null && !publicInputAvailable) {
            return VerificationDecision.fail("publicSignals or publicInputHash must contain verifiable content");
        }
        Object verdict = proofMap.get("valid");
        if (verdict instanceof Boolean && !((Boolean) verdict)) {
            return VerificationDecision.fail("proof verdict is not accepted");
        }
        return VerificationDecision.pass();
    }

    private boolean hasProofElement(Map<?, ?> proof, String key) {
        Object value = proof.get(key);
        return value != null && !String.valueOf(value).trim().isEmpty();
    }

    public static class VerificationDecision {
        private final boolean passed;
        private final String reason;

        private VerificationDecision(boolean passed, String reason) {
            this.passed = passed;
            this.reason = reason;
        }

        public static VerificationDecision pass() {
            return new VerificationDecision(true, null);
        }

        public static VerificationDecision fail(String reason) {
            return new VerificationDecision(false, reason);
        }

        public boolean isPassed() {
            return passed;
        }

        public String getReason() {
            return reason;
        }
    }
}
