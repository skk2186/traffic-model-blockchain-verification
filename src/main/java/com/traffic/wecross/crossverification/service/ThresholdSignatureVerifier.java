package com.traffic.wecross.crossverification.service;

import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Component;

@Component
public class ThresholdSignatureVerifier {
    public VerificationDecision verify(
            Integer threshold,
            List<Integer> participantIds,
            Map<String, Object> signatureBundle) {
        Object accepted = signatureBundle.get("valid");
        if (accepted instanceof Boolean && !((Boolean) accepted)) {
            return VerificationDecision.fail("signatureBundle verdict is not accepted");
        }

        Object participantSignatures = signatureBundle.get("participantSignatures");
        if (participantSignatures instanceof Map) {
            int count = countPresentValues(((Map<?, ?>) participantSignatures).values());
            return count >= threshold
                    ? VerificationDecision.pass()
                    : VerificationDecision.fail("participantSignatures count is less than threshold");
        }

        Object signatures = signatureBundle.get("signatures");
        if (signatures instanceof List) {
            int count = countPresentValues((List<?>) signatures);
            return count >= threshold
                    ? VerificationDecision.pass()
                    : VerificationDecision.fail("signatures count is less than threshold");
        }

        if (hasText(signatureBundle.get("aggregateSignature")) || hasText(signatureBundle.get("signature"))) {
            return participantIds.size() >= threshold
                    ? VerificationDecision.pass()
                    : VerificationDecision.fail("participant count is less than threshold");
        }

        return VerificationDecision.fail("signatureBundle must contain signature evidence");
    }

    private int countPresentValues(Iterable<?> values) {
        int count = 0;
        for (Object value : values) {
            if (hasText(value)) {
                count++;
            }
        }
        return count;
    }

    private boolean hasText(Object value) {
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
