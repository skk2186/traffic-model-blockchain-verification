package com.traffic.wecross.crossverification.service;

import com.traffic.wecross.crossverification.config.ThresholdSignatureVerificationProperties;
import com.traffic.wecross.crossverification.threshold.ThresholdSignatureMessage;
import com.traffic.wecross.crossverification.threshold.ThresholdSignaturePolicy;
import com.traffic.wecross.crossverification.threshold.ThresholdSignaturePolicyLoader;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class ThresholdSignatureVerifier {
    public static final String ENGINE = "BOUNCY_CASTLE_ED25519_RFC8032";
    private static final int ED25519_SIGNATURE_BYTES = 64;

    private final ThresholdSignaturePolicyLoader policyLoader;
    private final ThresholdSignatureVerificationProperties properties;

    public ThresholdSignatureVerifier(
            ThresholdSignaturePolicyLoader policyLoader,
            ThresholdSignatureVerificationProperties properties) {
        this.policyLoader = policyLoader;
        this.properties = properties;
    }

    public VerificationDecision verify(
            String businessId,
            String message,
            Integer threshold,
            Integer totalNodes,
            List<Integer> participantIds,
            Map<String, Object> signatureBundle) {
        try {
            if (properties.getMode() != ThresholdSignatureVerificationProperties.Mode.REAL) {
                throw new IllegalArgumentException(
                        "mock threshold signatures are disabled; use a FROST aggregate signature");
            }
            return verifyInternal(
                    businessId, message, threshold, totalNodes, participantIds, signatureBundle);
        } catch (IllegalArgumentException e) {
            return VerificationDecision.fail(
                    null,
                    null,
                    safeThreshold(threshold),
                    safeTotalNodes(totalNodes),
                    safeParticipants(participantIds),
                    e.getMessage());
        }
    }

    private VerificationDecision verifyInternal(
            String businessId,
            String message,
            Integer threshold,
            Integer totalNodes,
            List<Integer> participantIds,
            Map<String, Object> signatureBundle) {
        requireText(businessId, "businessId");
        requireText(message, "message");
        validateThreshold(threshold, totalNodes, participantIds);
        if (signatureBundle == null || signatureBundle.isEmpty()) {
            throw new IllegalArgumentException("signatureBundle must not be empty");
        }
        validateBundleFields(signatureBundle);

        String scheme = stringField(signatureBundle, "scheme");
        String policyId = stringField(signatureBundle, "policyId");
        String aggregateSignature = stringField(signatureBundle, "aggregateSignature");
        if (!ThresholdSignaturePolicyLoader.SUPPORTED_SCHEME.equals(scheme)) {
            throw new IllegalArgumentException("signatureBundle scheme must be "
                    + ThresholdSignaturePolicyLoader.SUPPORTED_SCHEME);
        }
        requireText(policyId, "policyId");
        requireText(aggregateSignature, "aggregateSignature");

        ThresholdSignaturePolicy policy = policyLoader.load(policyId);
        if (!scheme.equals(policy.getScheme())) {
            throw new IllegalArgumentException("signatureBundle scheme does not match policy");
        }
        if (threshold.intValue() != policy.getThreshold()) {
            throw new IllegalArgumentException("request threshold does not match policy");
        }
        if (totalNodes.intValue() != policy.getTotalNodes()) {
            throw new IllegalArgumentException("request totalNodes does not match policy");
        }

        byte[] signatureBytes = decodeSignature(aggregateSignature);
        byte[] payload = ThresholdSignatureMessage.encode(
                policyId,
                businessId,
                threshold,
                totalNodes,
                participantIds,
                message);
        boolean verified = verifyAggregateSignature(payload, signatureBytes, policy.getGroupPublicKey());
        if (verified) {
            return VerificationDecision.pass(
                    scheme,
                    policyId,
                    threshold,
                    totalNodes,
                    safeParticipants(participantIds));
        }
        return VerificationDecision.fail(
                scheme,
                policyId,
                threshold,
                totalNodes,
                safeParticipants(participantIds),
                "FROST aggregate signature verification failed");
    }

    private void validateBundleFields(Map<String, Object> signatureBundle) {
        Set<String> expected = new LinkedHashSet<>();
        expected.add("scheme");
        expected.add("policyId");
        expected.add("aggregateSignature");
        if (!signatureBundle.keySet().equals(expected)) {
            throw new IllegalArgumentException(
                    "signatureBundle may contain only scheme, policyId and aggregateSignature");
        }
    }

    private byte[] decodeSignature(String aggregateSignature) {
        byte[] signatureBytes;
        try {
            signatureBytes = Base64.getDecoder().decode(aggregateSignature);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("aggregateSignature must be valid Base64", e);
        }
        if (signatureBytes.length != ED25519_SIGNATURE_BYTES) {
            throw new IllegalArgumentException("aggregateSignature must decode to 64 bytes");
        }
        return signatureBytes;
    }

    private boolean verifyAggregateSignature(byte[] message, byte[] signature, byte[] groupPublicKey) {
        try {
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, new Ed25519PublicKeyParameters(groupPublicKey, 0));
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(signature);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private void validateThreshold(Integer threshold, Integer totalNodes, List<Integer> participantIds) {
        if (threshold == null || threshold < 1) {
            throw new IllegalArgumentException("threshold must be greater than 0");
        }
        if (totalNodes == null || totalNodes < 1) {
            throw new IllegalArgumentException("totalNodes must be greater than 0");
        }
        if (threshold > totalNodes) {
            throw new IllegalArgumentException("threshold must be less than or equal to totalNodes");
        }
        if (participantIds == null || participantIds.isEmpty()) {
            throw new IllegalArgumentException("participantIds must not be empty");
        }
        if (participantIds.size() < threshold) {
            throw new IllegalArgumentException("participantIds count must be greater than or equal to threshold");
        }
        Set<Integer> seen = new LinkedHashSet<>();
        for (Integer participantId : participantIds) {
            if (participantId == null || participantId < 1 || participantId > totalNodes) {
                throw new IllegalArgumentException("participantId must be between 1 and totalNodes");
            }
            if (!seen.add(participantId)) {
                throw new IllegalArgumentException("participantIds must not contain duplicate values");
            }
        }
    }

    private String stringField(Map<String, Object> signatureBundle, String fieldName) {
        Object value = signatureBundle.get(fieldName);
        return value == null ? null : String.valueOf(value).trim();
    }

    private void requireText(String value, String fieldName) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(fieldName + " must not be empty");
        }
    }

    private int safeThreshold(Integer threshold) {
        return threshold == null ? 0 : threshold;
    }

    private int safeTotalNodes(Integer totalNodes) {
        return totalNodes == null ? 0 : totalNodes;
    }

    private List<Integer> safeParticipants(List<Integer> participantIds) {
        if (participantIds == null) {
            return Collections.emptyList();
        }
        List<Integer> normalized = new ArrayList<>(participantIds);
        Collections.sort(normalized);
        return normalized;
    }

    public static class VerificationDecision {
        private final boolean passed;
        private final boolean aggregateSignatureVerified;
        private final String scheme;
        private final String policyId;
        private final int validSignatureCount;
        private final int threshold;
        private final int totalNodes;
        private final List<Integer> participantIds;
        private final String reason;

        private VerificationDecision(
                boolean passed,
                String scheme,
                String policyId,
                int validSignatureCount,
                int threshold,
                int totalNodes,
                List<Integer> participantIds,
                String reason) {
            this.passed = passed;
            this.aggregateSignatureVerified = passed;
            this.scheme = scheme;
            this.policyId = policyId;
            this.validSignatureCount = validSignatureCount;
            this.threshold = threshold;
            this.totalNodes = totalNodes;
            this.participantIds = Collections.unmodifiableList(new ArrayList<>(participantIds));
            this.reason = reason;
        }

        public static VerificationDecision pass(
                String scheme,
                String policyId,
                int threshold,
                int totalNodes,
                List<Integer> participantIds) {
            return new VerificationDecision(
                    true, scheme, policyId, participantIds.size(), threshold, totalNodes,
                    participantIds, null);
        }

        public static VerificationDecision fail(
                String scheme,
                String policyId,
                int threshold,
                int totalNodes,
                List<Integer> participantIds,
                String reason) {
            return new VerificationDecision(
                    false, scheme, policyId, 0, threshold, totalNodes,
                    participantIds, reason);
        }

        public boolean isPassed() {
            return passed;
        }

        public boolean isAggregateSignatureVerified() {
            return aggregateSignatureVerified;
        }

        public String getVerifierMode() {
            return "REAL";
        }

        public String getVerifierEngine() {
            return ENGINE;
        }

        public String getScheme() {
            return scheme;
        }

        public String getPolicyId() {
            return policyId;
        }

        public int getValidSignatureCount() {
            return validSignatureCount;
        }

        public int getThreshold() {
            return threshold;
        }

        public int getTotalNodes() {
            return totalNodes;
        }

        public List<Integer> getParticipantIds() {
            return participantIds;
        }

        public String getReason() {
            return reason;
        }
    }
}
