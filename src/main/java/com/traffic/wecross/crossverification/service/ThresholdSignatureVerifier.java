package com.traffic.wecross.crossverification.service;

import com.traffic.wecross.crossverification.config.ThresholdSignatureVerificationProperties;
import com.traffic.wecross.crossverification.threshold.ThresholdSignaturePolicy;
import com.traffic.wecross.crossverification.threshold.ThresholdSignaturePolicyLoader;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class ThresholdSignatureVerifier {
    private static final String ENGINE = "JAVA_SIGNATURE";
    private static final String MOCK_ENGINE = "STRUCTURAL_MOCK";

    private final ThresholdSignaturePolicyLoader policyLoader;
    private final ThresholdSignatureVerificationProperties properties;

    public ThresholdSignatureVerifier(
            ThresholdSignaturePolicyLoader policyLoader,
            ThresholdSignatureVerificationProperties properties) {
        this.policyLoader = policyLoader;
        this.properties = properties;
    }

    public VerificationDecision verify(
            String message,
            Integer threshold,
            Integer totalNodes,
            List<Integer> participantIds,
            Map<String, Object> signatureBundle) {
        if (properties.getMode() == ThresholdSignatureVerificationProperties.Mode.MOCK) {
            return verifyMock(threshold, totalNodes, participantIds, signatureBundle);
        }
        try {
            return verifyInternal(message, threshold, totalNodes, participantIds, signatureBundle);
        } catch (IllegalArgumentException e) {
            return VerificationDecision.fail(
                    null,
                    null,
                    0,
                    safeThreshold(threshold),
                    safeTotalNodes(totalNodes),
                    safeParticipants(participantIds),
                    Collections.emptyMap(),
                    e.getMessage());
        }
    }

    private VerificationDecision verifyMock(
            Integer threshold,
            Integer totalNodes,
            List<Integer> participantIds,
            Map<String, Object> signatureBundle) {
        if (!properties.isAllowLegacyMock()) {
            return VerificationDecision.fail(
                    null,
                    null,
                    0,
                    safeThreshold(threshold),
                    safeTotalNodes(totalNodes),
                    safeParticipants(participantIds),
                    Collections.emptyMap(),
                    "legacy mock threshold signature is disabled");
        }
        try {
            validateThreshold(threshold, totalNodes, participantIds);
            if (signatureBundle == null || signatureBundle.isEmpty()) {
                throw new IllegalArgumentException("signatureBundle must not be empty");
            }
            int count = mockSignatureCount(signatureBundle, participantIds);
            Map<String, Boolean> participantResults = new LinkedHashMap<>();
            for (Integer participantId : participantIds) {
                participantResults.put(String.valueOf(participantId), true);
            }
            if (count >= threshold) {
                return VerificationDecision.pass(
                        "MOCK",
                        stringField(signatureBundle, "policyId"),
                        count,
                        threshold,
                        totalNodes,
                        safeParticipants(participantIds),
                        participantResults,
                        "MOCK",
                        MOCK_ENGINE);
            }
            return VerificationDecision.fail(
                    "MOCK",
                    stringField(signatureBundle, "policyId"),
                    count,
                    threshold,
                    totalNodes,
                    safeParticipants(participantIds),
                    participantResults,
                    "mock signature count is less than threshold",
                    "MOCK",
                    MOCK_ENGINE);
        } catch (IllegalArgumentException e) {
            return VerificationDecision.fail(
                    "MOCK",
                    null,
                    0,
                    safeThreshold(threshold),
                    safeTotalNodes(totalNodes),
                    safeParticipants(participantIds),
                    Collections.emptyMap(),
                    e.getMessage(),
                    "MOCK",
                    MOCK_ENGINE);
        }
    }

    private VerificationDecision verifyInternal(
            String message,
            Integer threshold,
            Integer totalNodes,
            List<Integer> participantIds,
            Map<String, Object> signatureBundle) {
        requireText(message, "message");
        validateThreshold(threshold, totalNodes, participantIds);
        if (signatureBundle == null || signatureBundle.isEmpty()) {
            throw new IllegalArgumentException("signatureBundle must not be empty");
        }
        validateRealBundleFields(signatureBundle);

        String scheme = stringField(signatureBundle, "scheme");
        String policyId = stringField(signatureBundle, "policyId");
        if (!ThresholdSignaturePolicyLoader.SUPPORTED_SCHEME.equals(scheme)) {
            throw new IllegalArgumentException("signatureBundle scheme must be "
                    + ThresholdSignaturePolicyLoader.SUPPORTED_SCHEME);
        }
        requireText(policyId, "policyId");

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

        Map<Integer, String> signatures = participantSignatures(signatureBundle.get("participantSignatures"));
        validateParticipantSignatureSet(participantIds, signatures, totalNodes);

        Map<String, Boolean> participantResults = new LinkedHashMap<>();
        int validCount = 0;
        for (Integer participantId : participantIds) {
            PublicKey publicKey = policy.getPublicKey(participantId);
            boolean valid = verifyOne(message, signatures.get(participantId), publicKey);
            participantResults.put(String.valueOf(participantId), valid);
            if (valid) {
                validCount++;
            }
        }

        if (validCount >= threshold) {
            return VerificationDecision.pass(
                    scheme,
                    policyId,
                    validCount,
                    threshold,
                    totalNodes,
                    safeParticipants(participantIds),
                    participantResults);
        }
        return VerificationDecision.fail(
                scheme,
                policyId,
                validCount,
                threshold,
                totalNodes,
                safeParticipants(participantIds),
                participantResults,
                "valid signature count is less than threshold");
    }

    private void validateRealBundleFields(Map<String, Object> signatureBundle) {
        Set<String> expected = new LinkedHashSet<>();
        expected.add("scheme");
        expected.add("policyId");
        expected.add("participantSignatures");
        if (!signatureBundle.keySet().equals(expected)) {
            throw new IllegalArgumentException(
                    "signatureBundle may contain only scheme, policyId and participantSignatures in real mode");
        }
    }

    private int mockSignatureCount(Map<String, Object> signatureBundle, List<Integer> participantIds) {
        Object accepted = signatureBundle.get("valid");
        if (accepted instanceof Boolean && !((Boolean) accepted)) {
            return 0;
        }
        Object participantSignatures = signatureBundle.get("participantSignatures");
        if (participantSignatures instanceof Map) {
            return countPresentValues(((Map<?, ?>) participantSignatures).values());
        }
        Object signatures = signatureBundle.get("signatures");
        if (signatures instanceof List) {
            return countPresentValues((List<?>) signatures);
        }
        if (hasText(signatureBundle.get("aggregateSignature")) || hasText(signatureBundle.get("signature"))) {
            return participantIds == null ? 0 : participantIds.size();
        }
        return 0;
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

    private boolean verifyOne(String message, String signatureBase64, PublicKey publicKey) {
        try {
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(publicKey);
            signature.update(message.getBytes(StandardCharsets.UTF_8));
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }

    private Map<Integer, String> participantSignatures(Object value) {
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("participantSignatures must be an object");
        }
        Map<Integer, String> signatures = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
            Integer participantId = parseParticipantId(entry.getKey());
            String signature = entry.getValue() == null ? null : String.valueOf(entry.getValue()).trim();
            if (signature == null || signature.isEmpty()) {
                throw new IllegalArgumentException("participant signature must not be empty");
            }
            if (signatures.put(participantId, signature) != null) {
                throw new IllegalArgumentException("participantSignatures must not contain duplicate participant ids");
            }
        }
        return signatures;
    }

    private void validateParticipantSignatureSet(
            List<Integer> participantIds,
            Map<Integer, String> signatures,
            Integer totalNodes) {
        Set<Integer> requested = new LinkedHashSet<>(participantIds);
        Set<Integer> signed = new LinkedHashSet<>(signatures.keySet());
        if (!requested.equals(signed)) {
            throw new IllegalArgumentException("participantIds must match participantSignatures");
        }
        Set<String> uniqueSignatures = new LinkedHashSet<>();
        for (Map.Entry<Integer, String> entry : signatures.entrySet()) {
            Integer participantId = entry.getKey();
            if (participantId == null || participantId < 1 || participantId > totalNodes) {
                throw new IllegalArgumentException("participantSignatures contains participant outside totalNodes");
            }
            if (!uniqueSignatures.add(entry.getValue())) {
                throw new IllegalArgumentException("participantSignatures must not reuse the same signature");
            }
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

    private Integer parseParticipantId(Object value) {
        try {
            return Integer.valueOf(String.valueOf(value));
        } catch (Exception e) {
            throw new IllegalArgumentException("participantSignatures participant id must be numeric", e);
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

    private boolean hasText(Object value) {
        return value != null && !String.valueOf(value).trim().isEmpty();
    }

    private Integer safeThreshold(Integer threshold) {
        return threshold == null ? 0 : threshold;
    }

    private Integer safeTotalNodes(Integer totalNodes) {
        return totalNodes == null ? 0 : totalNodes;
    }

    private List<Integer> safeParticipants(List<Integer> participantIds) {
        return participantIds == null ? Collections.emptyList() : new ArrayList<>(participantIds);
    }

    public static class VerificationDecision {
        private final boolean passed;
        private final String scheme;
        private final String policyId;
        private final int validSignatureCount;
        private final int threshold;
        private final int totalNodes;
        private final List<Integer> participantIds;
        private final Map<String, Boolean> participantResults;
        private final String reason;
        private final String verifierMode;
        private final String verifierEngine;

        private VerificationDecision(
                boolean passed,
                String scheme,
                String policyId,
                int validSignatureCount,
                int threshold,
                int totalNodes,
                List<Integer> participantIds,
                Map<String, Boolean> participantResults,
                String reason,
                String verifierMode,
                String verifierEngine) {
            this.passed = passed;
            this.scheme = scheme;
            this.policyId = policyId;
            this.validSignatureCount = validSignatureCount;
            this.threshold = threshold;
            this.totalNodes = totalNodes;
            this.participantIds = Collections.unmodifiableList(new ArrayList<>(participantIds));
            this.participantResults = Collections.unmodifiableMap(new LinkedHashMap<>(participantResults));
            this.reason = reason;
            this.verifierMode = verifierMode;
            this.verifierEngine = verifierEngine;
        }

        public static VerificationDecision pass(
                String scheme,
                String policyId,
                int validSignatureCount,
                int threshold,
                int totalNodes,
                List<Integer> participantIds,
                Map<String, Boolean> participantResults) {
            return new VerificationDecision(
                    true, scheme, policyId, validSignatureCount, threshold, totalNodes,
                    participantIds, participantResults, null, "REAL", ENGINE);
        }

        public static VerificationDecision pass(
                String scheme,
                String policyId,
                int validSignatureCount,
                int threshold,
                int totalNodes,
                List<Integer> participantIds,
                Map<String, Boolean> participantResults,
                String verifierMode,
                String verifierEngine) {
            return new VerificationDecision(
                    true, scheme, policyId, validSignatureCount, threshold, totalNodes,
                    participantIds, participantResults, null, verifierMode, verifierEngine);
        }

        public static VerificationDecision fail(
                String scheme,
                String policyId,
                int validSignatureCount,
                int threshold,
                int totalNodes,
                List<Integer> participantIds,
                Map<String, Boolean> participantResults,
                String reason) {
            return new VerificationDecision(
                    false, scheme, policyId, validSignatureCount, threshold, totalNodes,
                    participantIds, participantResults, reason, "REAL", ENGINE);
        }

        public static VerificationDecision fail(
                String scheme,
                String policyId,
                int validSignatureCount,
                int threshold,
                int totalNodes,
                List<Integer> participantIds,
                Map<String, Boolean> participantResults,
                String reason,
                String verifierMode,
                String verifierEngine) {
            return new VerificationDecision(
                    false, scheme, policyId, validSignatureCount, threshold, totalNodes,
                    participantIds, participantResults, reason, verifierMode, verifierEngine);
        }

        public boolean isPassed() {
            return passed;
        }

        public String getVerifierMode() {
            return verifierMode;
        }

        public String getVerifierEngine() {
            return verifierEngine;
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

        public Map<String, Boolean> getParticipantResults() {
            return participantResults;
        }

        public String getReason() {
            return reason;
        }
    }
}
