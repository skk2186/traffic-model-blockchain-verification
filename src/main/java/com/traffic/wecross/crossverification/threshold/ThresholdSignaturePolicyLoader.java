package com.traffic.wecross.crossverification.threshold;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@Component
public class ThresholdSignaturePolicyLoader {
    public static final String SUPPORTED_SCHEME = "FROST-ED25519-SHA512";
    private static final int ED25519_PUBLIC_KEY_BYTES = 32;
    private static final Pattern SAFE_ID = Pattern.compile("^[A-Za-z0-9._-]+$");
    private static final String DEFAULT_POLICY_ROOT = "config/threshold";

    private final ObjectMapper objectMapper;
    private final Path policyRoot;
    private final Map<String, ThresholdSignaturePolicy> dynamicPolicies = new ConcurrentHashMap<>();

    @Autowired
    public ThresholdSignaturePolicyLoader(ObjectMapper objectMapper) {
        this(objectMapper, Paths.get(DEFAULT_POLICY_ROOT));
    }

    public ThresholdSignaturePolicyLoader(ObjectMapper objectMapper, Path policyRoot) {
        this.objectMapper = objectMapper;
        this.policyRoot = policyRoot;
    }

    public ThresholdSignaturePolicy load(String policyId) {
        validatePolicyId(policyId);
        ThresholdSignaturePolicy dynamicPolicy = dynamicPolicies.get(policyId);
        if (dynamicPolicy != null) {
            return dynamicPolicy;
        }
        Path policyPath = resolvePolicyPath(policyId);
        PolicyDocument document;
        try {
            document = objectMapper.readValue(policyPath.toFile(), PolicyDocument.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("threshold policy could not be read: " + policyId, e);
        }
        validateDocument(policyId, document);
        byte[] groupPublicKey;
        try {
            groupPublicKey = Base64.getDecoder().decode(document.groupPublicKey);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("threshold policy groupPublicKey must be valid Base64", e);
        }
        if (groupPublicKey.length != ED25519_PUBLIC_KEY_BYTES) {
            throw new IllegalArgumentException("threshold policy groupPublicKey must decode to 32 bytes");
        }
        return new ThresholdSignaturePolicy(
                document.policyId,
                document.scheme,
                document.threshold,
                document.totalNodes,
                groupPublicKey);
    }

    public void registerDynamicPolicy(ThresholdSignaturePolicy policy) {
        if (policy == null) {
            throw new IllegalArgumentException("threshold policy must not be null");
        }
        validatePolicyId(policy.getPolicyId());
        if (!SUPPORTED_SCHEME.equals(policy.getScheme())) {
            throw new IllegalArgumentException("threshold policy scheme must be " + SUPPORTED_SCHEME);
        }
        if (policy.getThreshold() < 2 || policy.getThreshold() > policy.getTotalNodes()) {
            throw new IllegalArgumentException("dynamic threshold policy is invalid");
        }
        if (policy.getGroupPublicKey().length != ED25519_PUBLIC_KEY_BYTES) {
            throw new IllegalArgumentException("threshold policy groupPublicKey must decode to 32 bytes");
        }
        dynamicPolicies.put(policy.getPolicyId(), policy);
    }

    public void validatePolicyId(String policyId) {
        if (policyId == null || policyId.trim().isEmpty()) {
            throw new IllegalArgumentException("policyId must not be empty");
        }
        String value = policyId.trim();
        if (!SAFE_ID.matcher(value).matches()
                || value.contains("..")
                || value.contains("/")
                || value.contains("\\")
                || Paths.get(value).isAbsolute()) {
            throw new IllegalArgumentException("policyId is invalid");
        }
    }

    private Path resolvePolicyPath(String policyId) {
        try {
            Path root = policyRoot.toAbsolutePath().normalize();
            Path target = root.resolve(policyId + ".json").normalize();
            if (!target.startsWith(root)) {
                throw new IllegalArgumentException("policyId resolves outside policy root");
            }
            if (!Files.isRegularFile(target)) {
                throw new IllegalArgumentException("threshold policy not found: " + policyId);
            }
            Path realRoot = root.toRealPath();
            Path realTarget = target.toRealPath();
            if (!realTarget.startsWith(realRoot)) {
                throw new IllegalArgumentException("threshold policy resolves outside policy root");
            }
            return realTarget;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("threshold policy path could not be resolved: " + policyId, e);
        }
    }

    private void validateDocument(String requestedPolicyId, PolicyDocument document) {
        if (document == null) {
            throw new IllegalArgumentException("threshold policy must not be empty");
        }
        if (!requestedPolicyId.equals(document.policyId)) {
            throw new IllegalArgumentException("threshold policyId does not match request");
        }
        if (!SUPPORTED_SCHEME.equals(document.scheme)) {
            throw new IllegalArgumentException("threshold policy scheme must be " + SUPPORTED_SCHEME);
        }
        if (document.threshold == null || document.threshold < 1) {
            throw new IllegalArgumentException("threshold policy threshold must be greater than 0");
        }
        if (document.totalNodes == null || document.totalNodes < 1) {
            throw new IllegalArgumentException("threshold policy totalNodes must be greater than 0");
        }
        if (document.threshold > document.totalNodes) {
            throw new IllegalArgumentException("threshold policy threshold must be less than or equal to totalNodes");
        }
        if (document.groupPublicKey == null || document.groupPublicKey.trim().isEmpty()) {
            throw new IllegalArgumentException("threshold policy groupPublicKey must not be empty");
        }
    }

    static class PolicyDocument {
        public String policyId;
        public String scheme;
        public Integer threshold;
        public Integer totalNodes;
        public String groupPublicKey;
    }
}
