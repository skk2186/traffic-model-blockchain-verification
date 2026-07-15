package com.traffic.wecross.crossverification.threshold;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

@Component
public class ThresholdSignaturePolicyLoader {
    public static final String SUPPORTED_SCHEME = "ECDSA-P256-SHA256";
    private static final Pattern SAFE_ID = Pattern.compile("^[A-Za-z0-9._-]+$");
    private static final String DEFAULT_POLICY_ROOT = "config/threshold";

    private final ObjectMapper objectMapper;
    private final PemPublicKeyParser publicKeyParser;
    private final Path policyRoot;

    @Autowired
    public ThresholdSignaturePolicyLoader(ObjectMapper objectMapper) {
        this(objectMapper, Paths.get(DEFAULT_POLICY_ROOT), new PemPublicKeyParser());
    }

    public ThresholdSignaturePolicyLoader(ObjectMapper objectMapper, Path policyRoot) {
        this(objectMapper, policyRoot, new PemPublicKeyParser());
    }

    public ThresholdSignaturePolicyLoader(
            ObjectMapper objectMapper,
            Path policyRoot,
            PemPublicKeyParser publicKeyParser) {
        this.objectMapper = objectMapper;
        this.publicKeyParser = publicKeyParser;
        this.policyRoot = policyRoot;
    }

    public ThresholdSignaturePolicy load(String policyId) {
        validatePolicyId(policyId);
        Path policyPath = resolvePolicyPath(policyId);
        PolicyDocument document;
        try {
            document = objectMapper.readValue(
                    policyPath.toFile(),
                    new TypeReference<PolicyDocument>() { });
        } catch (Exception e) {
            throw new IllegalArgumentException("threshold policy could not be read: " + policyId, e);
        }
        validateDocument(policyId, document);

        Map<Integer, PublicKey> publicKeys = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : document.publicKeys.entrySet()) {
            Integer participantId = parseParticipantId(entry.getKey());
            if (participantId < 1 || participantId > document.totalNodes) {
                throw new IllegalArgumentException("threshold policy contains participant outside totalNodes");
            }
            if (publicKeys.containsKey(participantId)) {
                throw new IllegalArgumentException("threshold policy contains duplicate participant id");
            }
            try {
                publicKeys.put(participantId, publicKeyParser.parse(entry.getValue()));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("threshold policy public key is invalid for participant "
                        + participantId, e);
            }
        }
        for (int participantId = 1; participantId <= document.totalNodes; participantId++) {
            if (!publicKeys.containsKey(participantId)) {
                throw new IllegalArgumentException("threshold policy missing public key for participant "
                        + participantId);
            }
        }
        return new ThresholdSignaturePolicy(
                document.policyId,
                document.scheme,
                document.threshold,
                document.totalNodes,
                publicKeys);
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
        if (document.publicKeys == null || document.publicKeys.size() != document.totalNodes) {
            throw new IllegalArgumentException("threshold policy publicKeys size must equal totalNodes");
        }
    }

    private Integer parseParticipantId(String value) {
        try {
            return Integer.valueOf(value);
        } catch (Exception e) {
            throw new IllegalArgumentException("threshold policy participant id must be numeric", e);
        }
    }

    static class PolicyDocument {
        public String policyId;
        public String scheme;
        public Integer threshold;
        public Integer totalNodes;
        public Map<String, String> publicKeys;
    }
}
