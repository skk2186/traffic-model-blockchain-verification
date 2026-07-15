package com.traffic.wecross.crossverification.testsupport;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.traffic.wecross.crossverification.dto.ThresholdSignatureVerifyRequest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ThresholdSignatureTestFixtures {
    public static final String POLICY_ID = "traffic-test-v1";
    public static final String SCHEME = "ECDSA-P256-SHA256";
    public static final String MESSAGE = "traffic speed range approved";

    private final ObjectMapper objectMapper;
    private final Map<Integer, KeyPair> keyPairs;
    private final Path policyRoot;

    public ThresholdSignatureTestFixtures(ObjectMapper objectMapper, Path root) throws Exception {
        this.objectMapper = objectMapper;
        this.policyRoot = Files.createDirectories(root.resolve("policies"));
        this.keyPairs = generateKeyPairs(5);
        writePolicy(POLICY_ID, keyPairs, 3, 5);
    }

    public Path getPolicyRoot() {
        return policyRoot;
    }

    public Map<Integer, KeyPair> getKeyPairs() {
        return keyPairs;
    }

    public ThresholdSignatureVerifyRequest validRequest(Integer... participantIds) throws Exception {
        ThresholdSignatureVerifyRequest request = new ThresholdSignatureVerifyRequest();
        request.businessId = "traffic-threshold-test";
        request.message = MESSAGE;
        request.threshold = 3;
        request.totalNodes = 5;
        request.participantIds = ids(participantIds);
        request.signatureBundle = bundle(signatures(MESSAGE, participantIds));
        return request;
    }

    public Map<String, Object> bundle(Map<String, Object> signatures) {
        return bundle(POLICY_ID, SCHEME, signatures);
    }

    public Map<String, Object> bundle(String policyId, String scheme, Map<String, Object> signatures) {
        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("scheme", scheme);
        bundle.put("policyId", policyId);
        bundle.put("participantSignatures", signatures);
        return bundle;
    }

    public Map<String, Object> signatures(String message, Integer... participantIds) throws Exception {
        Map<String, Object> signatures = new LinkedHashMap<>();
        for (Integer participantId : participantIds) {
            signatures.put(String.valueOf(participantId), sign(message, keyPairs.get(participantId)));
        }
        return signatures;
    }

    public String sign(String message, KeyPair keyPair) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(message.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    public List<Integer> ids(Integer... values) {
        return Arrays.asList(values);
    }

    public void writePolicy(
            String policyId,
            Map<Integer, KeyPair> pairs,
            int threshold,
            int totalNodes) throws Exception {
        objectMapper.writerWithDefaultPrettyPrinter()
                .writeValue(policyRoot.resolve(policyId + ".json").toFile(),
                        policyDocument(policyId, SCHEME, pairs, threshold, totalNodes));
    }

    public void writeRawPolicy(String policyId, String content) throws Exception {
        Files.write(policyRoot.resolve(policyId + ".json"), content.getBytes("UTF-8"));
    }

    public Map<String, Object> policyDocument(
            String policyId,
            String scheme,
            Map<Integer, KeyPair> pairs,
            int threshold,
            int totalNodes) {
        Map<String, String> publicKeys = new LinkedHashMap<>();
        for (Map.Entry<Integer, KeyPair> entry : pairs.entrySet()) {
            publicKeys.put(String.valueOf(entry.getKey()), toPem(entry.getValue()));
        }
        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("policyId", policyId);
        policy.put("scheme", scheme);
        policy.put("threshold", threshold);
        policy.put("totalNodes", totalNodes);
        policy.put("publicKeys", publicKeys);
        return policy;
    }

    public String toPem(KeyPair keyPair) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(keyPair.getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----";
    }

    private Map<Integer, KeyPair> generateKeyPairs(int count) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        Map<Integer, KeyPair> pairs = new LinkedHashMap<>();
        for (int i = 1; i <= count; i++) {
            pairs.put(i, generator.generateKeyPair());
        }
        return pairs;
    }
}
