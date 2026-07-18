package com.traffic.wecross.crossverification.testsupport;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.traffic.wecross.crossverification.dto.ThresholdSignatureVerifyRequest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ThresholdSignatureTestFixtures {
    public static final String POLICY_ID = "traffic-consortium-frost-v1";
    public static final String SCHEME = "FROST-ED25519-SHA512";
    public static final String BUSINESS_ID = "traffic-threshold-frost-test";
    public static final String MESSAGE = "traffic speed range approved";
    public static final String GROUP_PUBLIC_KEY =
            "n2yyWrYKFQexB5LByQRcyWNIu9pKNiaiQ1VIhNf2blw=";
    public static final String AGGREGATE_SIGNATURE =
            "zEnSm9HxSLxWLIsrzjXf/udXHcU0u5wfQCR+sBJn4wY5CDl5m/Atzx8Y4scqlyQJpFWjetzckKWUCK35xcsnDw==";

    private final ObjectMapper objectMapper;
    private final Path policyRoot;

    public ThresholdSignatureTestFixtures(ObjectMapper objectMapper, Path root) throws Exception {
        this.objectMapper = objectMapper;
        this.policyRoot = Files.createDirectories(root.resolve("policies"));
        writePolicy(POLICY_ID, SCHEME, 3, 5, GROUP_PUBLIC_KEY);
    }

    public Path getPolicyRoot() {
        return policyRoot;
    }

    public ThresholdSignatureVerifyRequest validRequest() {
        ThresholdSignatureVerifyRequest request = new ThresholdSignatureVerifyRequest();
        request.businessId = BUSINESS_ID;
        request.message = MESSAGE;
        request.threshold = 3;
        request.totalNodes = 5;
        request.participantIds = ids(1, 2, 4);
        request.signatureBundle = bundle(POLICY_ID, SCHEME, AGGREGATE_SIGNATURE);
        return request;
    }

    public Map<String, Object> bundle(
            String policyId, String scheme, String aggregateSignature) {
        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("scheme", scheme);
        bundle.put("policyId", policyId);
        bundle.put("aggregateSignature", aggregateSignature);
        return bundle;
    }

    public List<Integer> ids(Integer... values) {
        return Arrays.asList(values);
    }

    public void writePolicy(
            String policyId,
            String scheme,
            int threshold,
            int totalNodes,
            String groupPublicKey) throws Exception {
        objectMapper.writerWithDefaultPrettyPrinter()
                .writeValue(
                        policyRoot.resolve(policyId + ".json").toFile(),
                        policyDocument(
                                policyId, scheme, threshold, totalNodes, groupPublicKey));
    }

    public void writeRawPolicy(String policyId, String content) throws Exception {
        Files.write(policyRoot.resolve(policyId + ".json"), content.getBytes("UTF-8"));
    }

    public Map<String, Object> policyDocument(
            String policyId,
            String scheme,
            int threshold,
            int totalNodes,
            String groupPublicKey) {
        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("policyId", policyId);
        policy.put("scheme", scheme);
        policy.put("threshold", threshold);
        policy.put("totalNodes", totalNodes);
        policy.put("groupPublicKey", groupPublicKey);
        return policy;
    }
}
