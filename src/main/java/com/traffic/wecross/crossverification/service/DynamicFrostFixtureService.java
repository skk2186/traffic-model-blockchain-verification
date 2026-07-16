package com.traffic.wecross.crossverification.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.traffic.wecross.crossverification.dto.ThresholdSignatureFixtureRequest;
import com.traffic.wecross.crossverification.threshold.ThresholdSignaturePolicy;
import com.traffic.wecross.crossverification.threshold.ThresholdSignaturePolicyLoader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class DynamicFrostFixtureService {
    private static final int MAX_OUTPUT_BYTES = 1024 * 1024;

    private final ObjectMapper objectMapper;
    private final ThresholdSignaturePolicyLoader policyLoader;
    private final Path executable;
    private final long timeoutMillis;
    private final int maxTotalNodes;

    public DynamicFrostFixtureService(
            ObjectMapper objectMapper,
            ThresholdSignaturePolicyLoader policyLoader,
            @Value("${verification.threshold-signature.fixture-generator-executable:tools/frost-fixture-generator/target/release/wecross-frost-fixture.exe}") String executable,
            @Value("${verification.threshold-signature.fixture-generator-timeout-millis:120000}") long timeoutMillis,
            @Value("${verification.threshold-signature.fixture-generator-max-nodes:500}") int maxTotalNodes) {
        this.objectMapper = objectMapper;
        this.policyLoader = policyLoader;
        this.executable = Paths.get(executable).toAbsolutePath().normalize();
        this.timeoutMillis = timeoutMillis;
        this.maxTotalNodes = maxTotalNodes;
    }

    public Map<String, Object> generate(ThresholdSignatureFixtureRequest request) {
        validate(request);
        List<Integer> participants = new ArrayList<>(request.participantIds);
        Collections.sort(participants);
        String policyId = "dynamic-frost-" + request.threshold + "of" + request.totalNodes + "-"
                + UUID.randomUUID().toString().replace("-", "");

        if (!Files.isRegularFile(executable)) {
            throw new IllegalArgumentException("FROST fixture generator executable not found: " + executable);
        }

        List<String> command = new ArrayList<>();
        command.add(executable.toString());
        command.add("--policy-id");
        command.add(policyId);
        command.add("--business-id-base64");
        command.add(base64(request.businessId));
        command.add("--message-base64");
        command.add(base64(request.message));
        command.add("--threshold");
        command.add(String.valueOf(request.threshold));
        command.add("--total-nodes");
        command.add(String.valueOf(request.totalNodes));
        command.add("--participants");
        command.add(join(participants));

        Process process = null;
        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.directory(executable.getParent().toFile());
            builder.redirectErrorStream(true);
            process = builder.start();
            if (!process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                throw new IllegalArgumentException("dynamic FROST signing timed out");
            }
            byte[] output = readBounded(process.getInputStream());
            String text = new String(output, StandardCharsets.UTF_8).trim();
            if (process.exitValue() != 0) {
                throw new IllegalArgumentException("dynamic FROST signing failed: " + text);
            }
            Map<String, Object> result = objectMapper.readValue(
                    text, new TypeReference<Map<String, Object>>() { });
            registerPolicy(result, policyId, request.threshold, request.totalNodes);
            return result;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("dynamic FROST signing could not be executed", e);
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    private void registerPolicy(
            Map<String, Object> result, String expectedPolicyId, int threshold, int totalNodes) {
        Object policyValue = result.get("policy");
        if (!(policyValue instanceof Map)) {
            throw new IllegalArgumentException("dynamic FROST output is missing policy");
        }
        Map<?, ?> policy = (Map<?, ?>) policyValue;
        String policyId = String.valueOf(policy.get("policyId"));
        String scheme = String.valueOf(policy.get("scheme"));
        String publicKeyText = String.valueOf(policy.get("groupPublicKey"));
        if (!expectedPolicyId.equals(policyId)) {
            throw new IllegalArgumentException("dynamic FROST policyId mismatch");
        }
        byte[] groupPublicKey;
        try {
            groupPublicKey = Base64.getDecoder().decode(publicKeyText);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("dynamic FROST group public key is invalid", e);
        }
        policyLoader.registerDynamicPolicy(new ThresholdSignaturePolicy(
                policyId, scheme, threshold, totalNodes, groupPublicKey));
    }

    private void validate(ThresholdSignatureFixtureRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        requireText(request.businessId, "businessId");
        requireText(request.message, "message");
        if (request.totalNodes == null || request.totalNodes < 2 || request.totalNodes > maxTotalNodes) {
            throw new IllegalArgumentException("totalNodes must be between 2 and " + maxTotalNodes);
        }
        if (request.threshold == null || request.threshold < 2 || request.threshold > request.totalNodes) {
            throw new IllegalArgumentException("threshold must be between 2 and totalNodes");
        }
        if (request.participantIds == null || request.participantIds.size() < request.threshold) {
            throw new IllegalArgumentException("participant count must be greater than or equal to threshold");
        }
        Set<Integer> unique = new HashSet<>();
        for (Integer participantId : request.participantIds) {
            if (participantId == null || participantId < 1 || participantId > request.totalNodes) {
                throw new IllegalArgumentException("participantId must be between 1 and totalNodes");
            }
            if (!unique.add(participantId)) {
                throw new IllegalArgumentException("participantIds must not contain duplicates");
            }
        }
    }

    private void requireText(String value, String name) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(name + " must not be empty");
        }
    }

    private String base64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private String join(List<Integer> values) {
        StringBuilder output = new StringBuilder();
        for (Integer value : values) {
            if (output.length() > 0) {
                output.append(',');
            }
            output.append(value);
        }
        return output.toString();
    }

    private byte[] readBounded(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = input.read(buffer)) != -1) {
            if (output.size() + read > MAX_OUTPUT_BYTES) {
                throw new IllegalArgumentException("dynamic FROST output exceeded size limit");
            }
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }
}
