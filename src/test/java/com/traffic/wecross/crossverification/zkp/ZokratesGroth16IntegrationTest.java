package com.traffic.wecross.crossverification.zkp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.traffic.wecross.crossverification.config.ZkpVerificationProperties;
import com.traffic.wecross.crossverification.service.Groth16ProofVerifier;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("integration")
@Tag("zokrates")
@Tag("real-crypto")
class ZokratesGroth16IntegrationTest {
    @TempDir
    Path tempDirectory;

    @Test
    void verifiesRealFixturesAndConcurrentRequests() throws Exception {
        Assumptions.assumeTrue(Boolean.getBoolean("zokrates.integration"));
        Path projectRoot = Paths.get("").toAbsolutePath().normalize();
        Path executable = zokratesExecutableFromEnvironment();
        Assumptions.assumeTrue(Files.isRegularFile(executable));

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> proof = objectMapper.readValue(
                projectRoot.resolve(Paths.get(
                        "crypto", "zokrates", "traffic-speed-range-v1", "fixtures", "valid", "proof.json")).toFile(),
                new TypeReference<Map<String, Object>>() { });
        List<String> signals = objectMapper.readValue(
                projectRoot.resolve(Paths.get(
                        "crypto", "zokrates", "traffic-speed-range-v1", "fixtures", "valid", "public-signals.json"))
                        .toFile(),
                new TypeReference<List<String>>() { });

        ZkpVerificationProperties properties = new ZkpVerificationProperties();
        properties.setMode(ZkpVerificationProperties.Mode.REAL);
        properties.setZokratesExecutable(executable.toString());
        properties.setKeyRoot(projectRoot.resolve(Paths.get("config", "zkp")).toString());
        properties.setTempRoot(tempDirectory.resolve("requests").toString());
        properties.setTimeoutMillis(30000L);
        Groth16ProofVerifier verifier = new Groth16ProofVerifier(
                properties,
                new VerifyingKeyResolver(properties),
                new ZokratesProofNormalizer(objectMapper),
                new ZokratesProcessRunner(properties));

        assertTrue(verify(verifier, proof, signals).isPassed());
        assertEquals("PUBLIC_SIGNALS_MISMATCH", verify(verifier, proof, Arrays.asList(31, 80)).getReasonCode());
        assertEquals("PUBLIC_SIGNALS_MISSING", verify(verifier, proof, null).getReasonCode());
        assertEquals("VERIFICATION_KEY_NOT_FOUND", verifier.verify(
                "traffic-speed-range-v1", "missing-key", proof, signals).getReasonCode());

        Map<String, Object> legacy = new LinkedHashMap<>();
        legacy.put("piA", "legacy-pi-a");
        legacy.put("piB", "legacy-pi-b");
        legacy.put("piC", "legacy-pi-c");
        assertEquals("PROOF_FORMAT_INVALID", verify(verifier, legacy, signals).getReasonCode());

        Map<String, Object> invalidProof = objectMapper.convertValue(
                proof, new TypeReference<Map<String, Object>>() { });
        Map<String, Object> points = (Map<String, Object>) invalidProof.get("proof");
        List<String> a = (List<String>) points.get("a");
        String coordinate = a.get(0);
        a.set(0, coordinate.substring(0, coordinate.length() - 1)
                + (coordinate.endsWith("0") ? "1" : "0"));
        assertEquals("PROOF_REJECTED", verify(verifier, invalidProof, signals).getReasonCode());

        ExecutorService executor = Executors.newFixedThreadPool(6);
        try {
            List<Callable<Boolean>> calls = new ArrayList<>();
            for (int i = 0; i < 12; i++) {
                calls.add(() -> verify(verifier, proof, signals).isPassed());
            }
            List<Future<Boolean>> futures = executor.invokeAll(calls);
            for (Future<Boolean> future : futures) {
                assertTrue(future.get());
            }
        } finally {
            executor.shutdownNow();
        }

        Path requestRoot = tempDirectory.resolve("requests");
        if (Files.exists(requestRoot)) {
            try (Stream<Path> children = Files.list(requestRoot)) {
                assertEquals(0L, children.count());
            }
        }
    }

    private Groth16ProofVerifier.VerificationDecision verify(
            Groth16ProofVerifier verifier,
            Object proof,
            Object signals) {
        return verifier.verify("traffic-speed-range-v1", null, proof, signals);
    }

    private Path zokratesExecutableFromEnvironment() {
        String executable = System.getenv("ZOKRATES_EXECUTABLE");
        Assumptions.assumeTrue(executable != null && !executable.trim().isEmpty());
        return Paths.get(executable).toAbsolutePath().normalize();
    }
}
