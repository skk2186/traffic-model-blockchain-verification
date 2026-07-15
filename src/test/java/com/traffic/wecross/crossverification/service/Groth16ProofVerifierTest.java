package com.traffic.wecross.crossverification.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.traffic.wecross.crossverification.config.ZkpVerificationProperties;
import com.traffic.wecross.crossverification.zkp.VerifyingKeyResolver;
import com.traffic.wecross.crossverification.zkp.ZokratesProcessResult;
import com.traffic.wecross.crossverification.zkp.ZokratesProcessRunner;
import com.traffic.wecross.crossverification.zkp.ZokratesProofNormalizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class Groth16ProofVerifierTest {
    @TempDir
    Path tempDirectory;

    private ZkpVerificationProperties properties;
    private VerifyingKeyResolver keyResolver;
    private ZokratesProcessRunner processRunner;
    private Groth16ProofVerifier verifier;
    private Map<String, Object> proof;
    private List<String> publicSignals;

    @BeforeEach
    void setUp() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        proof = objectMapper.readValue(
                Paths.get("crypto", "zokrates", "traffic-speed-range-v1", "fixtures", "valid", "proof.json")
                        .toFile(),
                new TypeReference<Map<String, Object>>() { });
        publicSignals = objectMapper.readValue(
                Paths.get("crypto", "zokrates", "traffic-speed-range-v1", "fixtures", "valid", "public-signals.json")
                        .toFile(),
                new TypeReference<List<String>>() { });

        properties = new ZkpVerificationProperties();
        properties.setMode(ZkpVerificationProperties.Mode.REAL);
        properties.setAllowLegacyMock(false);
        Path keyRoot = Files.createDirectories(tempDirectory.resolve("keys"));
        properties.setKeyRoot(keyRoot.toString());
        Path keyDirectory = Files.createDirectories(keyRoot.resolve("traffic-speed-range-v1"));
        Path key = keyDirectory.resolve("verification.key");
        Files.write(key, "public-key".getBytes(StandardCharsets.UTF_8));
        keyResolver = new VerifyingKeyResolver(properties);
        processRunner = mock(ZokratesProcessRunner.class);
        verifier = new Groth16ProofVerifier(
                properties,
                keyResolver,
                new ZokratesProofNormalizer(objectMapper),
                processRunner);
    }

    @Test
    void zkp001AcceptsCorrectProofSignalsAndKeyWhenZokratesPasses() {
        when(processRunner.runInTemporaryDirectory(any())).thenReturn(
                processResult(true, false, 0, "Performing verification...\nPASSED\n", "", null));

        Groth16ProofVerifier.VerificationDecision decision = verify(proof, publicSignals);

        assertTrue(decision.isPassed());
        assertEquals("REAL", decision.getVerifierMode());
        assertEquals("ZOKRATES_CLI", decision.getVerifierEngine());
        assertEquals("traffic-speed-range-v1", decision.getVerifyingKeyId());
        assertEquals("g16", decision.getScheme());
        assertEquals(Integer.valueOf(0), decision.getExitCode());
    }

    @Test
    void zkp002RejectsCorrectProofWithWrongPublicSignalsBeforeStartingProcess() {
        Groth16ProofVerifier.VerificationDecision decision = verify(proof, Arrays.asList(31, 80));

        assertFalse(decision.isPassed());
        assertEquals("PUBLIC_SIGNALS_MISMATCH", decision.getReasonCode());
        verifyNoInteractions(processRunner);
    }

    @Test
    void zkp003RejectsIncorrectProofWhenZokratesReturnsFailed() {
        when(processRunner.runInTemporaryDirectory(any())).thenReturn(
                processResult(true, false, 0, "Performing verification...\nFAILED\n", "", null));

        Groth16ProofVerifier.VerificationDecision decision = verify(proof, publicSignals);

        assertFalse(decision.isPassed());
        assertEquals("PROOF_REJECTED", decision.getReasonCode());
    }

    @Test
    void zkp004RejectsMissingVerificationKeyBeforeStartingProcess() {
        Groth16ProofVerifier.VerificationDecision decision = verifier.verify(
                "traffic-speed-range-v1", "missing-key", proof, publicSignals);

        assertFalse(decision.isPassed());
        assertEquals("VERIFICATION_KEY_NOT_FOUND", decision.getReasonCode());
        verifyNoInteractions(processRunner);
    }

    @Test
    void zkp004RejectsPathTraversalVerificationKeyBeforeStartingProcess() {
        Groth16ProofVerifier.VerificationDecision decision = verifier.verify(
                "traffic-speed-range-v1", "../outside", proof, publicSignals);

        assertFalse(decision.isPassed());
        assertEquals("VERIFYING_KEY_ID_INVALID", decision.getReasonCode());
        verifyNoInteractions(processRunner);
    }

    @Test
    void zkp006RejectsProofMissingRequiredFieldsBeforeStartingProcess() {
        Map<String, Object> missingField = deepCopy(proof);
        Map<String, Object> points = (Map<String, Object>) missingField.get("proof");
        points.remove("c");

        assertEquals("PROOF_FORMAT_INVALID", verify(missingField, publicSignals).getReasonCode());
        verifyNoInteractions(processRunner);
    }

    @Test
    void zkp007RejectsNonNativeLegacyProofInRealModeBeforeStartingProcess() {
        Map<String, Object> legacy = new LinkedHashMap<>();
        legacy.put("piA", "legacy-pi-a");
        legacy.put("piB", "legacy-pi-b");
        legacy.put("piC", "legacy-pi-c");
        assertEquals("PROOF_FORMAT_INVALID", verify(legacy, publicSignals).getReasonCode());
        verifyNoInteractions(processRunner);
    }

    @Test
    void mapsTimeoutAndProcessErrorToStableReasons() {
        when(processRunner.runInTemporaryDirectory(any()))
                .thenReturn(processResult(true, true, null, "", "", "timed out"))
                .thenReturn(processResult(true, false, 7, "", "error details", "exit 7"))
                .thenReturn(processResult(false, false, null, "", "", "ZoKrates executable does not exist"));

        assertEquals("ZOKRATES_TIMEOUT", verify(proof, publicSignals).getReasonCode());
        assertEquals("ZOKRATES_PROCESS_ERROR", verify(proof, publicSignals).getReasonCode());
        assertEquals("ZOKRATES_PROCESS_ERROR", verify(proof, publicSignals).getReasonCode());
    }

    @Test
    void mockModeRequiresExplicitLegacyPermission() {
        properties.setMode(ZkpVerificationProperties.Mode.MOCK);
        Map<String, Object> legacy = new LinkedHashMap<>();
        legacy.put("piA", "a");
        legacy.put("piB", "b");
        legacy.put("piC", "c");

        assertEquals("LEGACY_MOCK_DISABLED", verify(legacy, publicSignals).getReasonCode());
        properties.setAllowLegacyMock(true);
        assertTrue(verify(legacy, publicSignals).isPassed());
    }

    @Test
    void realModeRejectsLegacyMockEvenWhenLegacyPermissionWasPreviouslyEnabled() {
        properties.setMode(ZkpVerificationProperties.Mode.REAL);
        properties.setAllowLegacyMock(true);
        Map<String, Object> legacy = new LinkedHashMap<>();
        legacy.put("piA", "a");
        legacy.put("piB", "b");
        legacy.put("piC", "c");

        assertEquals("PROOF_FORMAT_INVALID", verify(legacy, publicSignals).getReasonCode());
        verifyNoInteractions(processRunner);
    }

    private Groth16ProofVerifier.VerificationDecision verify(Object candidateProof, Object signals) {
        return verifier.verify(
                "traffic-speed-range-v1", null, candidateProof, signals);
    }

    private ZokratesProcessResult processResult(
            boolean started,
            boolean timedOut,
            Integer exitCode,
            String stdout,
            String stderr,
            String failureReason) {
        return new ZokratesProcessResult(
                started, timedOut, exitCode, stdout, stderr, 12L, failureReason);
    }

    private Map<String, Object> deepCopy(Map<String, Object> value) {
        return new ObjectMapper().convertValue(value, new TypeReference<Map<String, Object>>() { });
    }
}
