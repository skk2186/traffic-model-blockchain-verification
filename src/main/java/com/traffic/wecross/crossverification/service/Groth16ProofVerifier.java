package com.traffic.wecross.crossverification.service;

import com.traffic.wecross.crossverification.config.ZkpVerificationProperties;
import com.traffic.wecross.crossverification.zkp.ProofNormalizationException;
import com.traffic.wecross.crossverification.zkp.VerifyingKeyResolver;
import com.traffic.wecross.crossverification.zkp.ZokratesNormalizedProof;
import com.traffic.wecross.crossverification.zkp.ZokratesProcessResult;
import com.traffic.wecross.crossverification.zkp.ZokratesProcessRunner;
import com.traffic.wecross.crossverification.zkp.ZokratesProofNormalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Component
public class Groth16ProofVerifier {
    private static final Logger LOGGER = LoggerFactory.getLogger(Groth16ProofVerifier.class);
    private static final String REAL_ENGINE = "ZOKRATES_CLI";
    private static final String MOCK_ENGINE = "STRUCTURAL_MOCK";

    private final ZkpVerificationProperties properties;
    private final VerifyingKeyResolver keyResolver;
    private final ZokratesProofNormalizer proofNormalizer;
    private final ZokratesProcessRunner processRunner;

    public Groth16ProofVerifier(
            ZkpVerificationProperties properties,
            VerifyingKeyResolver keyResolver,
            ZokratesProofNormalizer proofNormalizer,
            ZokratesProcessRunner processRunner) {
        this.properties = properties;
        this.keyResolver = keyResolver;
        this.proofNormalizer = proofNormalizer;
        this.processRunner = processRunner;
    }

    public VerificationDecision verify(
            String circuitId,
            String verifyingKeyId,
            Object proof,
            Object publicSignals) {
        String effectiveKeyId = hasText(verifyingKeyId) ? verifyingKeyId.trim() : trimToNull(circuitId);
        if (!hasText(circuitId)) {
            return VerificationDecision.fail(
                    properties.getMode().name(), engine(), effectiveKeyId, circuitId,
                    null, null, "CIRCUIT_ID_INVALID", "circuitId must not be empty", 0L, null);
        }
        if (properties.getMode() == ZkpVerificationProperties.Mode.MOCK) {
            return verifyMock(circuitId.trim(), effectiveKeyId, proof, publicSignals);
        }
        return verifyReal(circuitId.trim(), effectiveKeyId, proof, publicSignals);
    }

    private VerificationDecision verifyReal(
            String circuitId,
            String effectiveKeyId,
            Object proof,
            Object publicSignals) {
        try {
            keyResolver.validateKeyId(effectiveKeyId);
        } catch (IllegalArgumentException e) {
            return VerificationDecision.fail(
                    "REAL", REAL_ENGINE, effectiveKeyId, circuitId, null, null,
                    "VERIFYING_KEY_ID_INVALID", "verifyingKeyId is invalid", 0L, null);
        }

        final ZokratesNormalizedProof normalizedProof;
        try {
            normalizedProof = proofNormalizer.normalize(proof, publicSignals);
        } catch (ProofNormalizationException e) {
            return VerificationDecision.fail(
                    "REAL", REAL_ENGINE, effectiveKeyId, circuitId, null, null,
                    e.getReasonCode(), e.getMessage(), 0L, null);
        } catch (Exception e) {
            LOGGER.warn("Unexpected ZoKrates proof normalization failure circuitId={} keyId={}",
                    circuitId, effectiveKeyId, e);
            return VerificationDecision.fail(
                    "REAL", REAL_ENGINE, effectiveKeyId, circuitId, null, null,
                    "PROOF_FORMAT_INVALID", "proof could not be normalized", 0L, null);
        }

        final Path verificationKey;
        try {
            verificationKey = keyResolver.resolve(effectiveKeyId);
        } catch (IllegalArgumentException e) {
            return VerificationDecision.fail(
                    "REAL", REAL_ENGINE, effectiveKeyId, circuitId,
                    normalizedProof.getScheme(), normalizedProof.getCurve(),
                    "VERIFICATION_KEY_NOT_FOUND", "verification key was not found", 0L, null);
        }

        ZokratesProcessResult processResult = processRunner.runInTemporaryDirectory(workingDirectory -> {
            Path proofPath = workingDirectory.resolve("proof.json");
            proofNormalizer.write(normalizedProof, proofPath);
            return Arrays.asList(
                    "verify",
                    "--proof-path", proofPath.toString(),
                    "--verification-key-path", verificationKey.toString(),
                    "--backend", "ark");
        });

        if (processResult.isTimedOut()) {
            logProcessFailure("ZOKRATES_TIMEOUT", circuitId, effectiveKeyId, processResult);
            return fromProcessFailure(normalizedProof, effectiveKeyId, circuitId, processResult,
                    "ZOKRATES_TIMEOUT", "ZoKrates verification timed out");
        }
        if (!processResult.isStarted()
                || processResult.getExitCode() == null
                || processResult.getExitCode() != 0) {
            logProcessFailure("ZOKRATES_PROCESS_ERROR", circuitId, effectiveKeyId, processResult);
            return fromProcessFailure(normalizedProof, effectiveKeyId, circuitId, processResult,
                    "ZOKRATES_PROCESS_ERROR", "ZoKrates verification process failed");
        }

        boolean passed = containsOutputLine(processResult.getStdout(), "PASSED");
        boolean rejected = containsOutputLine(processResult.getStdout(), "FAILED")
                || containsOutputLine(processResult.getStderr(), "FAILED");
        if (!passed || rejected) {
            return fromProcessFailure(normalizedProof, effectiveKeyId, circuitId, processResult,
                    "PROOF_REJECTED", "proof was rejected by ZoKrates");
        }

        return VerificationDecision.pass(
                "REAL", REAL_ENGINE, effectiveKeyId, circuitId,
                normalizedProof.getScheme(), normalizedProof.getCurve(),
                "proof accepted", processResult.getDurationMillis(), processResult.getExitCode());
    }

    private VerificationDecision verifyMock(
            String circuitId,
            String effectiveKeyId,
            Object proof,
            Object publicSignals) {
        if (!properties.isAllowLegacyMock()) {
            return VerificationDecision.fail(
                    "MOCK", MOCK_ENGINE, effectiveKeyId, circuitId, null, null,
                    "LEGACY_MOCK_DISABLED", "legacy mock verification is disabled", 0L, null);
        }
        if (!(proof instanceof Map) || ((Map<?, ?>) proof).isEmpty()) {
            return mockFailure(effectiveKeyId, circuitId, "PROOF_FORMAT_INVALID", "proof must not be empty");
        }
        Map<?, ?> proofMap = (Map<?, ?>) proof;
        if (!hasProofElement(proofMap, "piA", "pi_a")
                || !hasProofElement(proofMap, "piB", "pi_b")
                || !hasProofElement(proofMap, "piC", "pi_c")) {
            return mockFailure(effectiveKeyId, circuitId, "PROOF_FORMAT_INVALID",
                    "mock proof must contain piA/piB/piC");
        }
        if (publicSignals == null) {
            return mockFailure(effectiveKeyId, circuitId, "PUBLIC_SIGNALS_MISSING",
                    "publicSignals must not be empty");
        }
        Object verdict = proofMap.get("valid");
        if (verdict instanceof Boolean && !((Boolean) verdict)) {
            return mockFailure(effectiveKeyId, circuitId, "PROOF_REJECTED", "mock proof verdict was rejected");
        }
        return VerificationDecision.pass(
                "MOCK", MOCK_ENGINE, effectiveKeyId, circuitId,
                "g16", null, "mock proof accepted", 0L, null);
    }

    private VerificationDecision fromProcessFailure(
            ZokratesNormalizedProof proof,
            String keyId,
            String circuitId,
            ZokratesProcessResult result,
            String reasonCode,
            String reasonMessage) {
        return VerificationDecision.fail(
                "REAL", REAL_ENGINE, keyId, circuitId,
                proof.getScheme(), proof.getCurve(), reasonCode, reasonMessage,
                result.getDurationMillis(), result.getExitCode());
    }

    private VerificationDecision mockFailure(
            String keyId, String circuitId, String reasonCode, String reasonMessage) {
        return VerificationDecision.fail(
                "MOCK", MOCK_ENGINE, keyId, circuitId, null, null,
                reasonCode, reasonMessage, 0L, null);
    }

    private void logProcessFailure(
            String reasonCode,
            String circuitId,
            String keyId,
            ZokratesProcessResult result) {
        LOGGER.warn(
                "ZoKrates verification failed reason={} circuitId={} keyId={} started={} timedOut={} exitCode={} "
                        + "failureReason={} stderr={}",
                reasonCode,
                circuitId,
                keyId,
                result.isStarted(),
                result.isTimedOut(),
                result.getExitCode(),
                summarize(result.getFailureReason()),
                summarize(result.getStderr()));
    }

    private String summarize(String value) {
        if (value == null) {
            return null;
        }
        String singleLine = value.replace('\r', ' ').replace('\n', ' ').trim();
        return singleLine.length() <= 512 ? singleLine : singleLine.substring(0, 512) + "...";
    }

    private boolean containsOutputLine(String output, String expectedLine) {
        if (output == null) {
            return false;
        }
        String[] lines = output.split("\\R");
        for (String line : lines) {
            if (expectedLine.equals(line.trim())) {
                return true;
            }
        }
        return false;
    }

    private String engine() {
        return properties.getMode() == ZkpVerificationProperties.Mode.REAL ? REAL_ENGINE : MOCK_ENGINE;
    }

    private String trimToNull(String value) {
        return hasText(value) ? value.trim() : null;
    }

    private boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }

    private boolean hasProofElement(Map<?, ?> proof, String... keys) {
        for (String key : keys) {
            Object value = proof.get(key);
            if (value != null && !String.valueOf(value).trim().isEmpty()) {
                return true;
            }
        }
        return false;
    }

    public static class VerificationDecision {
        private final boolean passed;
        private final String verifierMode;
        private final String verifierEngine;
        private final String verifyingKeyId;
        private final String circuitId;
        private final String scheme;
        private final String curve;
        private final String reasonCode;
        private final String reasonMessage;
        private final long durationMillis;
        private final Integer exitCode;

        private VerificationDecision(
                boolean passed,
                String verifierMode,
                String verifierEngine,
                String verifyingKeyId,
                String circuitId,
                String scheme,
                String curve,
                String reasonCode,
                String reasonMessage,
                long durationMillis,
                Integer exitCode) {
            this.passed = passed;
            this.verifierMode = verifierMode;
            this.verifierEngine = verifierEngine;
            this.verifyingKeyId = verifyingKeyId;
            this.circuitId = circuitId;
            this.scheme = scheme;
            this.curve = curve;
            this.reasonCode = reasonCode;
            this.reasonMessage = reasonMessage;
            this.durationMillis = durationMillis;
            this.exitCode = exitCode;
        }

        public static VerificationDecision pass(
                String verifierMode,
                String verifierEngine,
                String verifyingKeyId,
                String circuitId,
                String scheme,
                String curve,
                String reasonMessage,
                long durationMillis,
                Integer exitCode) {
            return new VerificationDecision(
                    true, verifierMode, verifierEngine, verifyingKeyId, circuitId, scheme, curve,
                    null, reasonMessage, durationMillis, exitCode);
        }

        public static VerificationDecision fail(
                String verifierMode,
                String verifierEngine,
                String verifyingKeyId,
                String circuitId,
                String scheme,
                String curve,
                String reasonCode,
                String reasonMessage,
                long durationMillis,
                Integer exitCode) {
            return new VerificationDecision(
                    false, verifierMode, verifierEngine, verifyingKeyId, circuitId, scheme, curve,
                    reasonCode, reasonMessage, durationMillis, exitCode);
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

        public String getVerifyingKeyId() {
            return verifyingKeyId;
        }

        public String getCircuitId() {
            return circuitId;
        }

        public String getScheme() {
            return scheme;
        }

        public String getCurve() {
            return curve;
        }

        public String getReasonCode() {
            return reasonCode;
        }

        public String getReasonMessage() {
            return reasonMessage;
        }

        public long getDurationMillis() {
            return durationMillis;
        }

        public Integer getExitCode() {
            return exitCode;
        }
    }
}
