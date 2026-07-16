package com.traffic.wecross.crossverification.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.traffic.wecross.crossverification.config.ThresholdSignatureVerificationProperties;
import com.traffic.wecross.crossverification.threshold.ThresholdSignaturePolicyLoader;
import com.traffic.wecross.crossverification.testsupport.ThresholdSignatureTestFixtures;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.traffic.wecross.crossverification.testsupport.ThresholdSignatureTestFixtures.AGGREGATE_SIGNATURE;
import static com.traffic.wecross.crossverification.testsupport.ThresholdSignatureTestFixtures.BUSINESS_ID;
import static com.traffic.wecross.crossverification.testsupport.ThresholdSignatureTestFixtures.GROUP_PUBLIC_KEY;
import static com.traffic.wecross.crossverification.testsupport.ThresholdSignatureTestFixtures.MESSAGE;
import static com.traffic.wecross.crossverification.testsupport.ThresholdSignatureTestFixtures.POLICY_ID;
import static com.traffic.wecross.crossverification.testsupport.ThresholdSignatureTestFixtures.SCHEME;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ThresholdSignatureVerifierTest {
    @TempDir
    Path tempDirectory;

    private ObjectMapper objectMapper;
    private ThresholdSignatureVerifier verifier;
    private ThresholdSignatureTestFixtures fixtures;
    private ThresholdSignatureVerificationProperties properties;

    @BeforeEach
    void setUp() throws Exception {
        objectMapper = new ObjectMapper();
        fixtures = new ThresholdSignatureTestFixtures(objectMapper, tempDirectory);
        properties = new ThresholdSignatureVerificationProperties();
        verifier = verifier(properties);
    }

    @Test
    void passesRealThreeOfFiveFrostAggregateSignature() {
        ThresholdSignatureVerifier.VerificationDecision decision = verifyValid();

        assertTrue(decision.isPassed());
        assertTrue(decision.isAggregateSignatureVerified());
        assertEquals("REAL", decision.getVerifierMode());
        assertEquals(ThresholdSignatureVerifier.ENGINE, decision.getVerifierEngine());
        assertEquals(SCHEME, decision.getScheme());
        assertEquals(POLICY_ID, decision.getPolicyId());
        assertEquals(3, decision.getValidSignatureCount());
    }

    @Test
    void acceptsDifferentRequestOrderBecauseParticipantSetIsCanonicalized() {
        ThresholdSignatureVerifier.VerificationDecision decision = verifier.verify(
                BUSINESS_ID,
                MESSAGE,
                3,
                5,
                fixtures.ids(4, 1, 2),
                fixtures.bundle(POLICY_ID, SCHEME, AGGREGATE_SIGNATURE));

        assertTrue(decision.isPassed());
        assertEquals(fixtures.ids(1, 2, 4), decision.getParticipantIds());
    }

    @Test
    void rejectsParticipantCountBelowThreshold() {
        ThresholdSignatureVerifier.VerificationDecision decision = verifier.verify(
                BUSINESS_ID,
                MESSAGE,
                3,
                5,
                fixtures.ids(1, 2),
                fixtures.bundle(POLICY_ID, SCHEME, AGGREGATE_SIGNATURE));

        assertFalse(decision.isPassed());
        assertEquals(
                "participantIds count must be greater than or equal to threshold",
                decision.getReason());
    }

    @Test
    void rejectsTamperedMessageBusinessIdAndParticipantSet() {
        assertFalse(verifier.verify(
                BUSINESS_ID,
                "tampered " + MESSAGE,
                3,
                5,
                fixtures.ids(1, 2, 4),
                fixtures.bundle(POLICY_ID, SCHEME, AGGREGATE_SIGNATURE)).isPassed());

        assertFalse(verifier.verify(
                "tampered-business",
                MESSAGE,
                3,
                5,
                fixtures.ids(1, 2, 4),
                fixtures.bundle(POLICY_ID, SCHEME, AGGREGATE_SIGNATURE)).isPassed());

        assertFalse(verifier.verify(
                BUSINESS_ID,
                MESSAGE,
                3,
                5,
                fixtures.ids(1, 2, 3),
                fixtures.bundle(POLICY_ID, SCHEME, AGGREGATE_SIGNATURE)).isPassed());
    }

    @Test
    void rejectsDuplicateAndOutOfRangeParticipantIds() {
        assertEquals(
                "participantIds must not contain duplicate values",
                verifier.verify(
                        BUSINESS_ID,
                        MESSAGE,
                        3,
                        5,
                        fixtures.ids(1, 1, 2),
                        fixtures.bundle(POLICY_ID, SCHEME, AGGREGATE_SIGNATURE))
                        .getReason());
        assertEquals(
                "participantId must be between 1 and totalNodes",
                verifier.verify(
                        BUSINESS_ID,
                        MESSAGE,
                        3,
                        5,
                        fixtures.ids(1, 2, 6),
                        fixtures.bundle(POLICY_ID, SCHEME, AGGREGATE_SIGNATURE))
                        .getReason());
    }

    @Test
    void rejectsLegacyIndependentEcdsaSignatureBundle() {
        Map<String, Object> legacy = new LinkedHashMap<>();
        legacy.put("scheme", "ECDSA-P256-SHA256");
        legacy.put("policyId", "traffic-consortium-v1");
        legacy.put("participantSignatures", new LinkedHashMap<String, Object>());

        ThresholdSignatureVerifier.VerificationDecision decision = verifier.verify(
                BUSINESS_ID, MESSAGE, 3, 5, fixtures.ids(1, 2, 4), legacy);

        assertFalse(decision.isPassed());
        assertTrue(decision.getReason().contains("signatureBundle"));
    }

    @Test
    void rejectsInvalidBase64AndWrongLengthAggregateSignatures() {
        assertEquals(
                "aggregateSignature must be valid Base64",
                verifier.verify(
                        BUSINESS_ID,
                        MESSAGE,
                        3,
                        5,
                        fixtures.ids(1, 2, 4),
                        fixtures.bundle(POLICY_ID, SCHEME, "not-base64!"))
                        .getReason());
        assertEquals(
                "aggregateSignature must decode to 64 bytes",
                verifier.verify(
                        BUSINESS_ID,
                        MESSAGE,
                        3,
                        5,
                        fixtures.ids(1, 2, 4),
                        fixtures.bundle(POLICY_ID, SCHEME, "YQ=="))
                        .getReason());
    }

    @Test
    void rejectsMissingMalformedAndMismatchedPolicies() throws Exception {
        assertFalse(verifier.verify(
                BUSINESS_ID,
                MESSAGE,
                3,
                5,
                fixtures.ids(1, 2, 4),
                fixtures.bundle("missing-policy", SCHEME, AGGREGATE_SIGNATURE)).isPassed());

        fixtures.writeRawPolicy("bad-json", "{bad json");
        assertFalse(verifier.verify(
                BUSINESS_ID,
                MESSAGE,
                3,
                5,
                fixtures.ids(1, 2, 4),
                fixtures.bundle("bad-json", SCHEME, AGGREGATE_SIGNATURE)).isPassed());

        fixtures.writePolicy("bad-key", SCHEME, 3, 5, "YQ==");
        assertFalse(verifier.verify(
                BUSINESS_ID,
                MESSAGE,
                3,
                5,
                fixtures.ids(1, 2, 4),
                fixtures.bundle("bad-key", SCHEME, AGGREGATE_SIGNATURE)).isPassed());

        fixtures.writePolicy("wrong-scheme", "ECDSA-P256-SHA256", 3, 5, GROUP_PUBLIC_KEY);
        assertFalse(verifier.verify(
                BUSINESS_ID,
                MESSAGE,
                3,
                5,
                fixtures.ids(1, 2, 4),
                fixtures.bundle("wrong-scheme", SCHEME, AGGREGATE_SIGNATURE)).isPassed());
    }

    @Test
    void rejectsRequestPolicyParameterMismatch() {
        assertFalse(verifier.verify(
                BUSINESS_ID,
                MESSAGE,
                2,
                5,
                fixtures.ids(1, 2, 4),
                fixtures.bundle(POLICY_ID, SCHEME, AGGREGATE_SIGNATURE)).isPassed());
        assertFalse(verifier.verify(
                BUSINESS_ID,
                MESSAGE,
                3,
                4,
                fixtures.ids(1, 2, 4),
                fixtures.bundle(POLICY_ID, SCHEME, AGGREGATE_SIGNATURE)).isPassed());
    }

    @Test
    void mockModeCannotBypassStrictVerification() {
        ThresholdSignatureVerificationProperties mockProperties =
                new ThresholdSignatureVerificationProperties();
        mockProperties.setMode(ThresholdSignatureVerificationProperties.Mode.MOCK);

        ThresholdSignatureVerifier.VerificationDecision decision =
                verifier(mockProperties).verify(
                        BUSINESS_ID,
                        MESSAGE,
                        3,
                        5,
                        fixtures.ids(1, 2, 4),
                        fixtures.bundle(POLICY_ID, SCHEME, AGGREGATE_SIGNATURE));

        assertFalse(decision.isPassed());
        assertTrue(decision.getReason().contains("mock threshold signatures are disabled"));
    }

    private ThresholdSignatureVerifier.VerificationDecision verifyValid() {
        return verifier.verify(
                BUSINESS_ID,
                MESSAGE,
                3,
                5,
                fixtures.ids(1, 2, 4),
                fixtures.bundle(POLICY_ID, SCHEME, AGGREGATE_SIGNATURE));
    }

    private ThresholdSignatureVerifier verifier(
            ThresholdSignatureVerificationProperties verificationProperties) {
        return new ThresholdSignatureVerifier(
                new ThresholdSignaturePolicyLoader(objectMapper, fixtures.getPolicyRoot()),
                verificationProperties);
    }
}
