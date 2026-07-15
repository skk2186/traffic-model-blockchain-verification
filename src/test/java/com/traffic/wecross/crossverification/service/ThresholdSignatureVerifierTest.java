package com.traffic.wecross.crossverification.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.traffic.wecross.crossverification.config.ThresholdSignatureVerificationProperties;
import com.traffic.wecross.crossverification.threshold.ThresholdSignaturePolicyLoader;
import com.traffic.wecross.crossverification.testsupport.ThresholdSignatureTestFixtures;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

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
    void ts001PassesWhenThreeOfFiveRealSignaturesAreValid() throws Exception {
        ThresholdSignatureVerifier.VerificationDecision decision = verifier.verify(
                MESSAGE, 3, 5, fixtures.ids(1, 2, 4), fixtures.bundle(fixtures.signatures(MESSAGE, 1, 2, 4)));

        assertTrue(decision.isPassed());
        assertEquals("REAL", decision.getVerifierMode());
        assertEquals("JAVA_SIGNATURE", decision.getVerifierEngine());
        assertEquals(SCHEME, decision.getScheme());
        assertEquals(POLICY_ID, decision.getPolicyId());
        assertEquals(3, decision.getValidSignatureCount());
        assertEquals(Boolean.TRUE, decision.getParticipantResults().get("1"));
        assertEquals(Boolean.TRUE, decision.getParticipantResults().get("2"));
        assertEquals(Boolean.TRUE, decision.getParticipantResults().get("4"));
    }

    @Test
    void ts002FailsWhenOnlyTwoOfFiveRealSignaturesAreProvided() throws Exception {
        ThresholdSignatureVerifier.VerificationDecision decision = verifier.verify(
                MESSAGE, 3, 5, fixtures.ids(1, 2), fixtures.bundle(fixtures.signatures(MESSAGE, 1, 2)));

        assertFalse(decision.isPassed());
        assertEquals(2, decision.getValidSignatureCount());
        assertEquals("valid signature count is less than threshold", decision.getReason());
    }

    @Test
    void ts003FailsWhenOneOfThreeSignaturesIsForged() throws Exception {
        Map<String, Object> signatures = fixtures.signatures(MESSAGE, 1, 3);
        signatures.put("2", fixtures.sign("forged-message", fixtures.getKeyPairs().get(2)));

        ThresholdSignatureVerifier.VerificationDecision decision = verifier.verify(
                MESSAGE, 3, 5, fixtures.ids(1, 2, 3), fixtures.bundle(signatures));

        assertFalse(decision.isPassed());
        assertEquals(2, decision.getValidSignatureCount());
        assertEquals(Boolean.FALSE, decision.getParticipantResults().get("2"));
    }

    @Test
    void ts004RejectsDuplicateParticipantIds() throws Exception {
        ThresholdSignatureVerifier.VerificationDecision decision = verifier.verify(
                MESSAGE, 3, 5, fixtures.ids(1, 1, 2), fixtures.bundle(fixtures.signatures(MESSAGE, 1, 2)));

        assertFalse(decision.isPassed());
        assertEquals("participantIds must not contain duplicate values", decision.getReason());
    }

    @Test
    void ts005RejectsParticipantIdOutsideTotalNodes() throws Exception {
        ThresholdSignatureVerifier.VerificationDecision decision = verifier.verify(
                MESSAGE, 3, 5, fixtures.ids(1, 2, 6), fixtures.bundle(fixtures.signatures(MESSAGE, 1, 2)));

        assertFalse(decision.isPassed());
        assertEquals("participantId must be between 1 and totalNodes", decision.getReason());
    }

    @Test
    void ts006FailsWhenSignatureIsCheckedAgainstWrongPublicKey() throws Exception {
        Map<String, Object> signatures = fixtures.signatures(MESSAGE, 1, 3);
        signatures.put("2", fixtures.sign(MESSAGE, fixtures.getKeyPairs().get(1)));

        ThresholdSignatureVerifier.VerificationDecision decision = verifier.verify(
                MESSAGE, 3, 5, fixtures.ids(1, 2, 3), fixtures.bundle(signatures));

        assertFalse(decision.isPassed());
        assertEquals(Boolean.FALSE, decision.getParticipantResults().get("2"));
        assertEquals(2, decision.getValidSignatureCount());
    }

    @Test
    void ts007FailsWhenMessageIsTamperedAfterSigning() throws Exception {
        ThresholdSignatureVerifier.VerificationDecision decision = verifier.verify(
                "tampered " + MESSAGE,
                3,
                5,
                fixtures.ids(1, 2, 3),
                fixtures.bundle(fixtures.signatures(MESSAGE, 1, 2, 3)));

        assertFalse(decision.isPassed());
        assertEquals(0, decision.getValidSignatureCount());
    }

    @Test
    void ts008RejectsEmptySignatureBundle() {
        ThresholdSignatureVerifier.VerificationDecision decision = verifier.verify(
                MESSAGE, 3, 5, fixtures.ids(1, 2, 3), new LinkedHashMap<>());

        assertFalse(decision.isPassed());
        assertEquals("signatureBundle must not be empty", decision.getReason());
    }

    @Test
    void rejectsInvalidBase64AndInvalidDerSignaturesAsFailedVerification() throws Exception {
        Map<String, Object> invalidBase64 = fixtures.signatures(MESSAGE, 1, 2);
        invalidBase64.put("3", "not-base64!");
        assertEquals(2, verifier.verify(
                MESSAGE, 3, 5, fixtures.ids(1, 2, 3), fixtures.bundle(invalidBase64)).getValidSignatureCount());

        Map<String, Object> invalidDer = fixtures.signatures(MESSAGE, 1, 2);
        invalidDer.put("3", Base64.getEncoder().encodeToString("not-der".getBytes("UTF-8")));
        ThresholdSignatureVerifier.VerificationDecision decision = verifier.verify(
                MESSAGE, 3, 5, fixtures.ids(1, 2, 3), fixtures.bundle(invalidDer));
        assertFalse(decision.isPassed());
        assertEquals(Boolean.FALSE, decision.getParticipantResults().get("3"));
    }

    @Test
    void rejectsMissingMalformedAndMismatchedPolicies() throws Exception {
        assertFalse(verifier.verify(MESSAGE, 3, 5, fixtures.ids(1, 2, 3),
                fixtures.bundle("missing-policy", SCHEME, fixtures.signatures(MESSAGE, 1, 2, 3))).isPassed());

        fixtures.writeRawPolicy("bad-json", "{bad json");
        assertFalse(verifier.verify(MESSAGE, 3, 5, fixtures.ids(1, 2, 3),
                fixtures.bundle("bad-json", SCHEME, fixtures.signatures(MESSAGE, 1, 2, 3))).isPassed());

        Map<String, Object> wrongSchemePolicy = fixtures.policyDocument(
                "wrong-scheme-policy", "BLS", fixtures.getKeyPairs(), 3, 5);
        objectMapper.writerWithDefaultPrettyPrinter()
                .writeValue(fixtures.getPolicyRoot().resolve("wrong-scheme-policy.json").toFile(), wrongSchemePolicy);
        assertFalse(verifier.verify(MESSAGE, 3, 5, fixtures.ids(1, 2, 3),
                fixtures.bundle("wrong-scheme-policy", SCHEME, fixtures.signatures(MESSAGE, 1, 2, 3))).isPassed());
    }

    @Test
    void rejectsSchemeThresholdTotalNodesAndParticipantMapMismatches() throws Exception {
        assertFalse(verifier.verify(MESSAGE, 3, 5, fixtures.ids(1, 2, 3),
                fixtures.bundle(POLICY_ID, "BLS", fixtures.signatures(MESSAGE, 1, 2, 3))).isPassed());
        assertFalse(verifier.verify(MESSAGE, 2, 5, fixtures.ids(1, 2, 3),
                fixtures.bundle(fixtures.signatures(MESSAGE, 1, 2, 3))).isPassed());
        assertFalse(verifier.verify(MESSAGE, 3, 4, fixtures.ids(1, 2, 3),
                fixtures.bundle(fixtures.signatures(MESSAGE, 1, 2, 3))).isPassed());

        Map<String, Object> extra = fixtures.signatures(MESSAGE, 1, 2, 3);
        extra.put("4", fixtures.sign(MESSAGE, fixtures.getKeyPairs().get(4)));
        assertFalse(verifier.verify(MESSAGE, 3, 5, fixtures.ids(1, 2, 3), fixtures.bundle(extra)).isPassed());

        Map<String, Object> unknown = fixtures.signatures(MESSAGE, 1, 2, 3);
        unknown.put("6", fixtures.sign(MESSAGE, fixtures.getKeyPairs().get(1)));
        assertFalse(verifier.verify(MESSAGE, 3, 5, fixtures.ids(1, 2, 3, 6), fixtures.bundle(unknown)).isPassed());
    }

    @Test
    void rejectsLegacyMockShapeInRealModeAndAllowsItOnlyInExplicitMockMode() throws Exception {
        Map<String, Object> legacy = new LinkedHashMap<>();
        legacy.put("valid", true);
        legacy.put("participantSignatures", fixtures.signatures(MESSAGE, 1, 2, 3));

        assertFalse(verifier.verify(MESSAGE, 3, 5, fixtures.ids(1, 2, 3), legacy).isPassed());

        ThresholdSignatureVerificationProperties mockProperties = new ThresholdSignatureVerificationProperties();
        mockProperties.setMode(ThresholdSignatureVerificationProperties.Mode.MOCK);
        ThresholdSignatureVerifier disabledMockVerifier = verifier(mockProperties);
        assertFalse(disabledMockVerifier.verify(MESSAGE, 3, 5, fixtures.ids(1, 2, 3), legacy).isPassed());

        mockProperties.setAllowLegacyMock(true);
        ThresholdSignatureVerifier enabledMockVerifier = verifier(mockProperties);
        ThresholdSignatureVerifier.VerificationDecision decision =
                enabledMockVerifier.verify(MESSAGE, 3, 5, fixtures.ids(1, 2, 3), legacy);
        assertTrue(decision.isPassed());
        assertEquals("MOCK", decision.getVerifierMode());
        assertEquals("STRUCTURAL_MOCK", decision.getVerifierEngine());
    }

    private ThresholdSignatureVerifier verifier(ThresholdSignatureVerificationProperties props) {
        return new ThresholdSignatureVerifier(
                new ThresholdSignaturePolicyLoader(objectMapper, fixtures.getPolicyRoot()),
                props);
    }
}
