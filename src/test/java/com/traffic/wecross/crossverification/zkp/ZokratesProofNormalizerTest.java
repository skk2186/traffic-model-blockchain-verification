package com.traffic.wecross.crossverification.zkp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ZokratesProofNormalizerTest {
    private ObjectMapper objectMapper;
    private ZokratesProofNormalizer normalizer;
    private Map<String, Object> completeProof;
    private List<String> publicSignals;

    @BeforeEach
    void setUp() throws Exception {
        objectMapper = new ObjectMapper();
        normalizer = new ZokratesProofNormalizer(objectMapper);
        completeProof = objectMapper.readValue(
                Paths.get("crypto", "zokrates", "traffic-speed-range-v1", "fixtures", "valid", "proof.json")
                        .toFile(),
                new TypeReference<Map<String, Object>>() { });
        publicSignals = objectMapper.readValue(
                Paths.get("crypto", "zokrates", "traffic-speed-range-v1", "fixtures", "valid", "public-signals.json")
                        .toFile(),
                new TypeReference<List<String>>() { });
    }

    @Test
    void acceptsNativeCompleteProofWithoutMutatingRequest() throws Exception {
        String before = objectMapper.writeValueAsString(completeProof);

        ZokratesNormalizedProof normalized = normalizer.normalize(completeProof, publicSignals);

        assertEquals("g16", normalized.getScheme());
        assertEquals("bn128", normalized.getCurve());
        assertEquals(before, objectMapper.writeValueAsString(completeProof));
        assertEquals(publicSignals, objectMapper.convertValue(
                normalized.getDocument().get("inputs"), new TypeReference<List<String>>() { }));
    }

    @Test
    void completesExactInnerProofUsingRequestPublicSignals() {
        Object innerProof = completeProof.get("proof");

        ZokratesNormalizedProof normalized = normalizer.normalize(innerProof, Arrays.asList(30, 80));

        assertEquals("g16", normalized.getDocument().get("scheme").asText());
        assertEquals("bn128", normalized.getDocument().get("curve").asText());
        assertEquals(publicSignals, objectMapper.convertValue(
                normalized.getDocument().get("inputs"), new TypeReference<List<String>>() { }));
    }

    @Test
    void rejectsMismatchedPublicSignals() {
        ProofNormalizationException exception = assertThrows(
                ProofNormalizationException.class,
                () -> normalizer.normalize(completeProof, Arrays.asList(31, 80)));

        assertEquals("PUBLIC_SIGNALS_MISMATCH", exception.getReasonCode());
    }

    @Test
    void rejectsMissingPublicSignalsAndLegacyMockShape() {
        ProofNormalizationException missing = assertThrows(
                ProofNormalizationException.class,
                () -> normalizer.normalize(completeProof, null));
        assertEquals("PUBLIC_SIGNALS_MISSING", missing.getReasonCode());

        Map<String, Object> legacy = new LinkedHashMap<>();
        legacy.put("piA", "legacy-pi-a");
        legacy.put("piB", "legacy-pi-b");
        legacy.put("piC", "legacy-pi-c");
        ProofNormalizationException invalid = assertThrows(
                ProofNormalizationException.class,
                () -> normalizer.normalize(legacy, publicSignals));
        assertEquals("PROOF_FORMAT_INVALID", invalid.getReasonCode());
    }

    @Test
    void rejectsUnknownOuterAndInnerFields() {
        Map<String, Object> outer = deepCopy(completeProof);
        outer.put("valid", true);
        assertEquals("PROOF_FORMAT_INVALID", assertThrows(
                ProofNormalizationException.class,
                () -> normalizer.normalize(outer, publicSignals)).getReasonCode());

        Map<String, Object> inner = objectMapper.convertValue(
                completeProof.get("proof"), new TypeReference<Map<String, Object>>() { });
        inner.put("piA", "not-native");
        assertEquals("PROOF_FORMAT_INVALID", assertThrows(
                ProofNormalizationException.class,
                () -> normalizer.normalize(inner, publicSignals)).getReasonCode());
    }

    @Test
    void writesOnlyNormalizedNativeFields() throws Exception {
        ZokratesNormalizedProof normalized = normalizer.normalize(completeProof, publicSignals);
        ObjectNode document = normalized.getDocument();

        assertEquals(4, document.size());
        assertTrue(document.has("scheme"));
        assertTrue(document.has("curve"));
        assertTrue(document.has("proof"));
        assertTrue(document.has("inputs"));
        assertFalse(document.has("valid"));
    }

    private Map<String, Object> deepCopy(Map<String, Object> value) {
        return objectMapper.convertValue(value, new TypeReference<Map<String, Object>>() { });
    }
}
