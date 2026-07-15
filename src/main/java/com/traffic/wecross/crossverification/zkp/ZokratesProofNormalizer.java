package com.traffic.wecross.crossverification.zkp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.regex.Pattern;

@Component
public class ZokratesProofNormalizer {
    private static final String SCHEME = "g16";
    private static final String CURVE = "bn128";
    private static final Pattern FIELD_HEX = Pattern.compile("^0x[0-9a-fA-F]{1,64}$");
    private static final Set<String> OUTER_FIELDS = setOf("scheme", "curve", "proof", "inputs");
    private static final Set<String> PROOF_FIELDS = setOf("a", "b", "c");
    private static final Set<String> PUBLIC_SIGNAL_WRAPPER_FIELDS = setOf("inputs");

    private final ObjectMapper objectMapper;

    public ZokratesProofNormalizer(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public ZokratesNormalizedProof normalize(Object proof, Object publicSignals) {
        if (proof == null) {
            throw invalid("proof must not be empty");
        }
        if (publicSignals == null) {
            throw new ProofNormalizationException(
                    "PUBLIC_SIGNALS_MISSING", "publicSignals must not be empty in real verification mode");
        }

        JsonNode proofNode = objectMapper.valueToTree(proof);
        if (!proofNode.isObject() || proofNode.size() == 0) {
            throw invalid("proof must be a non-empty JSON object");
        }
        ArrayNode requestInputs = normalizePublicSignals(publicSignals);
        ObjectNode proofObject = (ObjectNode) proofNode;

        if (hasExactFields(proofObject, OUTER_FIELDS)) {
            return normalizeCompleteDocument(proofObject, requestInputs);
        }
        if (hasExactFields(proofObject, PROOF_FIELDS)) {
            validateProofPoints(proofObject);
            ObjectNode document = objectMapper.createObjectNode();
            document.put("scheme", SCHEME);
            document.put("curve", CURVE);
            document.set("proof", proofObject.deepCopy());
            document.set("inputs", requestInputs.deepCopy());
            return new ZokratesNormalizedProof(document, SCHEME, CURVE);
        }
        throw invalid("proof must be a native ZoKrates document or its exact a/b/c proof object");
    }

    public void write(ZokratesNormalizedProof proof, Path destination) throws IOException {
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(destination.toFile(), proof.getDocument());
    }

    private ZokratesNormalizedProof normalizeCompleteDocument(ObjectNode document, ArrayNode requestInputs) {
        JsonNode scheme = document.get("scheme");
        JsonNode curve = document.get("curve");
        JsonNode proof = document.get("proof");
        JsonNode inputs = document.get("inputs");
        if (scheme == null || !scheme.isTextual() || !SCHEME.equals(scheme.textValue())) {
            throw invalid("proof scheme must be g16");
        }
        if (curve == null || !curve.isTextual() || !CURVE.equals(curve.textValue())) {
            throw invalid("proof curve must be bn128");
        }
        if (proof == null || !proof.isObject() || !hasExactFields((ObjectNode) proof, PROOF_FIELDS)) {
            throw invalid("proof field must contain exactly a, b and c");
        }
        validateProofPoints((ObjectNode) proof);
        ArrayNode proofInputs = normalizeInputArray(inputs, "proof inputs");
        if (!proofInputs.equals(requestInputs)) {
            throw new ProofNormalizationException(
                    "PUBLIC_SIGNALS_MISMATCH", "publicSignals do not match the inputs embedded in the proof");
        }

        ObjectNode normalized = objectMapper.createObjectNode();
        normalized.put("scheme", SCHEME);
        normalized.put("curve", CURVE);
        normalized.set("proof", proof.deepCopy());
        normalized.set("inputs", proofInputs);
        return new ZokratesNormalizedProof(normalized, SCHEME, CURVE);
    }

    private ArrayNode normalizePublicSignals(Object publicSignals) {
        JsonNode node = objectMapper.valueToTree(publicSignals);
        if (node.isObject()) {
            ObjectNode wrapper = (ObjectNode) node;
            if (!hasExactFields(wrapper, PUBLIC_SIGNAL_WRAPPER_FIELDS)) {
                throw new ProofNormalizationException(
                        "PUBLIC_SIGNALS_INVALID", "publicSignals object may contain only the inputs field");
            }
            node = wrapper.get("inputs");
        }
        return normalizeInputArray(node, "publicSignals");
    }

    private ArrayNode normalizeInputArray(JsonNode node, String fieldName) {
        if (node == null || !node.isArray() || node.size() == 0) {
            throw new ProofNormalizationException(
                    "PUBLIC_SIGNALS_INVALID", fieldName + " must be a non-empty JSON array");
        }
        ArrayNode normalized = objectMapper.createArrayNode();
        for (JsonNode value : node) {
            normalized.add(normalizeFieldElement(value, fieldName));
        }
        return normalized;
    }

    private String normalizeFieldElement(JsonNode node, String fieldName) {
        BigInteger value;
        if (node.isIntegralNumber()) {
            value = node.bigIntegerValue();
        } else if (node.isTextual() && FIELD_HEX.matcher(node.textValue()).matches()) {
            value = new BigInteger(node.textValue().substring(2), 16);
        } else {
            throw new ProofNormalizationException(
                    "PUBLIC_SIGNALS_INVALID", fieldName + " values must be non-negative integers or 0x hex strings");
        }
        if (value.signum() < 0 || value.bitLength() > 256) {
            throw new ProofNormalizationException(
                    "PUBLIC_SIGNALS_INVALID", fieldName + " contains a value outside the 256-bit unsigned range");
        }
        return String.format("0x%064x", value);
    }

    private void validateProofPoints(ObjectNode proof) {
        validatePoint(proof.get("a"), "proof.a", 2, false);
        validatePoint(proof.get("b"), "proof.b", 2, true);
        validatePoint(proof.get("c"), "proof.c", 2, false);
    }

    private void validatePoint(JsonNode point, String fieldName, int expectedSize, boolean nested) {
        if (point == null || !point.isArray() || point.size() != expectedSize) {
            throw invalid(fieldName + " has an invalid shape");
        }
        for (JsonNode coordinate : point) {
            if (nested) {
                validatePoint(coordinate, fieldName, 2, false);
            } else if (!coordinate.isTextual() || !FIELD_HEX.matcher(coordinate.textValue()).matches()) {
                throw invalid(fieldName + " coordinates must be 0x-prefixed field elements");
            }
        }
    }

    private boolean hasExactFields(ObjectNode object, Set<String> expected) {
        Set<String> actual = new HashSet<>();
        Iterator<String> names = object.fieldNames();
        while (names.hasNext()) {
            actual.add(names.next());
        }
        return actual.equals(expected);
    }

    private ProofNormalizationException invalid(String message) {
        return new ProofNormalizationException("PROOF_FORMAT_INVALID", message);
    }

    private static Set<String> setOf(String... values) {
        return new HashSet<>(Arrays.asList(values));
    }
}
