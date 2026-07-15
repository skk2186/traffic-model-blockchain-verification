package com.traffic.wecross.crossverification.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.traffic.wecross.crossverification.ledger.TrustedLedgerService;
import com.traffic.wecross.crossverification.ledger.VerificationLedgerService;
import com.traffic.wecross.crossverification.record.VerificationRecordDetail;
import com.traffic.wecross.crossverification.service.Groth16ProofVerifier;
import com.traffic.wecross.crossverification.service.VerificationRecordService;
import com.traffic.wecross.crossverification.service.ZkpVerificationService;
import com.traffic.wecross.crossverification.util.HashUtils;
import com.traffic.wecross.crossverification.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.file.Paths;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class ZkpVerificationControllerTest {
    private ObjectMapper objectMapper;
    private VerificationRecordService recordService;
    private TrustedLedgerService trustedLedgerService;
    private Groth16ProofVerifier verifier;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        recordService = new VerificationRecordService();
        trustedLedgerService = mock(TrustedLedgerService.class);
        verifier = mock(Groth16ProofVerifier.class);
        VerificationLedgerService ledgerService = new VerificationLedgerService(trustedLedgerService);
        ZkpVerificationService service = new ZkpVerificationService(recordService, ledgerService, verifier);
        mockMvc = MockMvcBuilders
                .standaloneSetup(new ZkpVerificationController(service))
                .build();
    }

    @Test
    void verifiesZkpEndpointWithRealFixtureShapeAndRecordsResultWithoutLedgerWrite() throws Exception {
        Map<String, Object> proof = readProofFixture();
        List<String> inputs = readPublicSignalsFixture();
        Map<String, Object> publicSignals = new LinkedHashMap<>();
        publicSignals.put("inputs", inputs);
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("businessId", "traffic-controller-zkp");
        request.put("circuitId", "traffic-speed-range-v1");
        request.put("verifyingKeyId", "traffic-speed-range-v1");
        request.put("proof", proof);
        request.put("publicSignals", publicSignals);
        request.put("writeLedger", false);
        request.put("ledgerTargets", Collections.emptyList());

        when(verifier.verify(eq("traffic-speed-range-v1"), eq("traffic-speed-range-v1"), any(), any()))
                .thenReturn(Groth16ProofVerifier.VerificationDecision.pass(
                        "REAL", "ZOKRATES_CLI", "traffic-speed-range-v1", "traffic-speed-range-v1",
                        "g16", "bn128", "proof accepted", 21L, 0));

        String expectedProofHash = HashUtils.sha256Hex(JsonUtils.toJson(proof));
        String expectedInputHash = HashUtils.sha256Hex(JsonUtils.toJson(publicSignals));

        MvcResult mvcResult = mockMvc.perform(post("/api/cross-verification/zkp/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PASS"))
                .andExpect(jsonPath("$.detail.verifierMode").value("REAL"))
                .andExpect(jsonPath("$.detail.verifierEngine").value("ZOKRATES_CLI"))
                .andExpect(jsonPath("$.proofHash").value(expectedProofHash))
                .andExpect(jsonPath("$.inputHash").value(expectedInputHash))
                .andExpect(jsonPath("$.ledger.status").value("DISABLED"))
                .andReturn();

        JsonNode response = objectMapper.readTree(mvcResult.getResponse().getContentAsString());
        String recordId = response.get("recordId").asText();
        VerificationRecordDetail detail = recordService.getRecordDetail(recordId);
        assertNotNull(detail);
        assertEquals("PASS", detail.status);
        assertEquals(expectedProofHash, detail.proofHash);
        assertEquals(expectedInputHash, detail.inputHash);
        verify(verifier).verify(eq("traffic-speed-range-v1"), eq("traffic-speed-range-v1"), any(), any());
        verifyNoInteractions(trustedLedgerService);
    }

    private Map<String, Object> readProofFixture() throws Exception {
        return objectMapper.readValue(
                Paths.get("crypto", "zokrates", "traffic-speed-range-v1", "fixtures", "valid", "proof.json")
                        .toFile(),
                new TypeReference<Map<String, Object>>() { });
    }

    private List<String> readPublicSignalsFixture() throws Exception {
        return objectMapper.readValue(
                Paths.get("crypto", "zokrates", "traffic-speed-range-v1", "fixtures", "valid", "public-signals.json")
                        .toFile(),
                new TypeReference<List<String>>() { });
    }
}
