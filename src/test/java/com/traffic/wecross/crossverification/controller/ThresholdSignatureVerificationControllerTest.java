package com.traffic.wecross.crossverification.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.traffic.wecross.crossverification.config.ThresholdSignatureVerificationProperties;
import com.traffic.wecross.crossverification.dto.ThresholdSignatureVerifyRequest;
import com.traffic.wecross.crossverification.ledger.TrustedLedgerService;
import com.traffic.wecross.crossverification.ledger.VerificationLedgerService;
import com.traffic.wecross.crossverification.record.VerificationRecordDetail;
import com.traffic.wecross.crossverification.service.ThresholdSignatureVerificationService;
import com.traffic.wecross.crossverification.service.ThresholdSignatureVerifier;
import com.traffic.wecross.crossverification.service.VerificationRecordService;
import com.traffic.wecross.crossverification.testsupport.ThresholdSignatureTestFixtures;
import com.traffic.wecross.crossverification.threshold.ThresholdSignaturePolicyLoader;
import com.traffic.wecross.crossverification.util.HashUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.file.Path;

import static com.traffic.wecross.crossverification.testsupport.ThresholdSignatureTestFixtures.MESSAGE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class ThresholdSignatureVerificationControllerTest {
    @TempDir
    Path tempDirectory;

    private ObjectMapper objectMapper;
    private VerificationRecordService recordService;
    private TrustedLedgerService trustedLedgerService;
    private ThresholdSignatureTestFixtures fixtures;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() throws Exception {
        objectMapper = new ObjectMapper();
        fixtures = new ThresholdSignatureTestFixtures(objectMapper, tempDirectory);
        recordService = new VerificationRecordService();
        trustedLedgerService = mock(TrustedLedgerService.class);
        VerificationLedgerService ledgerService = new VerificationLedgerService(trustedLedgerService);
        ThresholdSignatureVerifier verifier = new ThresholdSignatureVerifier(
                new ThresholdSignaturePolicyLoader(objectMapper, fixtures.getPolicyRoot()),
                new ThresholdSignatureVerificationProperties());
        ThresholdSignatureVerificationService service =
                new ThresholdSignatureVerificationService(recordService, ledgerService, verifier);
        mockMvc = MockMvcBuilders
                .standaloneSetup(new ThresholdSignatureVerificationController(service))
                .build();
    }

    @Test
    void verifiesThresholdSignatureEndpointPassAndDoesNotWriteLedgerWhenDisabled() throws Exception {
        ThresholdSignatureVerifyRequest request = fixtures.validRequest();
        request.writeLedger = false;

        MvcResult mvcResult = mockMvc.perform(post("/api/cross-verification/threshold-signature/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PASS"))
                .andExpect(jsonPath("$.detail.verifierMode").value("REAL"))
                .andExpect(jsonPath("$.detail.verifierEngine").value("BOUNCY_CASTLE_ED25519_RFC8032"))
                .andExpect(jsonPath("$.detail.scheme").value("FROST-ED25519-SHA512"))
                .andExpect(jsonPath("$.detail.aggregateSignatureVerified").value(true))
                .andExpect(jsonPath("$.detail.validSignatureCount").value(3))
                .andExpect(jsonPath("$.inputHash").value(HashUtils.sha256Hex(MESSAGE)))
                .andExpect(jsonPath("$.ledger.status").value("DISABLED"))
                .andReturn();

        JsonNode response = objectMapper.readTree(mvcResult.getResponse().getContentAsString());
        assertNotNull(response.get("proofHash").asText());
        assertEquals(response.get("proofHash").asText(), response.get("detail").get("signatureHash").asText());
        String recordId = response.get("recordId").asText();
        VerificationRecordDetail detail = recordService.getRecordDetail(recordId);
        assertNotNull(detail);
        assertEquals("PASS", detail.status);
        assertEquals(HashUtils.sha256Hex(MESSAGE), detail.inputHash);
        verifyNoInteractions(trustedLedgerService);
    }

    @Test
    void returnsFailWhenMessageIsTamperedAfterSigning() throws Exception {
        ThresholdSignatureVerifyRequest request = fixtures.validRequest();
        request.message = "tampered " + MESSAGE;
        request.writeLedger = false;

        MvcResult mvcResult = mockMvc.perform(post("/api/cross-verification/threshold-signature/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("FAIL"))
                .andExpect(jsonPath("$.detail.validSignatureCount").value(0))
                .andExpect(jsonPath("$.inputHash").value(HashUtils.sha256Hex(request.message)))
                .andReturn();

        JsonNode response = objectMapper.readTree(mvcResult.getResponse().getContentAsString());
        VerificationRecordDetail detail = recordService.getRecordDetail(response.get("recordId").asText());
        assertNotNull(detail);
        assertEquals("FAIL", detail.status);
        verifyNoInteractions(trustedLedgerService);
    }
}
