package com.traffic.wecross.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.traffic.wecross.crossverification.config.ThresholdSignatureVerificationProperties;
import com.traffic.wecross.crossverification.config.ZkpVerificationProperties;
import com.traffic.wecross.crossverification.ledger.TrustedLedgerService;
import com.traffic.wecross.crossverification.ledger.VerificationLedgerService;
import com.traffic.wecross.crossverification.service.Groth16ProofVerifier;
import com.traffic.wecross.crossverification.service.MerkleVerificationService;
import com.traffic.wecross.crossverification.service.ThresholdSignatureVerificationService;
import com.traffic.wecross.crossverification.service.ThresholdSignatureVerifier;
import com.traffic.wecross.crossverification.service.VerificationRecordService;
import com.traffic.wecross.crossverification.service.ZkpVerificationService;
import com.traffic.wecross.crossverification.threshold.ThresholdSignaturePolicyLoader;
import com.traffic.wecross.crossverification.zkp.VerifyingKeyResolver;
import com.traffic.wecross.crossverification.zkp.ZokratesProcessRunner;
import com.traffic.wecross.crossverification.zkp.ZokratesProofNormalizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class LegacyVerificationControllerCompatibilityTest {
    private ObjectMapper objectMapper;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        VerificationRecordService recordService = new VerificationRecordService();
        VerificationLedgerService ledgerService = new VerificationLedgerService(mock(TrustedLedgerService.class));

        ZkpVerificationProperties zkpProperties = new ZkpVerificationProperties();
        Groth16ProofVerifier groth16ProofVerifier = new Groth16ProofVerifier(
                zkpProperties,
                new VerifyingKeyResolver(zkpProperties),
                new ZokratesProofNormalizer(objectMapper),
                new ZokratesProcessRunner(zkpProperties));

        ThresholdSignatureVerifier thresholdSignatureVerifier = new ThresholdSignatureVerifier(
                new ThresholdSignaturePolicyLoader(objectMapper),
                new ThresholdSignatureVerificationProperties());

        VerificationController controller = new VerificationController(
                new MerkleVerificationService(recordService, ledgerService),
                new ZkpVerificationService(recordService, ledgerService, groth16ProofVerifier),
                new ThresholdSignatureVerificationService(recordService, ledgerService, thresholdSignatureVerifier));
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void legacyGroth16MockProofDoesNotPassInRealMode() throws Exception {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("businessId", "legacy-groth16-real-mode");
        request.put("dataBlocks", Arrays.asList("record-1", "record-2"));
        request.put("merkleRoot", "legacy-root");
        request.put("writeOnChain", false);

        mockMvc.perform(post("/api/verification/groth16")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passed").value(false))
                .andExpect(jsonPath("$.detail.verifierMode").value("REAL"));
    }

    @Test
    void legacyThresholdMockSignatureDoesNotPassInRealMode() throws Exception {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("businessId", "legacy-threshold-real-mode");
        request.put("dataBlocks", Arrays.asList("record-1", "record-2"));
        request.put("threshold", 3);
        request.put("totalNodes", 5);
        request.put("participantIds", Arrays.asList(1, 2, 3));
        request.put("writeOnChain", false);

        mockMvc.perform(post("/api/verification/threshold-signature")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passed").value(false))
                .andExpect(jsonPath("$.detail.verifierMode").value("REAL"))
                .andExpect(jsonPath("$.detail.verifierEngine").value("JAVA_SIGNATURE"));
    }
}
