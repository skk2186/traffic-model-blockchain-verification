package com.traffic.wecross.api;

import com.traffic.wecross.crossverification.dto.MerkleVerifyRequest;
import com.traffic.wecross.crossverification.dto.ThresholdSignatureVerifyRequest;
import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.dto.ZkpVerifyRequest;
import com.traffic.wecross.crossverification.ledger.LedgerSyncResult;
import com.traffic.wecross.crossverification.record.VerifyStatus;
import com.traffic.wecross.crossverification.service.MerkleVerificationService;
import com.traffic.wecross.crossverification.service.ThresholdSignatureVerificationService;
import com.traffic.wecross.crossverification.service.ZkpVerificationService;
import com.traffic.wecross.crossverification.util.HashUtils;
import com.traffic.wecross.crossverification.util.JsonUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@CrossOrigin
@RequestMapping("/api/verification")
public class VerificationController {
    private final MerkleVerificationService merkleVerificationService;
    private final ZkpVerificationService zkpVerificationService;
    private final ThresholdSignatureVerificationService thresholdSignatureVerificationService;

    public VerificationController(
            MerkleVerificationService merkleVerificationService,
            ZkpVerificationService zkpVerificationService,
            ThresholdSignatureVerificationService thresholdSignatureVerificationService) {
        this.merkleVerificationService = merkleVerificationService;
        this.zkpVerificationService = zkpVerificationService;
        this.thresholdSignatureVerificationService = thresholdSignatureVerificationService;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "UP");
        result.put("service", "transportation-verification-service");
        return result;
    }

    @PostMapping("/merkle")
    public VerificationRecord verifyMerkle(@RequestBody VerificationRequests.MerkleRequest request) {
        MerkleVerifyRequest mapped = toMerkleRequest(request);
        return toLegacyRecord(merkleVerificationService.verify(mapped));
    }

    @PostMapping("/groth16")
    public VerificationRecord verifyGroth16(@RequestBody VerificationRequests.Groth16Request request) {
        String merkleRoot = normalizeHash(request.merkleRoot);
        ZkpVerifyRequest mapped = new ZkpVerifyRequest();
        mapped.businessId = request.businessId;
        mapped.circuitId = "legacy-groth16";
        mapped.publicInputHash = merkleRoot;
        mapped.proof = legacyProof(request.merkleRoot);
        mapped.publicSignals = legacyPublicSignals(request);
        mapped.writeLedger = request.writeOnChain;
        mapped.ledgerTargets = request.targetChains;
        return toLegacyRecord(zkpVerificationService.verify(mapped), merkleRoot);
    }

    @PostMapping("/threshold-signature")
    public VerificationRecord verifyThresholdSignature(@RequestBody VerificationRequests.ThresholdSignatureRequest request) {
        String merkleRoot = normalizeHash(request.merkleRoot);
        Integer totalNodes = request.totalNodes == null ? 10 : request.totalNodes;
        Integer threshold = request.threshold == null ? 5 : request.threshold;
        List<Integer> participantIds = request.participantIds == null || request.participantIds.isEmpty()
                ? defaultParticipants(threshold)
                : request.participantIds;
        ThresholdSignatureVerifyRequest mapped = new ThresholdSignatureVerifyRequest();
        mapped.businessId = request.businessId;
        mapped.message = merkleRoot == null
                ? JsonUtils.toJson(request.dataBlocks)
                : merkleRoot;
        mapped.threshold = threshold;
        mapped.totalNodes = totalNodes;
        mapped.participantIds = participantIds;
        mapped.signatureBundle = legacySignatureBundle(participantIds);
        mapped.writeLedger = request.writeOnChain;
        mapped.ledgerTargets = request.targetChains;
        return toLegacyRecord(thresholdSignatureVerificationService.verify(mapped), merkleRoot);
    }

    @PostMapping("/full")
    public Map<String, VerificationRecord> verifyAll(@RequestBody VerificationRequests.ThresholdSignatureRequest request) {
        Map<String, VerificationRecord> result = new LinkedHashMap<>();

        VerificationRequests.MerkleRequest merkleRequest = copyBase(request, new VerificationRequests.MerkleRequest());
        VerificationRecord merkleRecord = verifyMerkle(merkleRequest);
        result.put("merkle", merkleRecord);

        VerificationRequests.Groth16Request zkpRequest = copyBase(request, new VerificationRequests.Groth16Request());
        zkpRequest.merkleRoot = request.merkleRoot == null ? merkleRecord.dataHash : request.merkleRoot;
        result.put("groth16", verifyGroth16(zkpRequest));

        if (request.merkleRoot == null) {
            request.merkleRoot = merkleRecord.dataHash;
        }
        result.put("thresholdSignature", verifyThresholdSignature(request));
        return result;
    }

    private MerkleVerifyRequest toMerkleRequest(VerificationRequests.BaseRequest request) {
        MerkleVerifyRequest mapped = new MerkleVerifyRequest();
        mapped.businessId = request.businessId;
        mapped.leafItems = request.dataBlocks;
        mapped.sampleIndex = request.sampleIndex;
        mapped.writeLedger = request.writeOnChain;
        mapped.ledgerTargets = request.targetChains;
        return mapped;
    }

    private <T extends VerificationRequests.BaseRequest> T copyBase(VerificationRequests.BaseRequest source, T target) {
        target.businessId = source.businessId;
        target.dataBlocks = source.dataBlocks;
        target.sampleIndex = source.sampleIndex;
        target.targetChains = source.targetChains;
        target.writeOnChain = source.writeOnChain;
        return target;
    }

    private Map<String, Object> legacyProof(String merkleRoot) {
        Map<String, Object> proof = new LinkedHashMap<>();
        proof.put("piA", merkleRoot == null ? "legacy-pi-a" : merkleRoot);
        proof.put("piB", "legacy-pi-b");
        proof.put("piC", "legacy-pi-c");
        return proof;
    }

    private Map<String, Object> legacyPublicSignals(VerificationRequests.BaseRequest request) {
        Map<String, Object> publicSignals = new LinkedHashMap<>();
        publicSignals.put("businessId", request.businessId);
        publicSignals.put("dataHash", HashUtils.sha256Hex(JsonUtils.toJson(request.dataBlocks)));
        return publicSignals;
    }

    private Map<String, Object> legacySignatureBundle(List<Integer> participantIds) {
        Map<String, Object> signatureBundle = new LinkedHashMap<>();
        Map<String, Object> participantSignatures = new LinkedHashMap<>();
        if (participantIds != null) {
            for (Integer participantId : participantIds) {
                participantSignatures.put(String.valueOf(participantId), "legacy-signature-" + participantId);
            }
        }
        signatureBundle.put("participantSignatures", participantSignatures);
        return signatureBundle;
    }

    private List<Integer> defaultParticipants(Integer threshold) {
        List<Integer> participantIds = new ArrayList<>();
        int count = threshold == null ? 0 : threshold;
        for (int i = 1; i <= count; i++) {
            participantIds.add(i);
        }
        return participantIds;
    }

    private String normalizeHash(String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.matches("^[0-9a-fA-F]{64}$") ? trimmed : HashUtils.sha256Hex(trimmed);
    }

    private VerificationRecord toLegacyRecord(VerificationResult result) {
        return toLegacyRecord(result, null);
    }

    private VerificationRecord toLegacyRecord(VerificationResult result, String merkleRoot) {
        Map<String, Object> detail = legacyDetail(result, merkleRoot);
        VerificationRecord record = new VerificationRecord();
        record.recordId = result.recordId;
        record.businessId = result.businessId;
        record.verifyType = legacyVerifyType(result.verifyType);
        record.passed = VerifyStatus.PASS.name().equals(result.status);
        record.dataHash = legacyDataHash(result, detail);
        record.resultHash = legacyResultHash(result, detail);
        record.detailHash = HashUtils.sha256Hex(JsonUtils.toJson(detail));
        record.algorithm = legacyAlgorithm(result.verifyType, result.algorithm);
        record.timestamp = result.timestamp == null ? System.currentTimeMillis() : result.timestamp;
        record.detail = detail;
        record.chainResults = toLegacyChainResults(result.ledger);
        return record;
    }

    private String legacyVerifyType(String verifyType) {
        if ("MERKLE".equals(verifyType)) {
            return "MERKLE_ROOT";
        }
        if ("ZKP".equals(verifyType)) {
            return "GROTH16_ZKP";
        }
        return verifyType;
    }

    private String legacyAlgorithm(String verifyType, String algorithm) {
        if ("MERKLE".equals(verifyType)) {
            return "SHA-256";
        }
        if ("ZKP".equals(verifyType)) {
            return "GROTH16";
        }
        return algorithm;
    }

    private String legacyDataHash(VerificationResult result, Map<String, Object> detail) {
        Object merkleRoot = detail.get("merkleRoot");
        if (merkleRoot != null && !String.valueOf(merkleRoot).trim().isEmpty()) {
            return String.valueOf(merkleRoot);
        }
        if ("MERKLE".equals(result.verifyType)) {
            return result.resultHash == null ? result.inputHash : result.resultHash;
        }
        return result.inputHash;
    }

    private String legacyResultHash(VerificationResult result, Map<String, Object> detail) {
        String base = String.valueOf(result.businessId)
                + ":" + legacyVerifyType(result.verifyType)
                + ":" + VerifyStatus.PASS.name().equals(result.status)
                + ":" + legacyDataHash(result, detail)
                + ":" + HashUtils.sha256Hex(JsonUtils.toJson(detail));
        return HashUtils.sha256Hex(base);
    }

    private Map<String, Object> legacyDetail(VerificationResult result, String merkleRoot) {
        Map<String, Object> detail = new LinkedHashMap<>();
        if (result.detail != null) {
            detail.putAll(result.detail);
        }
        if ("MERKLE".equals(result.verifyType)) {
            Object rootHash = detail.get("rootHash");
            detail.put("merkleRoot", rootHash == null ? result.resultHash : rootHash);
            detail.put("leafCount", detail.get("totalLeaves"));
            detail.put("siblings", detail.get("proofPath"));
            detail.put("sampleData", null);
        }
        if ("ZKP".equals(result.verifyType) || "THRESHOLD_SIGNATURE".equals(result.verifyType)) {
            if (merkleRoot != null) {
                detail.put("merkleRoot", merkleRoot);
            } else if (!detail.containsKey("merkleRoot")) {
                detail.put("merkleRoot", result.inputHash);
            }
        }
        if ("ZKP".equals(result.verifyType)) {
            detail.put("proofHash", result.proofHash);
            Object root = detail.get("merkleRoot");
            detail.put("piA", root == null ? result.inputHash : root);
            detail.put("piB", "legacy-pi-b");
            detail.put("piC", "legacy-pi-c");
        }
        if ("THRESHOLD_SIGNATURE".equals(result.verifyType)) {
            Object participantIds = detail.get("participantIds");
            if (participantIds != null) {
                detail.put("participants", participantIds);
            }
            if (!detail.containsKey("signature")) {
                detail.put("signature", HashUtils.sha256Hex(String.valueOf(detail.get("signatureHash"))));
            }
        }
        return detail;
    }

    private List<ChainWriteResult> toLegacyChainResults(LedgerSyncResult ledger) {
        List<ChainWriteResult> results = new ArrayList<>();
        if (ledger == null || !Boolean.TRUE.equals(ledger.enabled)) {
            return results;
        }
        ChainWriteResult result = new ChainWriteResult();
        result.resourcePath = ledger.resourcePath;
        result.txHash = ledger.txHash;
        result.status = ledger.status;
        result.message = ledger.message;
        results.add(result);
        return results;
    }
}
