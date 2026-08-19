package com.traffic.wecross.crossverification.service;

import com.traffic.wecross.crossverification.dto.PageResult;
import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.ledger.LedgerSyncResult;
import com.traffic.wecross.crossverification.record.MysqlVerificationRecordRepository;
import com.traffic.wecross.crossverification.record.VerificationRecord;
import com.traffic.wecross.crossverification.record.VerificationRecordDetail;
import com.traffic.wecross.crossverification.record.VerifyStatus;
import com.traffic.wecross.crossverification.record.VerifyType;
import com.traffic.wecross.crossverification.util.HashUtils;
import com.traffic.wecross.crossverification.util.JsonUtils;
import com.traffic.wecross.crossverification.util.VerifyIdGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class VerificationRecordService {
    private static final Logger LOGGER = LoggerFactory.getLogger(VerificationRecordService.class);

    // Temporary development-stage store. Replace with database or trusted ledger query adapter later.
    private final Map<String, VerificationRecord> records = new ConcurrentHashMap<>();
    private final Map<String, VerificationRecordDetail> recordDetails = new ConcurrentHashMap<>();
    private final MysqlVerificationRecordRepository mysqlRepository;

    public VerificationRecordService() {
        this.mysqlRepository = null;
    }

    @Autowired
    public VerificationRecordService(ObjectProvider<MysqlVerificationRecordRepository> mysqlRepositoryProvider) {
        this.mysqlRepository = mysqlRepositoryProvider.getIfAvailable();
    }

    public VerificationResult createResult(
            VerifyType verifyType,
            String businessId,
            String algorithm,
            VerifyStatus status,
            String message,
            String inputHash,
            String proofHash,
            LedgerSyncResult ledger,
            Map<String, Object> detail) {
        return createResult(
                verifyType,
                businessId,
                algorithm,
                status,
                message,
                inputHash,
                proofHash,
                null,
                ledger,
                detail);
    }

    public VerificationResult createResult(
            VerifyType verifyType,
            String businessId,
            String algorithm,
            VerifyStatus status,
            String message,
            String inputHash,
            String proofHash,
            String resultHash,
            LedgerSyncResult ledger,
            Map<String, Object> detail) {
        long now = System.currentTimeMillis();
        VerificationRecord record = new VerificationRecord();
        record.recordId = VerifyIdGenerator.nextId(verifyType);
        record.verifyType = verifyType.name();
        record.verifyName = verifyType.getVerifyName();
        record.businessId = normalizeBusinessId(businessId, record.recordId);
        record.algorithm = algorithm;
        record.status = status.name();
        record.ledgerStatus = ledger == null ? null : ledger.status;
        record.chainPath = ledger == null ? null : ledger.chainPath;
        record.resourcePath = ledger == null ? null : ledger.resourcePath;
        record.txHash = ledger == null ? null : ledger.txHash;
        applyChainSelection(record, detail);
        record.createdAt = now;
        record.resultHash = resultHash == null ? buildResultHash(record, inputHash, proofHash, detail) : resultHash;
        VerificationResult result = toResult(record, message, inputHash, proofHash, ledger, detail);
        VerificationRecordDetail recordDetail = toDetail(record, inputHash, proofHash, detail, ledger, result);
        saveRecord(record, recordDetail);
        LOGGER.info(
                "verification record saved recordId={} verifyType={} businessId={} status={} ledgerStatus={}",
                record.recordId,
                record.verifyType,
                record.businessId,
                record.status,
                record.ledgerStatus);
        return result;
    }

    public PageResult<VerificationRecord> listRecords(
            VerifyType verifyType,
            String businessId,
            VerifyStatus status,
            Integer page,
            Integer size) {
        if (mysqlRepository != null) {
            return mysqlRepository.listRecords(verifyType, businessId, status, page, size);
        }
        int safePage = page == null || page < 1 ? 1 : page;
        int safeSize = size == null || size < 1 ? 10 : Math.min(size, 100);
        List<VerificationRecord> filtered = new ArrayList<>();
        for (VerificationRecord record : records.values()) {
            if (verifyType != null && !verifyType.name().equals(record.verifyType)) {
                continue;
            }
            if (status != null && !status.name().equals(record.status)) {
                continue;
            }
            if (businessId != null && !businessId.equals(record.businessId)) {
                continue;
            }
            filtered.add(record);
        }
        filtered.sort(Comparator.comparing((VerificationRecord record) -> record.createdAt).reversed());
        int fromIndex = Math.min((safePage - 1) * safeSize, filtered.size());
        int toIndex = Math.min(fromIndex + safeSize, filtered.size());
        return PageResult.of(new ArrayList<>(filtered.subList(fromIndex, toIndex)), safePage, safeSize, filtered.size());
    }

    public VerificationRecordDetail getRecordDetail(String recordId) {
        if (mysqlRepository != null) {
            return mysqlRepository.getRecordDetail(recordId);
        }
        return recordDetails.get(recordId);
    }

    public void updateLedger(String recordId, LedgerSyncResult ledger) {
        updateLedger(recordId, ledger, null);
    }

    public void updateLedger(
            String recordId,
            LedgerSyncResult ledger,
            Map<String, Object> chainVerification) {
        VerificationRecordDetail detail = getRecordDetail(recordId);
        if (detail == null || ledger == null) {
            return;
        }
        VerificationRecord record = detail;
        record.ledgerStatus = ledger.status;
        record.chainPath = ledger.chainPath;
        record.resourcePath = ledger.resourcePath;
        record.txHash = ledger.txHash;
        applyChainSelection(record, chainVerification);
        if (chainVerification != null) {
            record.crossChainStatus = stringValue(chainVerification.get("status"));
            record.crossChainTxHash = stringValue(chainVerification.get("txHash"));
        }
        LOGGER.info(
                "verification ledger status updated recordId={} verifyType={} businessId={} status={} ledgerStatus={}",
                record.recordId,
                record.verifyType,
                record.businessId,
                record.status,
                record.ledgerStatus);
        copyListFields(record, detail);
        detail.ledger = ledger;
        if (chainVerification != null && detail.detail != null) {
            detail.detail.put("chainVerification", chainVerification);
        }
        if (detail.rawResult != null) {
            detail.rawResult.ledger = ledger;
            if (chainVerification != null && detail.rawResult.detail != null) {
                detail.rawResult.detail.put("chainVerification", chainVerification);
            }
        }
        saveRecord(record, detail);
    }

    private VerificationResult toResult(
            VerificationRecord record,
            String message,
            String inputHash,
            String proofHash,
            LedgerSyncResult ledger,
            Map<String, Object> detail) {
        VerificationResult result = new VerificationResult();
        result.recordId = record.recordId;
        result.verifyType = record.verifyType;
        result.verifyName = record.verifyName;
        result.businessId = record.businessId;
        result.algorithm = record.algorithm;
        result.status = record.status;
        result.message = message;
        result.inputHash = inputHash;
        result.proofHash = proofHash;
        result.resultHash = record.resultHash;
        result.ledger = ledger;
        result.detail = detail;
        result.timestamp = record.createdAt;
        return result;
    }

    private VerificationRecordDetail toDetail(
            VerificationRecord record,
            String inputHash,
            String proofHash,
            Map<String, Object> detailMap,
            LedgerSyncResult ledger,
            VerificationResult rawResult) {
        VerificationRecordDetail detail = new VerificationRecordDetail();
        copyListFields(record, detail);
        detail.inputHash = inputHash;
        detail.proofHash = proofHash;
        detail.detail = detailMap;
        detail.ledger = ledger;
        detail.rawResult = rawResult;
        return detail;
    }

    private void copyListFields(VerificationRecord source, VerificationRecord target) {
        target.recordId = source.recordId;
        target.verifyType = source.verifyType;
        target.verifyName = source.verifyName;
        target.businessId = source.businessId;
        target.algorithm = source.algorithm;
        target.status = source.status;
        target.resultHash = source.resultHash;
        target.ledgerStatus = source.ledgerStatus;
        target.chainPath = source.chainPath;
        target.resourcePath = source.resourcePath;
        target.sourceChain = source.sourceChain;
        target.verificationChain = source.verificationChain;
        target.txHash = source.txHash;
        target.crossChainStatus = source.crossChainStatus;
        target.crossChainTxHash = source.crossChainTxHash;
        target.createdAt = source.createdAt;
    }

    private void saveRecord(VerificationRecord record, VerificationRecordDetail detail) {
        if (mysqlRepository != null) {
            mysqlRepository.save(detail);
            return;
        }
        records.put(record.recordId, record);
        recordDetails.put(record.recordId, detail);
    }

    private String stringValue(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private void applyChainSelection(VerificationRecord record, Map<String, Object> values) {
        if (record == null || values == null) {
            return;
        }
        record.sourceChain = firstNonBlank(stringValue(values.get("sourceChain")), record.sourceChain);
        record.verificationChain = firstNonBlank(
                stringValue(values.get("verificationChain")), record.verificationChain);
        Object nested = values.get("chainVerification");
        if (nested instanceof Map) {
            Map<?, ?> chainVerification = (Map<?, ?>) nested;
            record.sourceChain = firstNonBlank(
                    stringValue(chainVerification.get("sourceChain")), record.sourceChain);
            record.verificationChain = firstNonBlank(
                    stringValue(chainVerification.get("verificationChain")), record.verificationChain);
        }
        if (record.sourceChain == null) {
            record.sourceChain = chainFromPath(record.chainPath != null ? record.chainPath : record.resourcePath);
        }
    }

    private String firstNonBlank(String first, String fallback) {
        return first != null && !first.trim().isEmpty() ? first : fallback;
    }

    private String chainFromPath(String path) {
        if (path == null) {
            return null;
        }
        String[] parts = path.split("\\.");
        return parts.length >= 2 ? parts[1] : null;
    }

    private String normalizeBusinessId(String businessId, String recordId) {
        if (businessId == null || businessId.trim().isEmpty()) {
            return recordId;
        }
        return businessId.trim();
    }

    private String buildResultHash(
            VerificationRecord record,
            String inputHash,
            String proofHash,
            Map<String, Object> detail) {
        return HashUtils.sha256Hex(
                record.businessId + ":" +
                        record.verifyType + ":" +
                        record.status + ":" +
                        inputHash + ":" +
                        proofHash + ":" +
                        record.createdAt + ":" +
                        JsonUtils.toJson(detail));
    }
}
