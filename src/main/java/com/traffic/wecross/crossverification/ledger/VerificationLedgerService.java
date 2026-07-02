package com.traffic.wecross.crossverification.ledger;

import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.util.HashUtils;
import com.traffic.wecross.crossverification.util.JsonUtils;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class VerificationLedgerService {
    private final TrustedLedgerService trustedLedgerService;

    public VerificationLedgerService(TrustedLedgerService trustedLedgerService) {
        this.trustedLedgerService = trustedLedgerService;
    }

    public LedgerSyncResult syncIfRequested(
            VerificationResult result,
            Boolean writeLedger,
            List<String> ledgerTargets) {
        if (!Boolean.TRUE.equals(writeLedger)) {
            return LedgerSyncResult.disabled();
        }
        try {
            return trustedLedgerService.write(buildPayload(result), ledgerTargets);
        } catch (Exception e) {
            return LedgerSyncResult.failed(firstTarget(ledgerTargets), "验证已完成，但可信账本同步失败：" + messageOf(e));
        }
    }

    private LedgerRecordPayload buildPayload(VerificationResult result) {
        LedgerRecordPayload payload = new LedgerRecordPayload();
        payload.recordId = result.recordId;
        payload.verifyType = result.verifyType;
        payload.businessId = result.businessId;
        payload.algorithm = result.algorithm;
        payload.status = result.status;
        payload.inputHash = result.inputHash;
        payload.proofHash = result.proofHash;
        payload.resultHash = result.resultHash;
        payload.metadataHash = HashUtils.sha256Hex(JsonUtils.toJson(result.detail));
        payload.timestamp = result.timestamp;
        return payload;
    }

    private String firstTarget(List<String> ledgerTargets) {
        return ledgerTargets == null || ledgerTargets.isEmpty() ? null : ledgerTargets.get(0);
    }

    private String messageOf(Exception e) {
        return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
    }
}
