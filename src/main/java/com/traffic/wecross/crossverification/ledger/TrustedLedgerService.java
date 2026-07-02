package com.traffic.wecross.crossverification.ledger;

import com.traffic.wecross.crossverification.record.LedgerStatus;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Service;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

@Service
public class TrustedLedgerService {
    private final ApplicationContext applicationContext;

    public TrustedLedgerService(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    public LedgerSyncResult write(LedgerRecordPayload payload, List<String> ledgerTargets) throws Exception {
        String firstTarget = firstTarget(ledgerTargets);
        Object legacyGateway = findLegacyGateway();
        if (legacyGateway == null) {
            return LedgerSyncResult.pending(firstTarget);
        }

        Object legacyRecord = buildLegacyRecord(payload);
        Method writeRecord = legacyGateway.getClass().getMethod("writeRecord", legacyRecord.getClass(), List.class);
        Object writeResults = writeRecord.invoke(legacyGateway, legacyRecord, ledgerTargets);
        return convertLegacyResult(firstTarget, writeResults);
    }

    private Object findLegacyGateway() {
        Map<String, ?> beans = applicationContext.getBeansOfType(Object.class);
        for (Object bean : beans.values()) {
            if ("com.traffic.wecross.api.WeCrossGateway".equals(bean.getClass().getName())) {
                return bean;
            }
        }
        return null;
    }

    private Object buildLegacyRecord(LedgerRecordPayload payload) throws Exception {
        Class<?> recordClass = Class.forName("com.traffic.wecross.api.VerificationRecord");
        Object record = recordClass.getConstructor().newInstance();
        setField(record, "recordId", payload.recordId);
        setField(record, "businessId", payload.businessId);
        setField(record, "verifyType", payload.verifyType);
        setField(record, "passed", "PASS".equals(payload.status));
        setField(record, "dataHash", payload.inputHash);
        setField(record, "resultHash", payload.resultHash);
        setField(record, "detailHash", payload.metadataHash);
        setField(record, "algorithm", payload.algorithm);
        setField(record, "timestamp", payload.timestamp == null ? System.currentTimeMillis() : payload.timestamp);
        return record;
    }

    private LedgerSyncResult convertLegacyResult(String firstTarget, Object writeResults) throws Exception {
        if (!(writeResults instanceof List) || ((List<?>) writeResults).isEmpty()) {
            return LedgerSyncResult.pending(firstTarget);
        }
        Object first = ((List<?>) writeResults).get(0);
        String resourcePath = stringField(first, "resourcePath", firstTarget);
        String status = stringField(first, "status", LedgerStatus.PENDING.name());
        String txHash = stringField(first, "txHash", null);
        String message = stringField(first, "message", "可信账本同步状态暂未确认");
        if (LedgerStatus.SUCCESS.name().equalsIgnoreCase(status)) {
            return LedgerSyncResult.success(resourcePath, txHash);
        }
        if (LedgerStatus.FAILED.name().equalsIgnoreCase(status)) {
            return LedgerSyncResult.failed(resourcePath, "验证已完成，但可信账本同步失败：" + message);
        }
        return LedgerSyncResult.pending(resourcePath);
    }

    private String firstTarget(List<String> ledgerTargets) {
        return ledgerTargets == null || ledgerTargets.isEmpty() ? null : ledgerTargets.get(0);
    }

    private void setField(Object target, String name, Object value) {
        try {
            Field field = target.getClass().getField(name);
            field.set(target, value);
        } catch (Exception ignored) {
            // Legacy record versions may not expose every field.
        }
    }

    private String stringField(Object target, String name, String defaultValue) throws Exception {
        try {
            Field field = target.getClass().getField(name);
            Object value = field.get(target);
            return value == null ? defaultValue : String.valueOf(value);
        } catch (NoSuchFieldException e) {
            return defaultValue;
        }
    }
}
