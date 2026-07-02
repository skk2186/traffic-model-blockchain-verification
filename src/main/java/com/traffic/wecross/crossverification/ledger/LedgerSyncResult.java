package com.traffic.wecross.crossverification.ledger;

import com.traffic.wecross.crossverification.record.LedgerStatus;

public class LedgerSyncResult {
    public Boolean enabled;
    public String status;
    public String chainPath;
    public String resourcePath;
    public String txHash;
    public String message;

    public static LedgerSyncResult disabled() {
        LedgerSyncResult result = new LedgerSyncResult();
        result.enabled = false;
        result.status = LedgerStatus.DISABLED.name();
        result.message = "可信账本同步未请求";
        return result;
    }

    public static LedgerSyncResult pending(String target) {
        LedgerSyncResult result = new LedgerSyncResult();
        result.enabled = true;
        result.status = LedgerStatus.PENDING.name();
        result.message = "可信账本同步适配待接入";
        result.resourcePath = target;
        if (target != null && target.contains(".")) {
            result.chainPath = target.substring(0, target.lastIndexOf('.'));
        }
        return result;
    }

    public static LedgerSyncResult success(String target, String txHash) {
        LedgerSyncResult result = new LedgerSyncResult();
        result.enabled = true;
        result.status = LedgerStatus.SUCCESS.name();
        result.message = "验证结果已写入可信账本";
        result.resourcePath = target;
        result.txHash = txHash;
        fillChainPath(result, target);
        return result;
    }

    public static LedgerSyncResult failed(String target, String message) {
        LedgerSyncResult result = new LedgerSyncResult();
        result.enabled = true;
        result.status = LedgerStatus.FAILED.name();
        result.message = message;
        result.resourcePath = target;
        fillChainPath(result, target);
        return result;
    }

    private static void fillChainPath(LedgerSyncResult result, String target) {
        if (target != null && target.contains(".")) {
            result.chainPath = target.substring(0, target.lastIndexOf('.'));
        }
    }
}
