package com.traffic.wecross.crossverification.dto;

import com.traffic.wecross.crossverification.ledger.LedgerSyncResult;

import java.util.Map;

public class VerificationResult {
    public String recordId;
    public String verifyType;
    public String verifyName;
    public String businessId;
    public String algorithm;
    public String status;
    public String message;
    public String inputHash;
    public String proofHash;
    public String resultHash;
    public LedgerSyncResult ledger;
    public Map<String, Object> detail;
    public Long timestamp;
}
