package com.traffic.wecross.crossverification.record;

import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.ledger.LedgerSyncResult;

import java.util.Map;

public class VerificationRecordDetail extends VerificationRecord {
    public String inputHash;
    public String proofHash;
    public Map<String, Object> detail;
    public LedgerSyncResult ledger;
    public VerificationResult rawResult;
}
