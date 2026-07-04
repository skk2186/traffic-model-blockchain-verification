package com.traffic.wecross.crossverification.dto;

import com.traffic.wecross.crossverification.ledger.LedgerSyncResult;

import java.util.Map;

public class LedgerUpdateRequest {
    public LedgerSyncResult ledger;
    public Map<String, Object> chainVerification;
}