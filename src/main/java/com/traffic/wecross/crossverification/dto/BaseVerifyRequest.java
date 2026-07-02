package com.traffic.wecross.crossverification.dto;

import java.util.List;

public class BaseVerifyRequest {
    public String businessId;
    public Boolean writeLedger;
    public List<String> ledgerTargets;
}
