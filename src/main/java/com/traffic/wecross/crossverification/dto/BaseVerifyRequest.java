package com.traffic.wecross.crossverification.dto;

import java.util.List;

public class BaseVerifyRequest {
    public String businessId;
    public String sourceChain;
    public String verificationChain;
    public Boolean writeLedger;
    public List<String> ledgerTargets;
}
