package com.traffic.wecross.crossverification.dto;

public class ZkpVerifyRequest extends BaseVerifyRequest {
    public String circuitId;
    public Object proof;
    public Object publicSignals;
    public String verifyingKeyId;
    public String publicInputHash;
}
