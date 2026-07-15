package com.traffic.wecross.crossverification.zkp;

public class ProofNormalizationException extends IllegalArgumentException {
    private final String reasonCode;

    public ProofNormalizationException(String reasonCode, String message) {
        super(message);
        this.reasonCode = reasonCode;
    }

    public String getReasonCode() {
        return reasonCode;
    }
}
