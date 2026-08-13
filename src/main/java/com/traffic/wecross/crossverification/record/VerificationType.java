package com.traffic.wecross.crossverification.record;

public enum VerificationType {
    MERKLE("Merkle验证"),
    ZKP("ZKP验证"),
    THRESHOLD_SIGNATURE("门限阈值签名");

    private final String verifyName;

    VerificationType(String verifyName) {
        this.verifyName = verifyName;
    }

    public String getVerifyName() {
        return verifyName;
    }
}
