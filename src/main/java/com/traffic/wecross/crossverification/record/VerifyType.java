package com.traffic.wecross.crossverification.record;

public enum VerifyType {
    MERKLE("Merkle验证"),
    ZKP("ZKP验证"),
    THRESHOLD_SIGNATURE("门限阈值签名");

    private final String verifyName;

    VerifyType(String verifyName) {
        this.verifyName = verifyName;
    }

    public String getVerifyName() {
        return verifyName;
    }
}
