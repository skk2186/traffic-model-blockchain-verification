package com.traffic.wecross.crossverification.record;

public enum VerifyType {
    MERKLE("数据完整性验证"),
    ZKP("隐私证明验证"),
    THRESHOLD_SIGNATURE("多方签名验证");

    private final String verifyName;

    VerifyType(String verifyName) {
        this.verifyName = verifyName;
    }

    public String getVerifyName() {
        return verifyName;
    }
}
