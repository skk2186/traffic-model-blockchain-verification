package com.traffic.wecross.crossverification.threshold;

import java.util.Arrays;

public class ThresholdSignaturePolicy {
    private final String policyId;
    private final String scheme;
    private final int threshold;
    private final int totalNodes;
    private final byte[] groupPublicKey;

    public ThresholdSignaturePolicy(
            String policyId,
            String scheme,
            int threshold,
            int totalNodes,
            byte[] groupPublicKey) {
        this.policyId = policyId;
        this.scheme = scheme;
        this.threshold = threshold;
        this.totalNodes = totalNodes;
        this.groupPublicKey = Arrays.copyOf(groupPublicKey, groupPublicKey.length);
    }

    public String getPolicyId() {
        return policyId;
    }

    public String getScheme() {
        return scheme;
    }

    public int getThreshold() {
        return threshold;
    }

    public int getTotalNodes() {
        return totalNodes;
    }

    public byte[] getGroupPublicKey() {
        return Arrays.copyOf(groupPublicKey, groupPublicKey.length);
    }
}
